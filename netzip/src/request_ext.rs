use crate::Error;
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use reqwest::{Response, StatusCode};
use std::{
    fmt::{Display, Formatter},
    io::{Error as StdError, ErrorKind as StdEKind},
    time::Duration,
};

pub(crate) trait RangedRequest {
    async fn get_range(&self, url: &str, range: HttpRange) -> Result<Response, Error>;

    async fn get_range_body(&self, url: &str, range: HttpRange) -> Result<Bytes, Error> {
        let limit = usize::try_from(range.len())
            .map_err(|_| Error::IoError(StdEKind::OutOfMemory.into()))?;

        let response = self.get_range(url, range.clone()).await?;
        response.body_with_limit(limit).await
    }
}

impl RangedRequest for reqwest::Client {
    async fn get_range(&self, url: &str, range: HttpRange) -> Result<Response, Error> {
        let range_string = format!("bytes={range}");
        let make_request = async || {
            self.get(url)
                .header("Range", &range_string)
                .send()
                .await
                .map_err(|e| Error::NetworkError(url.into(), e))
        };

        let mut response: Response;
        loop {
            response = make_request().await?;
            match response.error_for_status_ref() {
                Ok(_) => break,
                Err(err) => {
                    if let Some(StatusCode::TOO_MANY_REQUESTS) = err.status() {
                        let after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|val| val.to_str().ok())
                            .and_then(|val| val.parse().ok());

                        if let Some(after) = after {
                            tokio::time::sleep(Duration::from_secs(after)).await;
                            continue;
                        }
                    }

                    return Err(Error::NetworkError(url.into(), err));
                }
            }
        }

        // recheck if server supports ranged requests
        // even 200 OK means partial range is not supported, so check is strictly bounded to 206 code
        let status = response.status();
        if status != StatusCode::PARTIAL_CONTENT {
            return Err(Error::UnexpectedHttpStatus(url.into(), status));
        }

        Ok(response)
    }
}

pub(crate) trait ResponseExt {
    async fn body_with_limit(self, limit: usize) -> Result<Bytes, Error>;
}

impl ResponseExt for Response {
    async fn body_with_limit(self, limit: usize) -> Result<Bytes, Error> {
        let mut buffer = BytesMut::with_capacity(limit);
        let url = self.url().to_string();

        let mut stream = self.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(data) => data,
                Err(err) => return Err(Error::NetworkError(url, err)),
            };

            if buffer.len() + chunk.len() > limit {
                return Err(Error::IoError(StdError::new(
                    StdEKind::InvalidData,
                    "HTTP response exceeds requested range",
                )));
            }

            buffer.extend_from_slice(&chunk);
        }

        if buffer.len() != limit {
            return Err(Error::IoError(StdError::new(
                StdEKind::UnexpectedEof,
                "HTTP response shorter than requested range",
            )));
        }

        Ok(buffer.freeze())
    }
}

#[derive(Clone)]
pub(crate) enum HttpRange {
    Closed(u64, u64),
    End(usize),
}

impl Display for HttpRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(start, end) => write!(f, "{start}-{end}"),
            Self::End(end) => write!(f, "-{end}"),
        }
    }
}

impl HttpRange {
    #[must_use]
    fn len(&self) -> u64 {
        match self {
            Self::Closed(start, end) => end - start + 1,
            Self::End(end) => *end as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HttpRange;
    use netzip_parser::EOCD_MIN_SIZE;

    #[test]
    fn range_fmt() {
        let range = HttpRange::End(EOCD_MIN_SIZE).to_string();
        assert_eq!(range, format!("-{EOCD_MIN_SIZE}"));

        let range = HttpRange::Closed(10, 20).to_string();
        assert_eq!(range, "10-20");
    }

    #[test]
    fn range_len() {
        assert_eq!(HttpRange::End(EOCD_MIN_SIZE).len(), EOCD_MIN_SIZE as u64);
        assert_eq!(HttpRange::Closed(10, 20).len(), 11);
    }
}
