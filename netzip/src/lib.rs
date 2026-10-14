#![deny(clippy::pedantic)]
#![allow(clippy::doc_markdown, clippy::missing_errors_doc)]

mod request_ext;

use self::request_ext::{HttpRange, RangedRequest};
use async_compression::tokio::bufread::{Deflate64Decoder, DeflateDecoder};
use futures_util::TryStreamExt;
use netzip_parser::{
    CentralDirectoryEnd, CentralDirectoryRecord, CompressionMethod, LocalFile, ZipError,
};
use reqwest::StatusCode;
use std::{
    io::{Error as StdError, ErrorKind as StdEKind},
    pin::Pin,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::StreamReader;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error encountered while sending network request to '{0}': {1}")]
    NetworkError(String, reqwest::Error),
    #[error("Error encountered whiler parsing Zip from request to '{0}': {1}")]
    ParserError(String, ZipError),
    #[error("Error encountered while decompressing file from request to '{0}': {1}")]
    DecompressionError(String, String),
    #[error("Unable to decompress file with compression type {0}")]
    UnsupportCompression(u16),
    #[error("Downloaded data is corrupted. Expected {0} CRC-32 hash, got {1}")]
    DataCorruption(u32, u32),
    #[error("Request to {0} failed. Server responded with {1}, expected to get 206.")]
    UnexpectedHttpStatus(String, StatusCode),
    #[error("I/O error encountered: {0}")]
    IoError(std::io::Error),
}

pub struct RemoteZip {
    url: String,
    http_client: reqwest::Client,
    central_directory: Vec<CentralDirectoryRecord>,
}

impl RemoteZip {
    /// Creates a new RemoteZip instance by fetching and parsing the ZIP directory structure from a remote URL
    /// using the provided HTTP client.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the remote ZIP file to access
    /// * `http_client` - The reqwest HTTP client to use for making requests
    ///
    /// # Returns
    ///
    /// A Result containing either the initialized RemoteZip instance or an Error
    pub async fn get_using(url: &str, http_client: reqwest::Client) -> Result<Self, Error> {
        let min_cde_bytes = http_client
            .get_range_body(url, HttpRange::End(netzip_parser::EOCD_MIN_SIZE))
            .await?;

        let cde = if let Ok(min_out) = CentralDirectoryEnd::parse(&min_cde_bytes) {
            min_out
        } else {
            // There might be a comment, retry with an offset and search for the EOCD
            let cde_haystack = http_client
                .get_range_body(url, HttpRange::End(netzip_parser::EOCD_MIN_SIZE + 1024))
                .await?;

            CentralDirectoryEnd::find_and_parse(&cde_haystack)
                .map_err(|e| Error::ParserError(url.into(), e))?
        };

        let cd_offset = u64::from(cde.central_directory_offset);
        let cd_range = HttpRange::from_start_len(cd_offset, u64::from(cde.directory_size))
            .ok_or_else(malformed_fields_error)?;

        let cd_bytes = http_client.get_range_body(url, cd_range).await?;

        let cd_records = CentralDirectoryRecord::parse_many(&cd_bytes)
            .map_err(|e| Error::ParserError(url.into(), e))?;

        Ok(Self {
            url: url.into(),
            central_directory: cd_records,
            http_client,
        })
    }

    /// Creates a new RemoteZip instance by fetching and parsing the ZIP directory structure from a remote URL
    /// using a default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the remote ZIP file to access
    ///
    /// # Returns
    ///
    /// A Result containing either the initialized RemoteZip instance or an Error
    pub async fn get(url: &str) -> Result<Self, Error> {
        Self::get_using(url, reqwest::Client::new()).await
    }

    /// Returns a reference to the central directory records of the ZIP file.
    ///
    /// # Returns
    ///
    /// A reference to the vector of CentralDirectoryRecord entries
    #[must_use]
    pub fn records(&self) -> &[CentralDirectoryRecord] {
        &self.central_directory
    }

    /// Returns a mutable reference to the central directory records of the ZIP file.
    ///
    /// # Returns
    ///
    /// A mutable reference to the vector of CentralDirectoryRecord entries
    #[must_use]
    pub fn records_mut(&mut self) -> &mut Vec<CentralDirectoryRecord> {
        &mut self.central_directory
    }

    /// Downloads and decompresses the specified files from the remote ZIP.
    ///
    /// # Arguments
    ///
    /// * `paths` - A vector of file paths/names to download from the ZIP
    /// * `file_handler` - Handler of the file stream.
    ///   As file can be big, it's better to process it asynchronously.
    ///
    /// # Returns
    ///
    /// A Result containing either a vector of types defined by user
    /// or an Error if any file could not be downloaded or decompressed
    pub async fn download_files<H, F, R>(
        &self,
        paths: Vec<String>,
        mut file_handler: H,
    ) -> Result<Vec<R>, Error>
    where
        F: Future<Output = R>,
        H: FnMut(LocalFile, Pin<Box<dyn AsyncRead + Send>>) -> F,
    {
        let needed_cd_records: Vec<&CentralDirectoryRecord> = self
            .central_directory
            .iter()
            .filter(|x| paths.contains(&x.file_name))
            .collect();

        let mut out = Vec::with_capacity(paths.len());

        for cd_record in needed_cd_records {
            let fh_offset = u64::from(cd_record.file_header_offset);

            let lfh_size = (netzip_parser::LFH_MIN_SIZE as u64)
                .checked_add(u64::from(cd_record.extra_field_length))
                .and_then(|off| off.checked_add(u64::from(cd_record.file_name_length)))
                .ok_or_else(malformed_fields_error)?;

            let lfh_range = HttpRange::from_start_len(fh_offset, lfh_size)
                .ok_or_else(malformed_fields_error)?;

            let lfh_bytes = self
                .http_client
                .get_range_body(&self.url, lfh_range)
                .await?;

            let mut lfh = LocalFile::parse(&lfh_bytes)
                .map_err(|e| Error::ParserError(self.url.clone(), e))?;

            // All these fields will always be zero when file was compressed in streaming mode
            if lfh.gp_bit_flag >> 3 & 1 == 1 {
                lfh.crc32 = cd_record.crc32;
                lfh.compressed_size = cd_record.compressed_size;
                lfh.uncompressed_size = cd_record.uncompressed_size;
            }

            // The set of extra fields in the CD do not need to be identical with LFH ones
            // macOS has 16 bytes in LFH and 12 in CD
            let data_offset = lfh_range
                .end()
                .saturating_sub(u64::from(cd_record.extra_field_length))
                .checked_add(u64::from(lfh.extra_field_length))
                .ok_or_else(malformed_fields_error)?;

            let mut compressed_size = u64::from(lfh.compressed_size);
            let mut uncompressed_size = u64::from(lfh.uncompressed_size);

            // zip64 sets these fields to 0xFFFFFFFF
            if let Some(extended_info) = cd_record.zip64_extended_info() {
                compressed_size = extended_info.compressed_size;
                uncompressed_size = extended_info.uncompressed_size;
            }

            let data_size = match lfh.compression_method {
                CompressionMethod::Unsupported(unsupported_id) => {
                    return Err(Error::UnsupportCompression(unsupported_id));
                }
                CompressionMethod::Stored => uncompressed_size,
                _ => compressed_size,
            };

            let data_range = HttpRange::from_start_len(data_offset, data_size)
                .ok_or_else(malformed_fields_error)?;

            let response = self.http_client.get_range(&self.url, data_range).await?;

            let url = self.url.clone();
            let chunk_stream = response
                .bytes_stream()
                .map_err(move |e| StdError::other(Error::NetworkError(url.clone(), e)));
            let chunk_reader = StreamReader::new(chunk_stream);

            match lfh.compression_method {
                CompressionMethod::Deflate => {
                    let decoder = Box::pin(DeflateDecoder::new(chunk_reader));
                    let result = file_handler(lfh, decoder).await;
                    out.push(result);
                }
                CompressionMethod::Deflate64 => {
                    let decoder = Box::pin(Deflate64Decoder::new(chunk_reader));
                    let result = file_handler(lfh, decoder).await;
                    out.push(result);
                }
                CompressionMethod::Stored => {
                    let decoder = Box::pin(chunk_reader);
                    let result = file_handler(lfh, decoder).await;
                    out.push(result);
                }
                CompressionMethod::Unsupported(_) => {}
            }
        }

        Ok(out)
    }

    /// Downloads and decompresses the specified files from the remote ZIP.
    ///
    /// # Arguments
    ///
    /// * `paths` - A vector of file paths/names to download from the ZIP
    ///
    /// # Returns
    ///
    /// A Result containing either a vector of tuples with (LocalFile metadata, file contents as bytes)
    /// or an Error if any file could not be downloaded or decompressed
    pub async fn download_files_to_vec(
        &self,
        paths: Vec<String>,
    ) -> Result<Vec<(LocalFile, Vec<u8>)>, Error> {
        let files = self
            .download_files(paths, |file, stream| async move {
                let mut data = Vec::with_capacity(file.uncompressed_size as usize);
                tokio::io::copy(
                    &mut stream.take(u64::from(file.uncompressed_size)),
                    &mut data,
                )
                .await
                .map_err(Error::IoError)?;

                Ok((file, data))
            })
            .await?;

        files.into_iter().collect()
    }
}

fn malformed_fields_error() -> Error {
    Error::IoError(StdError::new(
        StdEKind::InvalidData,
        "zip fields are malformed",
    ))
}
