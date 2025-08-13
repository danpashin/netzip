use std::io::Read;

use bytes::Bytes;
use flate2::bufread::DeflateDecoder;
use netzip_parser::{CentralDirectoryEnd, CentralDirectoryRecord, LocalFile, ZipError};
use thiserror::Error;

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
        let min_cde_bytes = ranged_request(
            url,
            &format!("bytes=-{}", netzip_parser::EOCD_MIN_SIZE),
            http_client.clone(),
        )
        .await?;

        let cde = if let Ok(min_out) = CentralDirectoryEnd::parse(&min_cde_bytes) {
            min_out
        } else {
            // There might be a comment, retry with an offset and search for the EOCD
            let cde_haystack = ranged_request(
                url,
                &format!("bytes=-{}", netzip_parser::EOCD_MIN_SIZE + 1024),
                http_client.clone(),
            )
            .await?;

            CentralDirectoryEnd::find_and_parse(&cde_haystack)
                .map_err(|e| Error::ParserError(url.into(), e))?
        };

        let cd_bytes = ranged_request(
            url,
            &format!(
                "bytes={}-{}",
                cde.central_directory_offset,
                cde.central_directory_offset + cde.directory_size
            ),
            http_client.clone(),
        )
        .await?;

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
    pub fn records(&self) -> &Vec<CentralDirectoryRecord> {
        &self.central_directory
    }

    /// Returns a mutable reference to the central directory records of the ZIP file.
    ///
    /// # Returns
    ///
    /// A mutable reference to the vector of CentralDirectoryRecord entries
    pub fn records_mut(&mut self) -> &mut Vec<CentralDirectoryRecord> {
        &mut self.central_directory
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
    pub async fn download_files(
        &self,
        paths: Vec<String>,
    ) -> Result<Vec<(LocalFile, Vec<u8>)>, Error> {
        let needed_cd_records: Vec<&CentralDirectoryRecord> = self
            .central_directory
            .iter()
            .filter(|x| paths.contains(&x.file_name))
            .collect();

        let mut out = Vec::new();

        for cd_record in needed_cd_records {
            let lfh_end_offset = cd_record.file_header_offset
                + netzip_parser::LFH_MIN_SIZE as u32
                + cd_record.extra_field_length as u32
                + cd_record.file_name_length as u32
                + cd_record.file_comment_length as u32;
            let lfh_bytes = &self
                .ranged_request(&format!(
                    "bytes={}-{}",
                    cd_record.file_header_offset, lfh_end_offset
                ))
                .await?;

            let mut lfh = LocalFile::parse(&lfh_bytes)
                .map_err(|e| Error::ParserError(self.url.clone(), e))?;

            // All these fields will always be zero when file was compressed with streaming
            if lfh.gp_bit_flag >> 3 & 1 == 1 {
                lfh.crc32 = cd_record.crc32;
                lfh.compressed_size = cd_record.compressed_size;
                lfh.uncompressed_size = cd_record.uncompressed_size;
            }

            // The set of extra fields in the CD do not need to be identical with LFH ones
            // macOS has 16 bytes in LFH and 12 in CD
            let data_offset = lfh_end_offset as u64 - cd_record.extra_field_length as u64
                + lfh.extra_field_length as u64;

            let mut compressed_size = lfh.compressed_size as u64;
            let mut uncompressed_size = lfh.uncompressed_size as u64;

            // zip64 sets these fields to 0xFFFFFFFF
            if let Some(extended_info) = cd_record.zip64_extended_info() {
                compressed_size = extended_info.compressed_size;
                uncompressed_size = extended_info.uncompressed_size;
            }

            let download_chunk = |end_offset: u64| async move {
                self.ranged_request(&format!(
                    "bytes={}-{}",
                    data_offset,
                    data_offset as u64 + end_offset.saturating_sub(1)
                ))
                .await
            };

            let check_crc = |data: &[u8]| {
                let checksum = crc32fast::hash(data);
                if checksum != lfh.crc32 {
                    return Err(Error::DataCorruption(lfh.crc32, checksum));
                }

                Ok(())
            };

            match lfh.compression_method {
                netzip_parser::CompressionMethod::Deflate
                | netzip_parser::CompressionMethod::Deflate64 => {
                    let compressed_data: &[u8] = &download_chunk(compressed_size).await?;

                    let mut decoder = DeflateDecoder::new(compressed_data);
                    let mut decoded = Vec::with_capacity(uncompressed_size as usize);
                    decoder
                        .read_to_end(&mut decoded)
                        .map_err(|e| Error::DecompressionError(self.url.clone(), e.to_string()))?;

                    check_crc(&decoded)?;

                    out.push((lfh, decoded));
                }
                netzip_parser::CompressionMethod::Stored => {
                    let data = download_chunk(uncompressed_size).await?;
                    check_crc(&data)?;

                    out.push((lfh, data.to_vec()));
                }
                netzip_parser::CompressionMethod::Unsupported(unsupported_id) => {
                    return Err(Error::UnsupportCompression(unsupported_id));
                }
            }
        }

        return Ok(out);
    }

    async fn ranged_request(&self, range_string: &str) -> Result<Bytes, Error> {
        self.http_client
            .get(&self.url)
            .header("Range", range_string)
            .send()
            .await
            .map_err(|e| Error::NetworkError(self.url.clone(), e))?
            .bytes()
            .await
            .map_err(|e| Error::NetworkError(self.url.clone(), e))
    }
}

async fn ranged_request(
    url: &str,
    range_string: &str,
    client: reqwest::Client,
) -> Result<Bytes, Error> {
    client
        .get(url)
        .header("Range", range_string)
        .send()
        .await
        .map_err(|e| Error::NetworkError(url.into(), e))?
        .bytes()
        .await
        .map_err(|e| Error::NetworkError(url.into(), e))
}
