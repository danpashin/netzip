use scroll::Pread;
use thiserror::Error;

const MAGIC_CENTRAL_DIRECTORY_END: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
const MAGIC_CENTRAL_DIRECTORY_RECORD: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];
const MAGIC_LOCAL_FILE: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];
const MAGIC_ZIP64_EIF: [u8; 2] = [0x01, 0x00];

pub const EOCD_MIN_SIZE: usize = 22;
const EOCD_BASE_OFFSET: usize = MAGIC_CENTRAL_DIRECTORY_END.len();
const EOCD_DISK_NUMBER_OFFSET: usize = EOCD_BASE_OFFSET + 0;
const EOCD_DISK_START_OFFSET: usize = EOCD_BASE_OFFSET + 2;
const EOCD_RECORD_COUNT_DISK_OFFSET: usize = EOCD_BASE_OFFSET + 4;
const EOCD_RECORD_COUNT_TOTAL_OFFSET: usize = EOCD_BASE_OFFSET + 6;
const EOCD_DIRECTORY_SIZE_OFFSET: usize = EOCD_BASE_OFFSET + 8;
const EOCD_CENTRAL_DIRECTORY_OFFSET: usize = EOCD_BASE_OFFSET + 12;
const EOCD_COMMENT_LENGTH_OFFSET: usize = EOCD_BASE_OFFSET + 16;
const EOCD_COMMENT_START: usize = EOCD_BASE_OFFSET + 18;

pub const CDR_MIN_SIZE: usize = 46;
const CDR_BASE_OFFSET: usize = MAGIC_CENTRAL_DIRECTORY_RECORD.len();
const CDR_VERSION_CREATED_OFFSET: usize = CDR_BASE_OFFSET + 0;
const CDR_VERSION_REQUIRED_OFFSET: usize = CDR_BASE_OFFSET + 2;
const CDR_BIT_FLAG_OFFSET: usize = CDR_BASE_OFFSET + 4;
const CDR_COMPRESSION_METHOD_OFFSET: usize = CDR_BASE_OFFSET + 6;
const CDR_MOD_TIME_OFFSET: usize = CDR_BASE_OFFSET + 8;
const CDR_MOD_DATE_OFFSET: usize = CDR_BASE_OFFSET + 10;
const CDR_CRC32_OFFSET: usize = CDR_BASE_OFFSET + 12;
const CDR_COMPRESSED_SIZE_OFFSET: usize = CDR_BASE_OFFSET + 16;
const CDR_UNCOMPRESSED_SIZE_OFFSET: usize = CDR_BASE_OFFSET + 20;
const CDR_FILE_NAME_LENGTH_OFFSET: usize = CDR_BASE_OFFSET + 24;
const CDR_EXTRA_FIELD_LENGTH_OFFSET: usize = CDR_BASE_OFFSET + 26;
const CDR_COMMENT_LENGTH_OFFSET: usize = CDR_BASE_OFFSET + 28;
const CDR_DISK_NUMBER_OFFSET: usize = CDR_BASE_OFFSET + 30;
const CDR_INTERNAL_ATTRS_OFFSET: usize = CDR_BASE_OFFSET + 32;
const CDR_EXTERNAL_ATTRS_OFFSET: usize = CDR_BASE_OFFSET + 34;
const CDR_FILE_HEADER_OFFSET: usize = CDR_BASE_OFFSET + 38;
const CDR_FILE_NAME_START: usize = CDR_BASE_OFFSET + 42;

pub const LFH_MIN_SIZE: usize = 30;
const LFH_BASE_OFFSET: usize = MAGIC_LOCAL_FILE.len();
const LFH_VERSION_OFFSET: usize = LFH_BASE_OFFSET + 0;
const LFH_BIT_FLAG_OFFSET: usize = LFH_BASE_OFFSET + 2;
const LFH_COMPRESSION_METHOD_OFFSET: usize = LFH_BASE_OFFSET + 4;
const LFH_MOD_TIME_OFFSET: usize = LFH_BASE_OFFSET + 6;
const LFH_MOD_DATE_OFFSET: usize = LFH_BASE_OFFSET + 8;
const LFH_CRC32_OFFSET: usize = LFH_BASE_OFFSET + 10;
const LFH_COMPRESSED_SIZE_OFFSET: usize = LFH_BASE_OFFSET + 14;
const LFH_UNCOMPRESSED_SIZE_OFFSET: usize = LFH_BASE_OFFSET + 18;
const LFH_FILE_NAME_LENGTH_OFFSET: usize = LFH_BASE_OFFSET + 22;
const LFH_EXTRA_FIELD_LENGTH_OFFSET: usize = LFH_BASE_OFFSET + 24;
const LFH_FILE_NAME_START: usize = LFH_BASE_OFFSET + 26;

type Result<R> = std::result::Result<R, ZipError>;

#[derive(Debug, Eq, PartialEq)]
pub struct CentralDirectoryEnd {
    pub disk_number: u16,
    pub disk_start: u16,
    pub record_count_disk: u16,
    pub record_count_total: u16,
    /// Size in bytes
    pub directory_size: u32,
    /// Offset from the start of the archive
    pub central_directory_offset: u32,
    pub comment_length: u16,
    pub comment: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CentralDirectoryRecord {
    pub zip_version_created: u16,
    pub zip_version_required: u16,
    pub gp_bit_flag: u16,
    pub compression_method: CompressionMethod,
    pub last_modification_time: u16,
    pub last_modification_date: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub file_name_length: u16,
    pub extra_field_length: u16,
    pub file_comment_length: u16,
    pub disk_number: u16,
    pub file_attributes_internal: u16,
    pub file_attributes_external: u32,
    pub file_header_offset: u32,
    pub file_name: String,
    pub extra_bytes: Option<Vec<u8>>,
    pub comment: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct LocalFile {
    pub zip_version: u16,
    pub gp_bit_flag: u16,
    pub compression_method: CompressionMethod,
    pub last_modification_time: u16,
    pub last_modification_date: u16,
    pub crc32: u32,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
    pub file_name_length: u16,
    pub file_name: String,
    pub extra_field_length: u16,
    pub extra_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ExtendedInfoField {
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub relative_header_offset: Option<u64>,
    pub disk_start_number: Option<u32>,
}

#[repr(u16)]
#[derive(Debug, Eq, PartialEq)]
pub enum CompressionMethod {
    Stored = 0,
    Deflate = 8,
    Deflate64 = 9,
    Unsupported(u16),
}

#[non_exhaustive]
#[derive(Error, Debug, Eq, PartialEq)]
pub enum ZipError {
    #[error("Encountered unexpected end while parsing {0}.")]
    MissingData(&'static str),
    #[error("Encountered malformed data while parsing {0}.")]
    MalformedData(&'static str),
    #[error("Encountered extraneous data while parsing {0}.")]
    ExtraneousData(&'static str),
}

impl CentralDirectoryEnd {
    pub fn parse(central_dir_buf: &[u8]) -> Result<Self> {
        if central_dir_buf.len() < EOCD_MIN_SIZE {
            return Err(ZipError::MissingData("EOCD (Initial Length Check)"));
        }
        for i in 0..MAGIC_CENTRAL_DIRECTORY_END.len() {
            if central_dir_buf[i] != MAGIC_CENTRAL_DIRECTORY_END[i] {
                return Err(ZipError::MissingData("EOCD Magic"));
            }
        }

        let mut out = CentralDirectoryEnd {
            disk_number: u16::from_le_bytes([
                central_dir_buf[EOCD_DISK_NUMBER_OFFSET],
                central_dir_buf[EOCD_DISK_NUMBER_OFFSET + 1],
            ]),
            disk_start: u16::from_le_bytes([
                central_dir_buf[EOCD_DISK_START_OFFSET],
                central_dir_buf[EOCD_DISK_START_OFFSET + 1],
            ]),
            record_count_disk: u16::from_le_bytes([
                central_dir_buf[EOCD_RECORD_COUNT_DISK_OFFSET],
                central_dir_buf[EOCD_RECORD_COUNT_DISK_OFFSET + 1],
            ]),
            record_count_total: u16::from_le_bytes([
                central_dir_buf[EOCD_RECORD_COUNT_TOTAL_OFFSET],
                central_dir_buf[EOCD_RECORD_COUNT_TOTAL_OFFSET + 1],
            ]),
            directory_size: u32::from_le_bytes([
                central_dir_buf[EOCD_DIRECTORY_SIZE_OFFSET],
                central_dir_buf[EOCD_DIRECTORY_SIZE_OFFSET + 1],
                central_dir_buf[EOCD_DIRECTORY_SIZE_OFFSET + 2],
                central_dir_buf[EOCD_DIRECTORY_SIZE_OFFSET + 3],
            ]),
            central_directory_offset: u32::from_le_bytes([
                central_dir_buf[EOCD_CENTRAL_DIRECTORY_OFFSET],
                central_dir_buf[EOCD_CENTRAL_DIRECTORY_OFFSET + 1],
                central_dir_buf[EOCD_CENTRAL_DIRECTORY_OFFSET + 2],
                central_dir_buf[EOCD_CENTRAL_DIRECTORY_OFFSET + 3],
            ]),
            comment_length: u16::from_le_bytes([
                central_dir_buf[EOCD_COMMENT_LENGTH_OFFSET],
                central_dir_buf[EOCD_COMMENT_LENGTH_OFFSET + 1],
            ]),
            comment: None,
        };

        if out.comment_length > 0 {
            let comment_end = EOCD_COMMENT_START + out.comment_length as usize;

            if comment_end > central_dir_buf.len() {
                return Err(ZipError::MissingData("EOCD Comment"));
            } else if comment_end < central_dir_buf.len() {
                return Err(ZipError::ExtraneousData("EOCD Comment"));
            }

            out.comment = Some(
                String::from_utf8_lossy(&central_dir_buf[EOCD_COMMENT_START..comment_end])
                    .into_owned(),
            );
        } else {
            if central_dir_buf.len() != EOCD_MIN_SIZE {
                return Err(ZipError::ExtraneousData("EOCD Comment (comment length 0)"));
            }
        }

        Ok(out)
    }

    pub fn find_and_parse(haystack: &[u8]) -> Result<Self> {
        let mut magic_cursor = MAGIC_CENTRAL_DIRECTORY_END.len() - 1;
        for idx in (MAGIC_CENTRAL_DIRECTORY_END.len() - 1..haystack.len()).rev() {
            if haystack[idx] == MAGIC_CENTRAL_DIRECTORY_END[magic_cursor] {
                if magic_cursor == 0 {
                    return CentralDirectoryEnd::parse(&haystack[idx - magic_cursor..]);
                } else {
                    magic_cursor -= 1;
                }
            } else {
                magic_cursor = MAGIC_CENTRAL_DIRECTORY_END.len() - 1;
            }
        }

        Err(ZipError::MissingData("EOCD Magic"))
    }
}

impl CentralDirectoryRecord {
    pub fn parse_many(records_buf: &[u8]) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        let mut cursor = 0;
        while cursor < records_buf.len() - 1 {
            let current_record = Self::parse(&records_buf[cursor..], true)?;
            cursor += CDR_MIN_SIZE
                + current_record.file_comment_length as usize
                + current_record.file_name_length as usize
                + current_record.extra_field_length as usize;
            out.push(current_record);
        }

        Ok(out)
    }

    pub fn parse(record_buf: &[u8], allow_extraneous: bool) -> Result<Self> {
        if record_buf.len() < CDR_MIN_SIZE {
            return Err(ZipError::MissingData("CDR (Initial Length Check)"));
        }

        for i in 0..MAGIC_CENTRAL_DIRECTORY_RECORD.len() {
            if record_buf[i] != MAGIC_CENTRAL_DIRECTORY_RECORD[i] {
                return Err(ZipError::MissingData("CDR Magic"));
            }
        }

        let file_name_length = u16::from_le_bytes([
            record_buf[CDR_FILE_NAME_LENGTH_OFFSET],
            record_buf[CDR_FILE_NAME_LENGTH_OFFSET + 1],
        ]);

        let extra_field_length = u16::from_le_bytes([
            record_buf[CDR_EXTRA_FIELD_LENGTH_OFFSET],
            record_buf[CDR_EXTRA_FIELD_LENGTH_OFFSET + 1],
        ]);

        let file_comment_length = u16::from_le_bytes([
            record_buf[CDR_COMMENT_LENGTH_OFFSET],
            record_buf[CDR_COMMENT_LENGTH_OFFSET + 1],
        ]);

        let required_length = CDR_FILE_NAME_START
            + file_name_length as usize
            + extra_field_length as usize
            + file_comment_length as usize;

        if record_buf.len() < required_length {
            return Err(ZipError::MissingData("CDR Variable Length Fields"));
        } else if record_buf.len() > required_length && !allow_extraneous {
            return Err(ZipError::ExtraneousData("CDR"));
        }

        let compression_method_raw = u16::from_le_bytes([
            record_buf[CDR_COMPRESSION_METHOD_OFFSET],
            record_buf[CDR_COMPRESSION_METHOD_OFFSET + 1],
        ]);

        let compression_method = match compression_method_raw {
            0 => CompressionMethod::Stored,
            8 => CompressionMethod::Deflate,
            9 => CompressionMethod::Deflate64,
            x => CompressionMethod::Unsupported(x),
        };

        let mut record = CentralDirectoryRecord {
            zip_version_created: u16::from_le_bytes([
                record_buf[CDR_VERSION_CREATED_OFFSET],
                record_buf[CDR_VERSION_CREATED_OFFSET + 1],
            ]),
            zip_version_required: u16::from_le_bytes([
                record_buf[CDR_VERSION_REQUIRED_OFFSET],
                record_buf[CDR_VERSION_REQUIRED_OFFSET + 1],
            ]),
            gp_bit_flag: u16::from_le_bytes([
                record_buf[CDR_BIT_FLAG_OFFSET],
                record_buf[CDR_BIT_FLAG_OFFSET + 1],
            ]),
            compression_method,
            last_modification_time: u16::from_le_bytes([
                record_buf[CDR_MOD_TIME_OFFSET],
                record_buf[CDR_MOD_TIME_OFFSET + 1],
            ]),
            last_modification_date: u16::from_le_bytes([
                record_buf[CDR_MOD_DATE_OFFSET],
                record_buf[CDR_MOD_DATE_OFFSET + 1],
            ]),
            crc32: u32::from_le_bytes([
                record_buf[CDR_CRC32_OFFSET],
                record_buf[CDR_CRC32_OFFSET + 1],
                record_buf[CDR_CRC32_OFFSET + 2],
                record_buf[CDR_CRC32_OFFSET + 3],
            ]),
            compressed_size: u32::from_le_bytes([
                record_buf[CDR_COMPRESSED_SIZE_OFFSET],
                record_buf[CDR_COMPRESSED_SIZE_OFFSET + 1],
                record_buf[CDR_COMPRESSED_SIZE_OFFSET + 2],
                record_buf[CDR_COMPRESSED_SIZE_OFFSET + 3],
            ]),
            uncompressed_size: u32::from_le_bytes([
                record_buf[CDR_UNCOMPRESSED_SIZE_OFFSET],
                record_buf[CDR_UNCOMPRESSED_SIZE_OFFSET + 1],
                record_buf[CDR_UNCOMPRESSED_SIZE_OFFSET + 2],
                record_buf[CDR_UNCOMPRESSED_SIZE_OFFSET + 3],
            ]),
            file_name_length,
            extra_field_length,
            file_comment_length,
            disk_number: u16::from_le_bytes([
                record_buf[CDR_DISK_NUMBER_OFFSET],
                record_buf[CDR_DISK_NUMBER_OFFSET + 1],
            ]),
            file_attributes_internal: u16::from_le_bytes([
                record_buf[CDR_INTERNAL_ATTRS_OFFSET],
                record_buf[CDR_INTERNAL_ATTRS_OFFSET + 1],
            ]),
            file_attributes_external: u32::from_le_bytes([
                record_buf[CDR_EXTERNAL_ATTRS_OFFSET],
                record_buf[CDR_EXTERNAL_ATTRS_OFFSET + 1],
                record_buf[CDR_EXTERNAL_ATTRS_OFFSET + 2],
                record_buf[CDR_EXTERNAL_ATTRS_OFFSET + 3],
            ]),
            file_header_offset: u32::from_le_bytes([
                record_buf[CDR_FILE_HEADER_OFFSET],
                record_buf[CDR_FILE_HEADER_OFFSET + 1],
                record_buf[CDR_FILE_HEADER_OFFSET + 2],
                record_buf[CDR_FILE_HEADER_OFFSET + 3],
            ]),
            file_name: String::new(),
            extra_bytes: None,
            comment: None,
        };

        let mut current_offset = CDR_FILE_NAME_START;

        record.file_name = String::from_utf8_lossy(
            &record_buf[current_offset..current_offset + file_name_length as usize],
        )
        .into_owned();
        current_offset += file_name_length as usize;

        if extra_field_length > 0 {
            record.extra_bytes = Some(
                record_buf[current_offset..current_offset + extra_field_length as usize].to_vec(),
            );
            current_offset += extra_field_length as usize;
        }

        if file_comment_length > 0 {
            record.comment = Some(
                String::from_utf8_lossy(
                    &record_buf[current_offset..current_offset + file_comment_length as usize],
                )
                .into_owned(),
            );
        }

        Ok(record)
    }

    pub fn zip64_extended_info(&self) -> Option<ExtendedInfoField> {
        self.extra_bytes
            .as_ref()
            .and_then(|bytes| bytes.pread_with(0, scroll::LE).ok())
    }
}

impl LocalFile {
    pub fn parse(file_buf: &[u8]) -> Result<Self> {
        if file_buf.len() < LFH_MIN_SIZE {
            return Err(ZipError::MissingData("Local File (Initial Length Check)"));
        }

        for i in 0..MAGIC_LOCAL_FILE.len() {
            if file_buf[i] != MAGIC_LOCAL_FILE[i] {
                return Err(ZipError::MissingData("Local File Magic"));
            }
        }

        let file_name_length = u16::from_le_bytes([
            file_buf[LFH_FILE_NAME_LENGTH_OFFSET],
            file_buf[LFH_FILE_NAME_LENGTH_OFFSET + 1],
        ]);

        let extra_field_length = u16::from_le_bytes([
            file_buf[LFH_EXTRA_FIELD_LENGTH_OFFSET],
            file_buf[LFH_EXTRA_FIELD_LENGTH_OFFSET + 1],
        ]);

        let compressed_size = u32::from_le_bytes([
            file_buf[LFH_COMPRESSED_SIZE_OFFSET],
            file_buf[LFH_COMPRESSED_SIZE_OFFSET + 1],
            file_buf[LFH_COMPRESSED_SIZE_OFFSET + 2],
            file_buf[LFH_COMPRESSED_SIZE_OFFSET + 3],
        ]);

        let compression_method_raw = u16::from_le_bytes([
            file_buf[LFH_COMPRESSION_METHOD_OFFSET],
            file_buf[LFH_COMPRESSION_METHOD_OFFSET + 1],
        ]);

        let compression_method = match compression_method_raw {
            0 => CompressionMethod::Stored,
            8 => CompressionMethod::Deflate,
            9 => CompressionMethod::Deflate64,
            x => CompressionMethod::Unsupported(x),
        };

        let mut local_file = LocalFile {
            zip_version: u16::from_le_bytes([
                file_buf[LFH_VERSION_OFFSET],
                file_buf[LFH_VERSION_OFFSET + 1],
            ]),
            gp_bit_flag: u16::from_le_bytes([
                file_buf[LFH_BIT_FLAG_OFFSET],
                file_buf[LFH_BIT_FLAG_OFFSET + 1],
            ]),
            compression_method,
            last_modification_time: u16::from_le_bytes([
                file_buf[LFH_MOD_TIME_OFFSET],
                file_buf[LFH_MOD_TIME_OFFSET + 1],
            ]),
            last_modification_date: u16::from_le_bytes([
                file_buf[LFH_MOD_DATE_OFFSET],
                file_buf[LFH_MOD_DATE_OFFSET + 1],
            ]),
            crc32: u32::from_le_bytes([
                file_buf[LFH_CRC32_OFFSET],
                file_buf[LFH_CRC32_OFFSET + 1],
                file_buf[LFH_CRC32_OFFSET + 2],
                file_buf[LFH_CRC32_OFFSET + 3],
            ]),
            compressed_size,
            uncompressed_size: u32::from_le_bytes([
                file_buf[LFH_UNCOMPRESSED_SIZE_OFFSET],
                file_buf[LFH_UNCOMPRESSED_SIZE_OFFSET + 1],
                file_buf[LFH_UNCOMPRESSED_SIZE_OFFSET + 2],
                file_buf[LFH_UNCOMPRESSED_SIZE_OFFSET + 3],
            ]),
            file_name: String::new(),
            file_name_length,
            extra_field_length,
            extra_bytes: None,
        };

        let mut current_offset = LFH_FILE_NAME_START;
        local_file.file_name = String::from_utf8_lossy(
            &file_buf[current_offset..current_offset + file_name_length as usize],
        )
        .into_owned();
        current_offset += file_name_length as usize;

        if extra_field_length > 0 {
            // Seems like some zip tools set invalid extra_field_length
            // Possibly should set extra_bytes to None instead of trimming?
            let end_offset = (current_offset + extra_field_length as usize).min(file_buf.len());
            local_file.extra_bytes = Some(file_buf[current_offset..end_offset].to_vec());
        }

        Ok(local_file)
    }
}

impl<'a> scroll::ctx::TryFromCtx<'a, scroll::Endian> for ExtendedInfoField {
    type Error = scroll::Error;

    #[allow(unused_assignments)]
    fn try_from_ctx(src: &'a [u8], ctx: scroll::Endian) -> scroll::Result<(Self, usize)> {
        let offset = &mut 0;

        let magic = src.gread_with::<u16>(offset, ctx)?;
        if magic.to_le_bytes() != MAGIC_ZIP64_EIF {
            return Err(scroll::Error::BadInput {
                size: 0,
                msg: "Invalid magic",
            });
        }

        // size is a size of all blob
        // uncompressed_size and compressed_size fields are required to persist
        // so subtracting 16 bytes
        let mut size = src.gread_with::<u16>(offset, ctx)?.saturating_sub(16);

        let mut data = Self {
            uncompressed_size: src.gread_with(offset, ctx)?,
            compressed_size: src.gread_with(offset, ctx)?,
            relative_header_offset: None,
            disk_start_number: None,
        };

        if size != 0 {
            data.relative_header_offset = Some(src.gread_with(offset, ctx)?);
            size = size.saturating_sub(8);
        }

        if size != 0 {
            data.disk_start_number = Some(src.gread_with(offset, ctx)?);
            size = size.saturating_sub(4);
        }

        Ok((data, *offset))
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn basic_eocd_parsing() {
        let valid_input: [u8; 0x16] = [
            0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x07, 0x01, 0x61, 0x43,
            0x00, 0x00, 0xA5, 0x98, 0xE4, 0x03, 0x00, 0x00,
        ];

        let dir_end = CentralDirectoryEnd::parse(&valid_input).unwrap();

        assert_eq!(dir_end.central_directory_offset, 65312933);
        assert_eq!(dir_end.comment, None);
        assert_eq!(dir_end.comment_length, 0);
        assert_eq!(dir_end.directory_size, 17249);
        assert_eq!(dir_end.disk_number, 0);
        assert_eq!(dir_end.disk_start, 0);
        assert_eq!(dir_end.record_count_disk, 263);
        assert_eq!(dir_end.record_count_total, 263);
    }

    #[test]
    fn commented_eocd_parsing() {
        let valid_input: [u8; 0x19] = [
            0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x07, 0x01, 0x61, 0x43,
            0x00, 0x00, 0xA5, 0x98, 0xE4, 0x03, 0x03, 0x00, 0x41, 0x42, 0x43,
        ];
        let dir_end = CentralDirectoryEnd::parse(&valid_input).unwrap();

        assert_eq!(dir_end.central_directory_offset, 65312933);
        assert_eq!(dir_end.comment, Some("ABC".into()));
        assert_eq!(dir_end.comment_length, 3);
        assert_eq!(dir_end.directory_size, 17249);
        assert_eq!(dir_end.disk_number, 0);
        assert_eq!(dir_end.disk_start, 0);
        assert_eq!(dir_end.record_count_disk, 263);
        assert_eq!(dir_end.record_count_total, 263);
    }

    #[test]
    fn test_find_and_parse() {
        let input: [u8; 26] = [
            // Some random data before EOCD
            0x10, 0x20, 0x30, 0x40, // Valid EOCD with no comment
            0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x07, 0x01, 0x07, 0x01, 0x61, 0x43,
            0x00, 0x00, 0xA5, 0x98, 0xE4, 0x03, 0x00, 0x00,
        ];
        let dir_end = CentralDirectoryEnd::find_and_parse(&input).unwrap();

        assert_eq!(dir_end.central_directory_offset, 65312933);
        assert_eq!(dir_end.comment, None);
        assert_eq!(dir_end.comment_length, 0);
        assert_eq!(dir_end.directory_size, 17249);
        assert_eq!(dir_end.disk_number, 0);
        assert_eq!(dir_end.disk_start, 0);
        assert_eq!(dir_end.record_count_disk, 263);
        assert_eq!(dir_end.record_count_total, 263);
    }

    #[test]
    fn test_cdr_parse() {
        let input: [u8; 0x39] = [
            0x37, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x44,
            0x20, 0x65, 0x59, 0x41, 0x83, 0x0E, 0x26, 0x72, 0x01, 0x00, 0x00, 0x1E, 0x02, 0x00,
            0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA4,
            0x81, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x43, 0x35, 0x4D, 0x37, 0x53, 0x4D, 0x56, 0x42,
            0x4B,
        ];
        let record = CentralDirectoryRecord::parse(&input[1..], false).unwrap();

        assert_eq!(record.zip_version_created, 788);
        assert_eq!(record.zip_version_required, 20);
        assert_eq!(record.gp_bit_flag, 0);
        assert_eq!(record.compression_method, CompressionMethod::Deflate);
        assert_eq!(record.last_modification_time, 0x2044);
        assert_eq!(record.last_modification_date, 0x5965);
        assert_eq!(record.crc32, 0x260E8341);
        assert_eq!(record.compressed_size, 370);
        assert_eq!(record.uncompressed_size, 542);
        assert_eq!(record.file_name_length, 10);
        assert_eq!(record.extra_field_length, 0);
        assert_eq!(record.file_comment_length, 0);
        assert_eq!(record.disk_number, 0);
        assert_eq!(record.file_attributes_internal, 0);
        assert_eq!(record.file_attributes_external, 2175008768);
        assert_eq!(record.file_header_offset, 0);
        assert_eq!(record.file_name, "JC5M7SMVBK");
        assert_eq!(record.extra_bytes, None);
        assert_eq!(record.comment, None);
    }

    #[test]
    fn test_lfh_parse() {
        let input: [u8; 0x48] = [
            0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9D, 0x4B, 0x83, 0x59,
            0x57, 0x51, 0x33, 0x2C, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x1C, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x74, 0x78, 0x74, 0x55, 0x54, 0x09, 0x00,
            0x03, 0x4A, 0xC1, 0x4E, 0x67, 0x4A, 0xC1, 0x4E, 0x67, 0x75, 0x78, 0x0B, 0x00, 0x01,
            0x04, 0xE8, 0x03, 0x00, 0x00, 0x04, 0xE8, 0x03, 0x00, 0x00, 0x41, 0x42, 0x31, 0x32,
            0x33, 0x0A,
        ];

        let local_file = LocalFile::parse(&input[..]).unwrap();

        assert_eq!(local_file.zip_version, 10);
        assert_eq!(local_file.gp_bit_flag, 0);
        assert_eq!(local_file.compression_method, CompressionMethod::Stored);
        assert_eq!(local_file.last_modification_time, 0x4b9d);
        assert_eq!(local_file.last_modification_date, 0x5983);
        assert_eq!(local_file.crc32, 0x2c335157);
        assert_eq!(local_file.compressed_size, 6);
        assert_eq!(local_file.uncompressed_size, 6);
        assert_eq!(local_file.file_name, "test.txt");
        assert_eq!(local_file.file_name_length, 8);
        assert_eq!(local_file.extra_field_length, 28);
    }

    #[test]
    fn test_zip64_extra_field() {
        let input: [u8; 100] = [
            0x50, 0x4B, 0x01, 0x02, 0x2D, 0x03, 0x2D, 0x00, 0x00, 0x00, 0x08, 0x00, 0x20, 0x4D,
            0x29, 0x36, 0x34, 0xFE, 0xA5, 0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x1A, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA4, 0x81,
            0xFF, 0xFF, 0xFF, 0xFF, 0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x63, 0x61, 0x63, 0x68,
            0x65, 0x2E, 0x72, 0x65, 0x6C, 0x65, 0x61, 0x73, 0x65, 0x2E, 0x69, 0x70, 0x61, 0x64,
            0x37, 0x62, 0x01, 0x00, 0x18, 0x00, 0xD8, 0xEB, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xCE, 0x9C, 0xDE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x76, 0xC5, 0xE4, 0x00, 0x00,
            0x00, 0x00,
        ];

        let cd_record = CentralDirectoryRecord::parse(&input[..], false).unwrap();
        assert_eq!(cd_record.crc32, 0x9BA5FE34);
        assert_eq!(cd_record.compressed_size, 0xFFFFFFFF);
        assert_eq!(cd_record.uncompressed_size, 0xFFFFFFFF);

        let extra_info = cd_record.zip64_extended_info().unwrap();
        assert_eq!(extra_info.uncompressed_size, 0xDEEBD8);
        assert_eq!(extra_info.compressed_size, 0xDE9CCE);
        assert_eq!(extra_info.relative_header_offset, Some(0xE4C57614));
        assert_eq!(extra_info.disk_start_number, None);
    }
}
