use wincode::{SchemaRead, SchemaWrite};

/// The little endian number used to denote the file as a valid Alpacka file "ALPK"
pub const MAGIC_NUMBER: u64 = 0x4B504C41;

/// The current version of Alpacka
pub const VERSION: u64 = 1;

/// the size of the Header type in the current specification
pub const HEADER_SIZE: usize = size_of::<Header>();

pub const ENTRY_SIZE: usize = size_of::<Entry>();

/// The type of compression used for each entry
#[repr(u64)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, SchemaWrite, SchemaRead)]
#[wincode(tag_encoding = "u64")]
pub enum CompressionType{
    /// No compression
    None = 0,
    /// Z-Standard compression, decent speed and compression
    Zstd = 1,
    /// Deflate compression, slowest speed and best compression
    Deflate = 2,
    /// LZ4 compression, fastest speed and worst compression
    Lz4 = 3,
}

/// Header at the start of the file denoting the necessary information to begin reading the file
#[derive(SchemaWrite, SchemaRead)]
pub struct Header {
    /// Number that identifies this file as a valid Alpacka file "ALPK"
    pub magic: u64,
    /// Version of the format. Note: older versions of Alpacka files can be read, but can only be written to the newest version
    pub version: u64,
    /// Amount of files in the archive
    pub entry_count: u64,
    /// Location of where the archive data starts
    pub data_offset: u64,
    /// Location of where the archive's string table is. String table contains the file paths to each entry
    pub string_table_offset: u64,
    /// Location to the archive's index where entry information is stored.
    pub index_offset: u64,
    /// a xxhash3-64 checksum for the whole index section to verify data integrity
    pub index_checksum: u64,
    /// Padding
    pub reserved: u64,
}

/// Metadata for each file entry
#[derive(SchemaWrite, SchemaRead)]
pub struct Entry {
    /// 32 bits reserved for custom data
    pub custom1: u64,
    /// 32 bits reserved for custom data
    pub custom2: u64,
    /// Offset to where the file data is contained relative to headers data offset
    pub data_offset: u64,
    /// Size of the file when it's compressed
    pub compressed_size: u64,
    /// The size the file should be when no longer compressed
    pub original_size: u64,
    /// The style of compression used, refer to format::CompressionType
    pub compression_type: CompressionType,
    /// Offset to the entry's file path string relative to headers string table offset
    pub name_offset: u64,
    /// Length of the file name in the string table
    pub name_length: u64,
    /// Padding
    pub reserved: u64,
}
