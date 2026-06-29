/// The little endian number used to denote the file as a valid Alpacka file "ALPK"
pub const MAGIC_NUMBER: u32 = 0x4B504C41;

/// The current version of Alpacka
pub const VERSION: u32 = 1;

/// The type of compression used for each entry
#[repr(u16)]
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
pub struct Header {
    /// Number that identifies this file as a valid Alpacka file "ALPK"
    pub magic: u32,
    /// Version of the format. Note: older versions of Alpacka files can be read, but can only be written to the newest version
    pub version: u32,
    /// Amount of files in the archive
    pub entry_count: u32,
    /// Location of where the archive data starts
    pub data_offset: u32,
    /// Location of where the archive's string table is. String table contains the file paths to each entry
    pub string_table_offset: u32,
    /// Location to the archive's index where entry information is stored.
    pub index_offset: u32,
    /// Padding
    pub reserved: u32,
}

/// Metadata for each file entry
pub struct Entry {
    /// File path hashed using FNV-1a
    pub path_hash: u64,
    /// Offset to where the file data is contained
    pub data_offset: u32,
    /// Size of the file when it's compressed
    pub compressed_size: u32,
    /// The size the file should be when no longer compressed
    pub original_size: u32,
    /// The style of compression used, refer to format::CompressionType
    pub compression_type: u16,
    /// Offset to the entry's file path string
    pub name_offset: u32,
    /// Padding
    pub reserved: u32,
}

/// Hashes a filepath using FNV-1a
pub fn hash_path(path: &str) -> u64 {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;

    let mut hash = OFFSET;
    for c in path.to_lowercase().replace("\\", "/").chars() {
        hash ^= c as u64;
        hash *= PRIME;
    }
    hash
}
