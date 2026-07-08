//! The on-disk format for Alpacka archives.
//!
//! # Layout
//! An archive is laid out as four contiguous sections, in this order:
//! `[header][data][string table][index]`
//! all multi-byte integers are little-endian
//!
//! - **header** -- fixed size [`Header`], always offset 0.
//! - **data** -- the concatenated bytes of every entry, each optionally compressed and/or encrypted.
//!   Located via [`Header::data_offset`].
//! - **string table** -- concatenated (not null-terminated) UTF-8 entry names, referenced by each
//!   [`Entry`]'s [`Entry::name_offset`]/[`Entry::name_length`].
//! - **index** -- one fixed-size [`Entry`] per archived file, back-to-back. Located via [`Header::index_offset`]
//!
//! # Design notes
//! - Every field in [`Header`] and [`Entry`] is a `u64`, for consistent byte alignment for consistent
//!   serialization and deserialization across languages and platforms.
//! - Fields are serialized and deserialize in declaration order. Reordering a struct's fields changes
//!   on-disk format and must be treated as a breaking change.
//! - Encryption, where used, is always applied *after* compression (see [`EncryptionType`])
//!   implementations must decrypt before decompressing and vice versa
//! - [`Entry`] names are meant to be relative file paths for better developer experience. for example,
//!   you would tell the packaging software where your Assets folder is, it will then *ideally* have
//!   every file (entry)'s name be based on their file paths.
//!   ex: `{project_root}/Assets/shaders/explosion.frag`
//!   would be accessed with:
//!   ```rust,ignore
//!   Reader.extract("shaders/explosion.frag")
//!   ```
//! - While an open standard, Alpacka is also meant to be very tight-knit and purpose built for game
//!   asset storage. meaning that i wish not for this format to be bloated with all different kinds
//!   of standards and encoders. **Alpacka is not just a container.** So please, to any future or
//!   current contributors, keep the format clean.

use hkdf::Hkdf;
use sha2::Sha256;
use wincode::{SchemaRead, SchemaWrite};

/// The little endian number used to denote the file as a valid Alpacka file "ALPK"
pub const MAGIC_NUMBER: u64 = 0x4B504C41;

/// The current version of Alpacka
pub const VERSION: u64 = 1;

/// the size of the Header type in the current specification, repliant on the all u64 layout
pub const HEADER_SIZE: usize = size_of::<Header>();

/// the size of the Entry type in the current specification, repliant on the all u64 layout
pub const ENTRY_SIZE: usize = size_of::<Entry>();

/// Poly1305's authentication tag length, in bytes.
/// Appended to every encrypted chunk's ciphertext per the ChaCha20-Poly1305 construction.
/// Note:specific to Poly1305
pub const TAG_SIZE: usize = 16;

/// the plaintext size, in bytes, of each chunk in the encryption STREAM construction.
/// All chunks are this size except the final one, which may be shorter (and is authenticated via
/// `decrypt_last`/`encrypt_last`).
pub const CHUNK_SIZE: usize = 64 * 1024;

/// The on-disk size, in bytes, of each *encrypted* chunk; plaintext [`CHUNK_SIZE`] plus its
/// [`TAG_SIZE`]-byte authentication tag. Used to split an encrypted entry's ciphertext back into its
/// original chunks on read.
pub const CIPHERTEXT_CHUNK_SIZE: usize = CHUNK_SIZE + TAG_SIZE;

/// The type of compression used for each entry's data, before any encryption.
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

/// The type of encryption applied to an entry's data, applied after compression
#[repr(u64)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, SchemaWrite, SchemaRead)]
#[wincode(tag_encoding = "u64")]
pub enum EncryptionType {
    /// no encryption - data is stored in plain (but possibley compressed) bytes
    None = 0,
    /// ChaCha20-Poly1305 authenticated encryption, applied in fixed-size chunks
    /// via a STREAM construction (see `CIPHERTEXT_CHUNK_SIZE`)
    ChaCha20Poly1305 = 1,
}

/// Header at the start of the file denoting the necessary information to begin reading the file
///
/// # Binary layout
///
/// | Offset  | Size | Field                | Type              |
/// |---------|------|-----------------------|-------------------|
/// | 0       | 8    | `magic`               | `u64`             |
/// | 8       | 8    | `version`             | `u64`             |
/// | 16      | 8    | `entry_count`         | `u64`             |
/// | 24      | 8    | `data_offset`         | `u64`             |
/// | 32      | 8    | `string_table_offset` | `u64`             |
/// | 40      | 8    | `index_offset`        | `u64`             |
/// | 48      | 8    | `index_checksum`      | `u64`             |
/// | 56      | 8    | `archive_salt`        | `u64`             |
/// | 64      | 8    | `reserved`            | `u64`             |
///
/// Total size: 72 bytes ([`HEADER_SIZE`]). Always located at file offset 0.
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
    /// A xxhash3-64 checksum for the whole index section to verify data integrity
    pub index_checksum: u64,
    /// A random non-secret value generated once the archive is created.
    /// mixed with the entry name into HKDF to create per-entry cryptographic sub-keys.
    /// This is so if two archives share the same master key and an entry shares an identical name (two archives contain the same file)
    /// they will still derive different sub-keys
    /// Note: should be generated with proper RNG to prevent collisions between archives
    pub archive_salt: u64,
    /// Padding
    pub reserved: u64,
}

/// Metadata for each file entry
///
/// # Binary layout
///
/// Offsets below are relative to the start of each `Entry` — entries are
/// packed back-to-back with no padding between them in the index section,
/// so entry `i`'s absolute file offset is `Header::index_offset + i * ENTRY_SIZE`.
///
/// | Offset | Size | Field               | Type                         |
/// |--------|------|---------------------|------------------------------|
/// | 0      | 8    | `custom1`           | `u64`                        |
/// | 8      | 8    | `custom2`           | `u64`                        |
/// | 16     | 8    | `data_offset`       | `u64`                        |
/// | 24     | 8    | `compressed_size`   | `u64`                        |
/// | 32     | 8    | `original_size`     | `u64`                        |
/// | 40     | 8    | `compression_type`  | [`CompressionType`] as `u64` |
/// | 48     | 8    | `name_offset`       | `u64`                        |
/// | 56     | 8    | `name_length`       | `u64`                        |
/// | 64     | 8    | `encryption_type`   | [`EncryptionType`] as `u64`  |
/// | 72     | 8    | `nonce`             | `u64`                        |
/// | 80     | 8    | `reserved`          | `u64`                        |
///
/// Total size: 88 bytes ([`ENTRY_SIZE`]).
#[derive(SchemaWrite, SchemaRead)]
pub struct Entry {
    /// 64 bits reserved for custom data set by the packager or preprocessor
    pub custom1: u64,
    /// 64 bits reserved for custom data set by the packager or preprocessor
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
    /// The style of encryption used, refer to format::EncryptionType
    pub encryption_type: EncryptionType,
    /// Nonce prefix used for this entry's stream encryption (lower 7 bytes used)
    /// Not secret - safe to store in the clear. Combined with per-entry
    /// sub-key (see `derive_entry_key`) to ensure unique encryption per entry.
    pub nonce: u64,
    /// Padding
    pub reserved: u64,
}

/// Derives a unique per-entry decryption sub-key from the master key
/// this way no two entries - even across different archives sharing the same master key
/// use the same key for encryption, uses [`Header::archive_salt`] and the entry's name
/// as HKDF's info parameter to guarantee uniqueness
///
/// # Parameters
/// - `master_key` -- supplied externally by the engine at runtime; never stored in the archive itself.
/// - `archive_salt` -- see [`Header::archive_salt`].
/// - `entry_name` -- the entry's full path as stored in the string table.
pub fn derive_entry_key(master_key: &[u8; 32], archive_salt: u64 , entry_name: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut info = Vec::with_capacity(8 + entry_name.len());
    info.extend_from_slice(&archive_salt.to_le_bytes());
    info.extend_from_slice(entry_name.as_bytes());

    let mut subkey = [0u8; 32];
    hk.expand(&info, &mut subkey).expect("32 bytes is a valid HKDF output length");
    subkey
}
