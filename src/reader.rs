//! Reads Alpacka archives.
//!
//! Per-entry data is processed in a fixed pipeline: on write, plaintext is compressed, then optionally
//! encrypted. On read, that's reversed: ciphertext is decrypted first, then decompressed. Encryption uses
//! ChaCha20-Poly1305 in a chunked STREAM construction, with per-entry sub-key derived via HKDF
//! from the archive's master key, `Header.archive_salt`, and the entry's name

use crate::format::{
    CIPHERTEXT_CHUNK_SIZE, CompressionType, ENTRY_SIZE, EncryptionType, Entry, HEADER_SIZE, Header,
    MAGIC_NUMBER, VERSION, derive_entry_key,
};
use aead_stream::DecryptorBE32;
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use positioned_io::ReadAt;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::Mutex;
use std::time::Instant;
use tempfile::{Builder, TempPath};
use thiserror::Error;
use xxhash_rust::xxh3::xxh3_64;

pub const ROOT: &str = "";

#[derive(Debug, Error)]
pub enum ReaderError {
    #[error("header malformed")]
    HeaderMalformed(#[source] wincode::ReadError),

    #[error(
        "invalid magic number: expected: {expected}, found: {0}",
        expected = crate::format::MAGIC_NUMBER
    )]
    BadMagic(u64),

    #[error("archive version {0} is unsupported")]
    UnsupportedVersion(u64),

    #[error("checksum mismatch")]
    ChecksumMismatch { expected: u64, found: u64 },

    #[error("{decompressor} decompressor has failed: {error}")]
    DecompressionFailure {
        decompressor: String,
        #[source]
        error: std::io::Error,
    },

    #[error("entry {0} has no data to decrypt")]
    NoDataToDecrypt(String),

    #[error("authentication failed for {0}")]
    AuthenticationFailure(String),

    #[error("no such entry: {0}")]
    NoSuchEntry(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub trait AssetAccessor {
    fn extract(&self, name: &str) -> Result<Vec<u8>, ReaderError>;
    fn stream(&self, name: &str) -> Result<Box<dyn Read + Send + '_>, ReaderError>;
    fn extract_to_temp_file(&self, name: &str) -> Result<TempPath, ReaderError>;

    /// creates a list of paths in a folder
    ///
    /// recursive makes the list drill down and list files inside subdirectories
    fn list(&self, folder: &str, recursive: bool) -> Result<Vec<String>, ReaderError>;

    /// uses the normal list function but only returns paths that contain the specified extension
    fn list_with_extension(
        &self,
        folder: &str,
        ext: &str,
        recursive: bool,
    ) -> Result<Vec<String>, ReaderError> {
        Ok(self
            .list(folder, recursive)?
            .into_iter()
            .filter(|name| {
                name.rsplit('.')
                    .next()
                    .is_some_and(|e| e.eq_ignore_ascii_case(ext))
            })
            .collect())
    }
}

#[derive(Debug)]
pub struct AlpackReader {
    pub header: Header,
    file: File,
    entries: HashMap<String, Entry>,
    master_key: [u8; 32],
}

impl AlpackReader {
    /// Creates a new Alpack reader, catalogs all the entries of the archive to be referenced later/
    ///
    /// `master_key` must match whatever key was used to encrypt the archive's entries at pack time
    /// the key itself is never stored in the archive. If the archive contains no encrypted entries,
    /// any value can be stored here, though callers may prefer a fixed/default key for clarity.
    ///
    /// # Debug
    /// Returns [`LooseAssetReader`] instead of a [`AlpackReader`] if `ALPACKA_ASSET_ROOT` enviroment
    /// variable is set.
    ///
    /// `ALPACKA_ASSET_ROOT` will use the same API as a AlpackReader however it will instead read raw
    /// files in the path specified by `ALPACKA_ASSET_ROOT` and mimic the same behavior allowing for
    /// faster iteration. **THIS IS FOR IN-DEV AND DEBUG, NOT RELEASE.**
    ///
    /// # Errors
    /// Returns an error if the file cant be opened, the header is corrupt or has an unrecognized
    /// magic number, the archive's format is newer then this crate supports, or the index checksum
    /// doesn't match.
    pub fn open(path: &Path, master_key: [u8; 32]) -> Result<Box<dyn AssetAccessor>, ReaderError> {
        if std::env::var("ALPACKA_ASSET_ROOT").is_ok() {
            return Ok(Box::new(LooseAssetReader::new(
                std::env::var("ALPACKA_ASSET_ROOT").unwrap(),
            )?));
        }

        Ok(Box::new(AlpackReader::new(path, master_key)?))
    }

    fn new(path: &Path, master_key: [u8; 32]) -> Result<Self, ReaderError> {
        let file = File::open(path)?;

        let mut reader = BufReader::new(&file);

        let mut header_buf = [0u8; HEADER_SIZE];

        reader.read_exact(&mut header_buf)?;

        let header: Header =
            wincode::deserialize(&header_buf).map_err(ReaderError::HeaderMalformed)?;

        if header.magic != MAGIC_NUMBER {
            Err(ReaderError::BadMagic(header.magic))?;
        }
        if header.version > VERSION {
            Err(ReaderError::UnsupportedVersion(header.version))?
        }

        let mut entries: HashMap<String, Entry> =
            HashMap::with_capacity(header.entry_count as usize);

        let mut entries_buf: Vec<u8> = vec![0u8; header.entry_count as usize * ENTRY_SIZE];

        let entry_pos = header.index_offset;
        reader.seek(SeekFrom::Start(entry_pos))?;
        reader.read_exact(&mut entries_buf)?;

        let checksum = xxh3_64(entries_buf.as_slice());

        if checksum != header.index_checksum {
            return Err(ReaderError::ChecksumMismatch {
                expected: header.index_checksum,
                found: checksum,
            });
        }

        for i in 0..header.entry_count {
            let entry_pos = i as usize * ENTRY_SIZE;

            let entry_buf = &entries_buf[entry_pos..entry_pos + ENTRY_SIZE];

            let entry: Entry = match wincode::deserialize(&entry_buf) {
                Ok(e) => e,
                Err(e) => {
                    println!("Error: Invalid entry: {e}, skipping");
                    continue;
                }
            };

            if reader
                .seek(SeekFrom::Start(
                    header.string_table_offset + entry.name_offset,
                ))
                .is_err()
            {
                println!("Error: invalid String Table offset, skipping entry.");
                continue;
            }

            let mut name_buf = vec![0u8; entry.name_length as usize];
            if reader.read_exact(&mut name_buf).is_err() {
                println!("Error: string table entry truncated, skipping.");
                continue;
            }

            let name = match String::from_utf8(name_buf) {
                Ok(n) => n,
                Err(e) => {
                    println!("Error: invalid string table entry: {e}, skipping");
                    continue;
                }
            };

            entries.insert(name, entry);
        }

        Ok(AlpackReader {
            header,
            file,
            entries,
            master_key,
        })
    }

    fn decompressor<'a, R: Read + Send + 'a>(
        source: R,
        compression_type: CompressionType,
    ) -> Result<Box<dyn Read + Send + 'a>, ReaderError> {
        match compression_type {
            CompressionType::None => Ok(Box::new(source)),
            CompressionType::Zstd => {
                Ok(Box::new(zstd::stream::read::Decoder::new(source).map_err(
                    |error| ReaderError::DecompressionFailure {
                        decompressor: "zstd".to_string(),
                        error,
                    },
                )?))
            }
            CompressionType::Deflate => Ok(Box::new(flate2::read::DeflateDecoder::new(source))),
            CompressionType::Lz4 => Ok(Box::new(lz4::Decoder::new(source).map_err(|error| {
                ReaderError::DecompressionFailure {
                    decompressor: "LZ4".to_string(),
                    error,
                }
            })?)),
        }
    }

    /// take the u64 (8 byte) value from the entry and turn it into a 7 byte nonce
    fn unpack_nonce(nonce: u64) -> [u8; 7] {
        let bytes = nonce.to_le_bytes();
        bytes[..7].try_into().expect("slice is exactly 7 bytes")
    }

    /// Decrypts `ciphertext` for the given entry, if it's encrypted. Chunks ciphertext according to
    /// `CIPHERTEXT_CHUNK_SIZE` and authentication each chunk against `name` as associated data -
    /// swapping ciphertext between two differently-named entries will fail authentication.
    fn decrypt_entry(
        &self,
        name: &str,
        entry: &Entry,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ReaderError> {
        match entry.encryption_type {
            EncryptionType::None => Ok(ciphertext.to_vec()),
            EncryptionType::ChaCha20Poly1305 => {
                let subkey = derive_entry_key(&self.master_key, self.header.archive_salt, name);
                let cipher = ChaCha20Poly1305::new((&subkey).into());
                let nonce_prefix = Self::unpack_nonce(entry.nonce);
                let mut decryptor = DecryptorBE32::from_aead(cipher, (&nonce_prefix).into());

                let mut plaintext = Vec::with_capacity(ciphertext.len());
                let chunks: Vec<&[u8]> = ciphertext.chunks(CIPHERTEXT_CHUNK_SIZE).collect();
                let (last_chunk, initial_chunks) = chunks
                    .split_last()
                    .ok_or_else(|| ReaderError::NoDataToDecrypt(name.to_string()))?;

                for chunk in initial_chunks {
                    let payload = Payload {
                        msg: chunk,
                        aad: name.as_bytes(),
                    };
                    let decrypted = decryptor
                        .decrypt_next(payload)
                        .map_err(|_| ReaderError::AuthenticationFailure(name.to_string()))?;
                    plaintext.extend_from_slice(&decrypted);
                }

                let payload = Payload {
                    msg: last_chunk,
                    aad: name.as_bytes(),
                };
                let decrypted = decryptor
                    .decrypt_last(payload)
                    .map_err(|_| ReaderError::AuthenticationFailure(name.to_string()))?;
                plaintext.extend_from_slice(&decrypted);

                Ok(plaintext)
            }
        }
    }

    fn matches_folder<'a>(name: &'a str, folder: &str) -> Option<&'a str> {
        if folder.is_empty() {
            return Some(name);
        }

        let rest = name.strip_prefix(folder)?;
        rest.strip_prefix('/')
    }
}

impl AssetAccessor for AlpackReader {
    /// Extracts and returns the full decoded contents of the named entry.
    ///
    /// Data flows: read ciphertext -> decrypt (if encrypted) -> decompress (if compressed).
    /// The entire entry is decrypted and decompressed into memory; for large entries where
    /// memory-bounded access matters, prefer [`AlpackReader::stream`]
    ///
    /// # Errors
    /// Returns an error if no entry with this name exists, the underlying read fails, decryption
    /// authentication fails (wrong key, tampered data, or wrong entry name), or decompression fails.
    fn extract(&self, name: &str) -> Result<Vec<u8>, ReaderError> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| ReaderError::NoSuchEntry(name.to_string()))?;

        let abs_offset = self.header.data_offset + entry.data_offset;

        let mut ciphertext = vec![0u8; entry.compressed_size as usize];
        self.file.read_exact_at(abs_offset, &mut ciphertext)?;

        let compressed = self.decrypt_entry(name, entry, &ciphertext)?;

        let mut decoder = Self::decompressor(Cursor::new(compressed), entry.compression_type)?;

        let mut decompressed = Vec::with_capacity(entry.original_size as usize);
        decoder.read_to_end(&mut decompressed)?;

        Ok(decompressed)
    }

    /// Returns a streaming, memory-bounded reader over the named entry's decoded contents.
    ///
    /// Data flows the same as [`AlpackReader::extract`] (decrypt -> decompress), but ciphertext is read
    /// and authenticated in fixed-size chunks as the caller reads, rather than buffering the whole
    /// entry up front.
    ///
    /// # Errors
    /// Returns an error if no entry with this name exists or if constructing the decompressor fails.
    /// Authentication failures on encrypted entries surface as [`std::io::Error`]s from the returned
    /// reader's `read` calls, not from this function itself.
    fn stream(&self, name: &str) -> Result<Box<dyn Read + Send + '_>, ReaderError> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| ReaderError::NoSuchEntry(name.to_string()))?;

        let abs_offset = self.header.data_offset + entry.data_offset;

        let bounded = BoundedPositionedReader {
            file: &self.file,
            pos: abs_offset,
            remaining: entry.compressed_size,
        };

        let reader: Box<dyn Read + Send> = match entry.encryption_type {
            EncryptionType::None => Box::new(bounded),
            EncryptionType::ChaCha20Poly1305 => {
                let subkey = derive_entry_key(&self.master_key, self.header.archive_salt, name);
                let cipher = ChaCha20Poly1305::new((&subkey).into());
                let nonce_prefix = Self::unpack_nonce(entry.nonce);
                let decryptor = DecryptorBE32::from_aead(cipher, (&nonce_prefix).into());

                Box::new(DecryptingReader {
                    inner: bounded,
                    decryptor: Some(decryptor),
                    entry_name: name.as_bytes().to_vec(),
                    remaining_ciphertext: entry.compressed_size,
                    plaintext_buf: Vec::new(),
                    buf_pos: 0,
                })
            }
        };

        Self::decompressor(reader, entry.compression_type)
    }

    /// Extracts the named entry's fully decoded contents into a new temporary file on disk, and
    /// returns its path. Useful for handing data to frameworks that expect a file path rather than
    /// an in-memory buffer.
    ///
    /// Data is streamed via [`AlpackReader::stream`] rather than buffered in memory first, so memory use
    /// stays bounded even for large entries. The temp file's extension is preserved from the entry's
    /// name, so consumers that infer the file type from extension (common in C-style asset loaders)
    /// behave correctly.
    ///
    /// The returned [`TempPath`] deletes the underlying file automatically when dropped,
    /// keep it alive for as long as the receiving framework needs the file to exist on the disk.
    ///
    /// ### Note:
    /// the temp file location is OS-dependent (`std::env::temp_dir()`). Some
    /// systems run periodic cleanup jobs that remove old files from this directory,
    /// if one runs while this file is still in use, it could be deleted out from
    /// under the caller. In practice this is a rare, edge-case risk, since these
    /// cleanup jobs typically only target files that have sat untouched for a long
    /// time (hours to days), well beyond the lifetime of a typical asset-loading call.
    ///
    /// # Errors
    /// Returns an error if no entry with this name exists, temp file creation fails, or the underlying
    /// stream read/decrypt/decompress fails partway through (in which case the partially-written temp
    /// file is cleaned up automatically).
    fn extract_to_temp_file(&self, name: &str) -> Result<TempPath, ReaderError> {
        let mut source = self.stream(name)?;

        let extension = Path::new(name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        let mut temp_file = Builder::new()
            .prefix("alpacka_")
            .suffix(&format!(".{extension}"))
            .tempfile()?;

        std::io::copy(&mut source, temp_file.as_file_mut())?;

        Ok(temp_file.into_temp_path())
    }

    fn list(&self, folder: &str, recursive: bool) -> Result<Vec<String>, ReaderError> {
        let mut results = Vec::new();

        for name in self.entries.keys() {
            let Some(rest) = Self::matches_folder(name, folder) else {
                continue;
            };

            if !recursive && rest.contains('/') {
                continue;
            }

            results.push(name.clone());
        }

        Ok(results)
    }
}

/// for debugging purposes, the Loose Asset Reader reads files inside your assets folder.
///
/// It should work much the same way as the [`AlpackReader`] in terms of paths, but will not include
/// any preprocessed content, so your engine should be made to expect that.
///
/// It will also log every time a file is accessed for debugging
pub struct LooseAssetReader {
    asset_root: PathBuf,
    access_log: Mutex<BufWriter<File>>,
    start_time: Instant,
}

impl LooseAssetReader {
    pub fn new(asset_root: String) -> Result<Self, ReaderError> {
        println!("Alpacka: emulating alpack file for debug.");

        let log_path = std::env::current_dir()?.join("alpacka/access_log.txt");

        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let log_file = File::create(&log_path)?;

        Ok(LooseAssetReader {
            asset_root: PathBuf::from(asset_root),
            access_log: Mutex::new(BufWriter::new(log_file)),
            start_time: Instant::now(),
        })
    }

    fn log_access(&self, name: &str, access_type: &str) {
        let elapsed = self.start_time.elapsed();
        if let Ok(mut writer) = self.access_log.lock() {
            let _ = writeln!(
                writer,
                "{:.3}\t{}\t{}",
                elapsed.as_secs_f64(),
                access_type,
                name
            );
        }
    }
}

impl AssetAccessor for LooseAssetReader {
    fn extract(&self, name: &str) -> Result<Vec<u8>, ReaderError> {
        self.log_access(name, "extract");
        Ok(std::fs::read(self.asset_root.join(name))?)
    }

    fn stream(&self, name: &str) -> Result<Box<dyn Read + Send + '_>, ReaderError> {
        self.log_access(name, "stream");
        let file = File::open(self.asset_root.join(name))?;
        Ok(Box::new(file))
    }

    fn extract_to_temp_file(&self, name: &str) -> Result<TempPath, ReaderError> {
        self.log_access(name, "extract_to_temp_file");

        let mut source = Box::new(File::open(self.asset_root.join(name))?);

        let extension = Path::new(name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");

        let mut temp_file = Builder::new()
            .prefix("alpacka_")
            .suffix(&format!(".{extension}"))
            .tempfile()?;

        std::io::copy(&mut source, temp_file.as_file_mut())?;

        Ok(temp_file.into_temp_path())
    }

    fn list(&self, folder: &str, recursive: bool) -> Result<Vec<String>, ReaderError> {
        self.log_access(folder, "list");

        let root = self.asset_root.join(folder);
        let mut stack = vec![root];
        let mut results = Vec::new();

        while let Some(dir) = stack.pop() {
            let read_dir = match std::fs::read_dir(&dir) {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(ReaderError::Io(e)),
            };

            for entry in read_dir {
                let entry = entry?;
                let path = entry.path();
                let is_dir = entry.file_type()?.is_dir();

                if is_dir {
                    if recursive {
                        stack.push(path);
                    }
                } else {
                    let relative = path
                        .strip_prefix(&self.asset_root)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    results.push(relative);
                }
            }
        }

        Ok(results)
    }
}

/// a lazy-reading adaptor over an entry's byte range in the archive
/// carries its own independent read position so any number of these
/// can run concurrently against the same `File` with no shared cursor
struct BoundedPositionedReader<'a> {
    file: &'a File,
    pos: u64,
    remaining: u64,
}

impl<'a> Read for BoundedPositionedReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let capacity = buf.len().min(self.remaining as usize);
        let n = self.file.read_at(self.pos, &mut buf[..capacity])?;
        self.pos += n as u64;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// A `read` adapter that decrypts ciphertext from `inner` in fixed-size chunks as bytes are requested,
/// rather than buffering the whole entry. `decryptor` becomes `None` once the final chunk has been
/// authenticated via `decrypt_last`, which naturally signals end-of-stream on subsequent `read` calls
/// without needing a separate "finish" flag.
struct DecryptingReader<R: Read> {
    inner: R,
    decryptor: Option<DecryptorBE32<ChaCha20Poly1305>>,
    entry_name: Vec<u8>,
    remaining_ciphertext: u64,
    plaintext_buf: Vec<u8>,
    buf_pos: usize,
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.buf_pos >= self.plaintext_buf.len() && self.decryptor.is_some() {
            let this_chunk_size = CIPHERTEXT_CHUNK_SIZE.min(self.remaining_ciphertext as usize);
            let mut raw = vec![0u8; this_chunk_size];
            self.inner.read_exact(&mut raw)?;
            self.remaining_ciphertext -= this_chunk_size as u64;

            let payload = Payload {
                msg: raw.as_slice(),
                aad: self.entry_name.as_slice(),
            };
            let is_last = self.remaining_ciphertext == 0;

            let plaintext = if is_last {
                let decryptor = self.decryptor.take().expect("checked Some above");
                decryptor.decrypt_last(payload)
            } else {
                self.decryptor
                    .as_mut()
                    .expect("checked Some above")
                    .decrypt_next(payload)
            }
            .map_err(|_| std::io::Error::other("chunk authentication filed"))?;

            self.plaintext_buf = plaintext;
            self.buf_pos = 0;
        }

        let available = &self.plaintext_buf[self.buf_pos..];
        let n = available.len().min(out.len());
        out[..n].copy_from_slice(&available[..n]);
        self.buf_pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{CHUNK_SIZE, CompressionType, EncryptionType};
    use aead_stream::EncryptorBE32;
    use lipsum::lipsum;
    use pretty_assertions::assert_eq;
    use rand::RngExt;
    use std::fs::read_to_string;
    use std::io::{BufWriter, Error, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::{fs, thread};
    use tempfile::env::temp_dir;
    use wincode::serialize_into;
    use xxhash_rust::xxh3::xxh3_64;

    const TEST_KEY: [u8; 32] = *b"testtesttesttesttesttesttesttest";
    const EMPTY: &[u8] = &[];

    fn encrypt_chunk_data(
        master_key: &[u8; 32],
        archive_salt: u64,
        name: &str,
        plaintext: &[u8],
    ) -> (Vec<u8>, u64) {
        let subkey = derive_entry_key(master_key, archive_salt, name);
        let cipher = ChaCha20Poly1305::new((&subkey).into());

        let nonce_prefix: [u8; 7] = rand::random();
        let mut encryptor = EncryptorBE32::from_aead(cipher, (&nonce_prefix).into());

        let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
        let plain_chunks: Vec<&[u8]> = plaintext.chunks(CHUNK_SIZE).collect();
        let (last, initial) = plain_chunks.split_last().unwrap_or((&EMPTY, &[]));

        for chunk in initial {
            let payload = Payload {
                msg: chunk,
                aad: name.as_bytes(),
            };
            ciphertext.extend_from_slice(
                &encryptor
                    .encrypt_next(payload)
                    .expect("encrypt_next failed"),
            );
        }
        let payload = Payload {
            msg: last,
            aad: name.as_bytes(),
        };
        ciphertext.extend_from_slice(
            &encryptor
                .encrypt_last(payload)
                .expect("encrypt_last failed"),
        );

        let mut buf8 = [0u8; 8];
        buf8[..7].copy_from_slice(&nonce_prefix);
        (ciphertext, u64::from_le_bytes(buf8))
    }

    fn compress(data: &[u8], compression_type: CompressionType) -> Vec<u8> {
        match compression_type {
            CompressionType::None => data.to_vec(),
            CompressionType::Zstd => zstd::encode_all(data, 3).expect("zstd encode failed"),
            CompressionType::Deflate => {
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(data).expect("deflate write failed");
                encoder.finish().expect("deflate finish failed")
            }
            CompressionType::Lz4 => {
                let mut encoder = lz4::EncoderBuilder::new()
                    .build(Vec::new())
                    .expect("lz4 build failed");
                encoder.write_all(data).expect("lz4 write failed");
                let (compressed, result) = encoder.finish();
                result.expect("lz4 finish failed");
                compressed
            }
        }
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = temp_dir().join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn build_test_archive(
        header: &mut Header,
        name: &str,
        first_entry_words: Option<usize>,
        first_entry_compression: Option<CompressionType>,
        first_entry_encrypted: bool,
    ) -> Result<PathBuf, Error> {
        let temp_dir = temp_dir().join(name);
        let mut writer = BufWriter::new(File::create(&temp_dir)?);
        let mut names: Vec<String> = Vec::new();
        let mut data: Vec<u8> = Vec::new();
        let mut entries: Vec<u8> = Vec::new();

        let mut rng = rand::rng();

        header.data_offset = HEADER_SIZE as u64;
        header.archive_salt = rand::random();

        let mut current_name_table_offset = 0;
        let mut data_length = 0;
        for i in 0..header.entry_count {
            let name = format!("fake/file.{}", i);

            let (content, compression_type) = if i == 0 {
                (
                    lipsum(first_entry_words.unwrap_or(3)),
                    first_entry_compression.unwrap_or(CompressionType::None),
                )
            } else {
                (lipsum(rng.random_range(0..100)), CompressionType::None)
            };

            let original_bytes = content.as_bytes();
            let compressed_bytes = compress(original_bytes, compression_type);

            let (stored_bytes, encryption_type, nonce) = if i == 0 && first_entry_encrypted {
                let (ciphertext, nonce) =
                    encrypt_chunk_data(&TEST_KEY, header.archive_salt, &name, &compressed_bytes);
                (ciphertext, EncryptionType::ChaCha20Poly1305, nonce)
            } else {
                (compressed_bytes, EncryptionType::None, 0)
            };

            let entry = Entry {
                custom1: 0,
                custom2: 0,
                data_offset: data_length,
                compressed_size: stored_bytes.len() as u64,
                original_size: original_bytes.len() as u64,
                compression_type,
                name_offset: current_name_table_offset as u64,
                name_length: name.len() as u64,
                encryption_type,
                nonce,
                reserved: 0,
            };

            let mut entry_buf: Vec<u8> = Vec::with_capacity(ENTRY_SIZE);
            serialize_into(&mut entry_buf, &entry).expect("failed to serialise entry");

            current_name_table_offset += name.len();
            data_length += stored_bytes.len() as u64;
            names.push(name);
            data.extend_from_slice(&stored_bytes);
            entries.extend_from_slice(&entry_buf);
        }

        header.string_table_offset = header.data_offset + data_length;

        header.index_offset = header.string_table_offset + current_name_table_offset as u64;
        header.index_checksum = xxh3_64(entries.as_slice());

        serialize_into(&mut writer, &*header).expect("failed to serialise header");
        writer.write_all(data.as_slice())?;
        for name in names.iter() {
            writer.write_all(name.as_bytes())?;
        }
        writer
            .write_all(entries.as_slice())
            .expect("failed to write entries");

        writer.flush()?;
        drop(writer);

        Ok(temp_dir)
    }

    fn build_simple_archive(header: &mut Header, name: &str) -> Result<PathBuf, Error> {
        build_test_archive(header, name, None, None, false)
    }

    fn build_archive_with_names(
        header: &mut Header,
        filename: &str,
        names: &[&str],
    ) -> Result<PathBuf, Error> {
        let tempt_dir = temp_dir().join(filename);
        let mut writer = BufWriter::new(File::create(&tempt_dir)?);
        let mut data: Vec<u8> = Vec::new();
        let mut entries: Vec<u8> = Vec::new();

        header.data_offset = HEADER_SIZE as u64;
        header.archive_salt = rand::random();
        header.entry_count = names.len() as u64;

        let mut current_name_table_offset = 0u64;
        for name in names {
            let content = b"x";

            let entry = Entry {
                custom1: 0,
                custom2: 0,
                data_offset: data.len() as u64,
                compressed_size: content.len() as u64,
                original_size: content.len() as u64,
                compression_type: CompressionType::None,
                name_offset: current_name_table_offset,
                name_length: name.len() as u64,
                encryption_type: EncryptionType::None,
                nonce: 0,
                reserved: 0,
            };

            let mut entry_buf: Vec<u8> = Vec::with_capacity(ENTRY_SIZE);
            serialize_into(&mut entry_buf, &entry).expect("entry serialisation should not fail");

            current_name_table_offset += name.len() as u64;
            data.extend_from_slice(content);
            entries.extend_from_slice(&entry_buf);
        }

        header.string_table_offset = header.data_offset + data.len() as u64;
        header.index_offset = header.string_table_offset + current_name_table_offset;
        header.index_checksum = xxh3_64(entries.as_slice());

        serialize_into(&mut writer, &*header).expect("header serialisation should not fail");
        writer.write_all(data.as_slice())?;
        for name in names {
            writer.write_all(name.as_bytes())?;
        }
        writer
            .write_all(entries.as_slice())
            .expect("entry writing should not fail");

        writer.flush()?;
        drop(writer);

        Ok(tempt_dir)
    }

    fn default_header(entry_count: u64) -> Header {
        Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            index_checksum: 0,
            archive_salt: 0,
            reserved: 0,
        }
    }

    #[test]
    fn reader_constructor_reads_correctly() {
        let entries: u64 = 1000;

        let mut header = default_header(entries);
        let path = build_simple_archive(&mut header, "test.alpack").unwrap();

        let reader = AlpackReader::new(path.as_path(), TEST_KEY).unwrap();

        assert_eq!(reader.header.magic, MAGIC_NUMBER);
        assert_eq!(reader.header.version, VERSION);
        assert_eq!(reader.header.entry_count, entries);
        assert_eq!(reader.entries.len(), entries as usize);
    }

    #[test]
    fn reader_constructor_fails_bad_magic() {
        let mut magic_fail_header = Header {
            magic: 0x6C696166, //"fail"
            version: VERSION,
            entry_count: 10,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            index_checksum: 0,
            archive_salt: 0,
            reserved: 0,
        };
        let magic_fail_path = build_simple_archive(&mut magic_fail_header, "fail.alpack").unwrap();

        let result = AlpackReader::new(magic_fail_path.as_path(), TEST_KEY);

        assert!(matches!(result, Err(ReaderError::BadMagic(found)) if found == 0x6C696166));
    }

    #[test]
    fn reader_constructor_fails_future_version() {
        let mut version_fail_header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION + 1,
            entry_count: 10,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            index_checksum: 0,
            archive_salt: 0,
            reserved: 0,
        };
        let version_fail_path =
            build_simple_archive(&mut version_fail_header, "future.alpack").unwrap();

        let result = AlpackReader::new(version_fail_path.as_path(), TEST_KEY);

        assert!(matches!(result, Err(ReaderError::UnsupportedVersion(v)) if v == VERSION + 1));
    }

    #[test]
    fn reader_constructor_fails_missing_file() {
        let path = Path::new("/this/does/not/exist.alpack");

        assert!(AlpackReader::new(path, TEST_KEY).is_err());
    }

    #[test]
    fn reader_constructor_fails_truncated_header() {
        let path = temp_dir().join("truncated.alpack");

        fs::write(&path, [0u8; 10]).unwrap();

        assert!(AlpackReader::new(&path, TEST_KEY).is_err());
    }

    #[test]
    fn reader_constructor_fails_invalid_utf8_name() {
        let mut header = default_header(1);
        let path = build_simple_archive(&mut header, "bad_utf8.alpack").unwrap();

        let mut bytes = fs::read(&path).unwrap();
        bytes[header.string_table_offset as usize] = 0x80; // invalid UTF-8 lead byte
        fs::write(&path, bytes).unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        assert!(reader.entries.is_empty())
    }

    #[test]
    fn extract_extracts_none_successfully() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "none_compression.alpack",
            Some(word_count),
            Some(CompressionType::None),
            false,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_extracts_zstd_successfully() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "zstd_compression.alpack",
            Some(word_count),
            Some(CompressionType::Zstd),
            false,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_extracts_deflate_successfully() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "deflate_compression.alpack",
            Some(word_count),
            Some(CompressionType::Deflate),
            false,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_extracts_lz4_successfully() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "lz4_compression.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            false,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_none_successfully() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "none_compression_stream.alpack",
            Some(word_count),
            Some(CompressionType::None),
            false,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_zstd_successfully() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "zstd_compression_stream.alpack",
            Some(word_count),
            Some(CompressionType::Zstd),
            false,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_deflate_successfully() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "deflate_compression_stream.alpack",
            Some(word_count),
            Some(CompressionType::Deflate),
            false,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_lz4_successfully() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "lz4_compression_stream.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            false,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_works_across_threads() {
        let word_count: usize = 30;
        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "stream_threaded.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            false,
        )
        .unwrap();

        let reader = Arc::new(AlpackReader::new(&path, TEST_KEY).unwrap());
        let reader_clone = Arc::clone(&reader);

        let handle = thread::spawn(move || {
            let mut stream = reader_clone.stream("fake/file.0").unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            String::from_utf8(bytes).unwrap()
        });

        let text = handle.join().expect("stream thread panicked");
        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_lz4_chacha20poly1305_successfully() {
        let word_count: usize = 300000;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "lz4_chacha20poly1305_stream.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            true,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn decryption_stream_works_across_threads() {
        let word_count: usize = 30;
        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "stream_threaded_encrypted.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            true,
        )
        .unwrap();

        let reader = Arc::new(AlpackReader::new(&path, TEST_KEY).unwrap());
        let reader_clone = Arc::clone(&reader);

        let handle = thread::spawn(move || {
            let mut stream = reader_clone.stream("fake/file.0").unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            String::from_utf8(bytes).unwrap()
        });

        let text = handle.join().expect("stream thread panicked");
        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_extracts_encrypted_lz4_successfully() {
        let word_count: usize = 300000;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "lz4_encryption.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            true,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_fails_on_tampered_ciphertext() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "tampered_encryption.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            true,
        )
        .unwrap();

        let mut bytes = fs::read(&path).unwrap();
        let flip_offset = header.data_offset as usize;
        bytes[flip_offset] ^= 0xff;
        fs::write(&path, bytes).unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        assert!(reader.extract("fake/file.0").is_err());
    }

    #[test]
    fn stream_fails_on_tampered_ciphertext() {
        let word_count: usize = 30;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "tampered_stream_encryption.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            true,
        )
        .unwrap();

        let mut bytes = fs::read(&path).unwrap();
        let flip_offset = header.data_offset as usize;
        bytes[flip_offset] ^= 0xff;
        fs::write(&path, bytes).unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        assert!(stream.read_to_end(&mut bytes).is_err());
    }

    #[test]
    fn extract_extracts_encrypted_lz4_short_data_successfully() {
        let word_count: usize = 1; // less than 16 bytes?

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "lz4_short_encryption.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            true,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_to_temp_file_extracts_encrypted_lz4_short_data_successfully() {
        let word_count: usize = 100;

        let mut header = default_header(1);
        let path = build_test_archive(
            &mut header,
            "lz4_temp_extract.alpack",
            Some(word_count),
            Some(CompressionType::Lz4),
            true,
        )
        .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let temp_path = reader.extract_to_temp_file("fake/file.0").unwrap();
        let text = read_to_string(temp_path).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn loose_asset_loader_extracts() {
        let root = scratch_dir("reader_root_loose_extract");
        let file_path = root.join("extract.txt");
        fs::write(&file_path, b"loose extract").unwrap();

        let reader = LooseAssetReader::new(root.to_str().unwrap().to_string()).unwrap();

        assert_eq!(reader.extract("extract.txt").unwrap(), b"loose extract")
    }

    #[test]
    fn loose_asset_loader_streams() {
        let root = scratch_dir("reader_root_loose_stream");
        let file_path = root.join("stream.txt");
        fs::write(&file_path, b"loose stream").unwrap();

        let reader = LooseAssetReader::new(root.to_str().unwrap().to_string()).unwrap();
        let mut content_buf = Vec::new();
        reader
            .stream("stream.txt")
            .unwrap()
            .read_to_end(&mut content_buf)
            .unwrap();

        assert_eq!(content_buf, b"loose stream")
    }

    #[test]
    fn loose_asset_loader_extracts_to_temp_file() {
        let root = scratch_dir("reader_root_loose_temp_file");
        let file_path = root.join("tempfile.txt");
        fs::write(&file_path, b"loose tempfile").unwrap();

        let reader = LooseAssetReader::new(root.to_str().unwrap().to_string()).unwrap();
        let mut content_buf = Vec::new();
        let mut file = File::open(reader.extract_to_temp_file("tempfile.txt").unwrap()).unwrap();
        file.read_to_end(&mut content_buf).unwrap();

        assert_eq!(content_buf, b"loose tempfile")
    }

    #[test]
    fn list_root_recursive_returns_everything() {
        let names = ["a.txt", "dir/b.txt", "dir/sub/c.txt"];
        let mut header = default_header(names.len() as u64);
        let path =
            build_archive_with_names(&mut header, "list_root_recursive.alpack", &names).unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut results = reader.list(ROOT, true).unwrap();
        results.sort();

        assert_eq!(results, vec!["a.txt", "dir/b.txt", "dir/sub/c.txt"])
    }

    #[test]
    fn list_root_non_recursive_returns_only_direct_children() {
        let names = ["a.txt", "dir/b.txt", "dir/sub/c.txt"];
        let mut header = default_header(names.len() as u64);
        let path =
            build_archive_with_names(&mut header, "list_root_nonrecursive.alpack", &names).unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut results = reader.list(ROOT, false).unwrap();
        results.sort();

        assert_eq!(results, vec!["a.txt"])
    }

    #[test]
    fn list_subfolder_recursive() {
        let names = ["a.txt", "dir/b.txt", "dir/sub/c.txt", "other/d.txt"];
        let mut header = default_header(names.len() as u64);
        let path = build_archive_with_names(&mut header, "list_subfolder_recursive.alpack", &names)
            .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut results = reader.list("dir", true).unwrap();
        results.sort();

        assert_eq!(results, vec!["dir/b.txt", "dir/sub/c.txt"])
    }

    #[test]
    fn list_subfolder_non_recursive() {
        let names = ["a.txt", "dir/b.txt", "dir/sub/c.txt", "other/d.txt"];
        let mut header = default_header(names.len() as u64);
        let path =
            build_archive_with_names(&mut header, "list_subfolder_nonrecursive.alpack", &names)
                .unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut results = reader.list("dir", false).unwrap();
        results.sort();

        assert_eq!(results, vec!["dir/b.txt"])
    }

    #[test]
    fn list_nonexistent_folder_returns_empty_not_error() {
        let names = ["a.txt"];
        let mut header = default_header(names.len() as u64);
        let path =
            build_archive_with_names(&mut header, "list_nonexistant.alpack", &names).unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut results = reader.list("nah", false).unwrap();
        results.sort();

        assert!(results.is_empty())
    }

    #[test]
    fn list_with_extension_filters_correctly() {
        let names = ["a.txt", "b.md", "dir/c.txt", "dir/d.md"];
        let mut header = default_header(names.len() as u64);
        let path =
            build_archive_with_names(&mut header, "list_with_extension.alpack", &names).unwrap();

        let reader = AlpackReader::new(&path, TEST_KEY).unwrap();
        let mut results = reader.list_with_extension(ROOT, "txt", true).unwrap();
        results.sort();
        results.sort();

        assert_eq!(results, vec!["a.txt", "dir/c.txt"])
    }

    #[test]
    fn loose_list_root_recursive_returns_everything() {
        let root = scratch_dir("loose_list_root_recursive");
        fs::write(root.join("a.txt"), b"x").unwrap();
        fs::create_dir_all(root.join("dir/sub")).unwrap();
        fs::write(root.join("dir/b.txt"), b"x").unwrap();
        fs::write(root.join("dir/sub/c.txt"), b"x").unwrap();

        let reader = LooseAssetReader::new(root.to_str().unwrap().to_string()).unwrap();
        let mut results = reader.list(ROOT, true).unwrap();
        results.sort();

        assert_eq!(results, vec!["a.txt", "dir/b.txt", "dir/sub/c.txt"])
    }

    #[test]
    fn loose_list_root_non_recursive_skips_nested() {
        let root = scratch_dir("loose_list_root_nonrecursive");
        fs::write(root.join("a.txt"), b"x").unwrap();
        fs::create_dir_all(root.join("dir")).unwrap();
        fs::write(root.join("dir/b.txt"), b"x").unwrap();

        let reader = LooseAssetReader::new(root.to_str().unwrap().to_string()).unwrap();
        let mut results = reader.list(ROOT, false).unwrap();
        results.sort();

        assert_eq!(results, vec!["a.txt"])
    }

    #[test]
    fn loose_list_subfolder_recursive() {
        let root = scratch_dir("loose_list_subfolder");
        fs::write(root.join("a.txt"), b"x").unwrap();
        fs::create_dir_all(root.join("dir/sub")).unwrap();
        fs::write(root.join("dir/b.txt"), b"x").unwrap();
        fs::write(root.join("dir/sub/c.txt"), b"x").unwrap();
        fs::create_dir_all(root.join("other")).unwrap();
        fs::write(root.join("other/d.txt"), b"x").unwrap();

        let reader = LooseAssetReader::new(root.to_str().unwrap().to_string()).unwrap();
        let mut results = reader.list("dir", true).unwrap();
        results.sort();

        assert_eq!(results, vec!["dir/b.txt", "dir/sub/c.txt"])
    }

    #[test]
    fn loose_list_nonexistent_folder_returns_empty() {
        let root = scratch_dir("loose_list_nonexistant");

        let reader = LooseAssetReader::new(root.to_str().unwrap().to_string()).unwrap();
        let result = reader.list("nah", true).unwrap();

        assert!(result.is_empty())
    }

    #[test]
    fn loose_list_sith_extension_filters_correctly() {
        let root = scratch_dir("loose_list_with_extension");
        fs::write(root.join("a.txt"), b"x").unwrap();
        fs::write(root.join("b.md"), b"x").unwrap();
        fs::create_dir_all(root.join("dir")).unwrap();
        fs::write(root.join("dir/c.txt"), b"x").unwrap();
        fs::write(root.join("dir/d.md"), b"x").unwrap();

        let reader = LooseAssetReader::new(root.to_str().unwrap().to_string()).unwrap();
        let mut results = reader.list_with_extension(ROOT, "txt", true).unwrap();
        results.sort();

        assert_eq!(results, vec!["a.txt", "dir/c.txt"])
    }
}
