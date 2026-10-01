//! Writes alpacka archives
//!
//! refer to [`format`] for more details on the format, or further documentation in this module for
//! how to use [`AlpackWriter`].

use crate::format::{
    CHUNK_SIZE, CompressionType, ENTRY_SIZE, EncryptionType, Entry, HEADER_SIZE, Header,
    derive_entry_key,
};
use crate::format::{MAGIC_NUMBER, VERSION};
use crate::meta_file::{Meta, load_or_default};
use aead_stream::EncryptorBE32;
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use std::fmt::Formatter;
use std::fs::File;
use std::io;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use xxhash_rust::xxh3::xxh3_64;

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("{file_path} is not under asset root: {root}")]
    NotInRoot { root: PathBuf, file_path: PathBuf },

    #[error(transparent)]
    SerialisationError(#[from] wincode::WriteError),

    #[error("{compressor} compressor {failure_point} has failed for {name} : {error}")]
    CompressionFailure {
        compressor: String,
        name: String,
        failure_point: String,
        #[source]
        error: io::Error,
    },

    #[error("ChaCha20-Poly1305 encryption failed for {name}")]
    EncryptionFailure {
        name: String,
        #[source]
        error: io::Error,
    },

    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug)]
pub struct AlpackWriter {
    output_path: PathBuf,
    asset_root: PathBuf,
    master_key: [u8; 32],
    archive_salt: u64,
    pending: Vec<PendingEntry>,
    running_name_offset: u64,
}

#[derive(Debug)]
struct PendingEntry {
    name: String,
    source_path: PathBuf,
    compression: CompressionType,
    encrypt: bool,
    name_offset: u64,
    custom1: u64,
    custom2: u64,
}

impl AlpackWriter {
    pub fn new(output_path: &Path, asset_root: &Path, master_key: [u8; 32]) -> Self {
        AlpackWriter {
            output_path: output_path.to_path_buf(),
            asset_root: asset_root.to_path_buf(),
            master_key,
            archive_salt: rand::random(),
            pending: Vec::new(),
            running_name_offset: 0,
        }
    }

    pub fn add(
        &mut self,
        path: &Path,
        compression: CompressionType,
        encrypt: bool,
        custom1: u64,
        custom2: u64,
    ) -> Result<(), WriterError> {
        let relative = path
            .strip_prefix(&self.asset_root)
            .map_err(|_| WriterError::NotInRoot {
                root: self.asset_root.to_path_buf(),
                file_path: path.to_path_buf(),
            })?;

        // windows uses backslashes for paths, which is irregular to most operating systems and
        // not as ergonomic as forward splashes so they get converted here
        let name = relative.to_string_lossy().replace('\\', "/");

        let meta_path = Self::meta_path_for(path);
        let meta: Option<Meta> = if meta_path.exists() {
            Some(load_or_default(&meta_path))
        } else {
            None
        };

        let name_offset = self.running_name_offset;
        self.running_name_offset += name.len() as u64;

        let (resolved_compression, resolved_encrypt) = match &meta {
            Some(m) => {
                let compression = m.get_compression_type().unwrap_or_else(|| compression);
                (compression, m.pack.encrypted)
            }
            None => (compression, encrypt),
        };

        self.pending.push(PendingEntry {
            name,
            source_path: path.to_path_buf(),
            compression: resolved_compression,
            encrypt: resolved_encrypt,
            name_offset,
            custom1,
            custom2,
        });

        Ok(())
    }

    pub fn finalise(self) -> Result<(), WriterError> {
        let mut file = File::create(&self.output_path)?;

        // step 1: reserve space for the header, we don't yet know all the necessary offsets nor have
        // we gotten the checksum yet so space is only reserved for now
        file.write_all(&[0u8; HEADER_SIZE])?;

        // step 2: stream every entry's data in order immediately after the header
        // `running_data_offset` is relative to data_offset which is fixed at HEADER_SIZE
        let mut finished_entries: Vec<Entry> = Vec::with_capacity(self.pending.len());
        let mut running_data_offset: u64 = 0;

        for pending in &self.pending {
            let source = File::open(&pending.source_path)?;

            let (original_size, compressed_size, nonce) = self.write_entry_data(
                &mut file,
                source,
                pending.compression,
                pending.encrypt,
                &pending.name,
            )?;

            finished_entries.push(Entry {
                custom1: pending.custom1,
                custom2: pending.custom2,
                data_offset: running_data_offset,
                compressed_size,
                original_size,
                compression_type: pending.compression,
                name_offset: pending.name_offset,
                name_length: pending.name.len() as u64,
                encryption_type: if pending.encrypt {
                    EncryptionType::ChaCha20Poly1305
                } else {
                    EncryptionType::None
                },
                nonce,
                reserved: 0,
            });

            running_data_offset += compressed_size;
        }

        // step 3: string table. current file position (absolute) is where it starts
        let string_table_offset = file.stream_position()?;

        for pending in &self.pending {
            file.write_all(pending.name.as_bytes())?;
        }

        // step 4: index section. Serialize every Entry into one buffer, checksum the buffer, then write
        let index_offset = file.stream_position()?;

        let mut entries_buf = Vec::with_capacity(finished_entries.len() * ENTRY_SIZE);
        for entry in &finished_entries {
            wincode::serialize_into(&mut entries_buf, entry)?;
        }
        let index_checksum = xxh3_64(&entries_buf);

        file.write_all(&entries_buf)?;

        // step 5: go back and replace the placeholder header with an actual header.
        let header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: finished_entries.len() as u64,
            data_offset: HEADER_SIZE as u64,
            string_table_offset,
            index_offset,
            index_checksum,
            archive_salt: self.archive_salt,
            reserved: 0,
        };

        let mut header_buf = Vec::with_capacity(HEADER_SIZE);

        wincode::serialize_into(&mut header_buf, &header)?;

        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header_buf)?;

        file.flush()?;

        Ok(())
    }

    fn meta_path_for(path: &Path) -> PathBuf {
        let mut os_string = path.as_os_str().to_os_string();
        os_string.push(".meta.toml");
        PathBuf::from(os_string)
    }

    fn write_entry_data(
        &self,
        file: &mut File,
        mut source: impl Read,
        compression: CompressionType,
        encrypt: bool,
        name: &str,
    ) -> Result<(u64, u64, u64), WriterError> {
        let counting = CountingWriter {
            inner: &mut *file,
            count: 0,
        };

        let (encrypt_layer, nonce) = if encrypt {
            let subkey = derive_entry_key(&self.master_key, self.archive_salt, name);
            let cipher = ChaCha20Poly1305::new((&subkey).into());
            let nonce_prefix: [u8; 7] = rand::random();
            let encryptor = EncryptorBE32::from_aead(cipher, (&nonce_prefix).into());

            let chunked = ChunkedEncryptWriter {
                inner: counting,
                encryptor,
                entry_name: name.as_bytes().to_vec(),
                buf: Vec::with_capacity(CHUNK_SIZE),
            };

            (
                EncryptLayer::Encrypted(chunked),
                Self::pack_nonce(nonce_prefix),
            )
        } else {
            (EncryptLayer::Plain(counting), 0)
        };

        let (original_size, compressed_size) = match compression {
            CompressionType::None => {
                let mut layer = encrypt_layer;
                let original_size = io::copy(&mut source, &mut layer)
                    .map_err(|e| Self::classify_stream_error(e, name))?;
                let compressed_size = layer
                    .finish()
                    .map_err(|e| Self::classify_stream_error(e, name))?;
                (original_size, compressed_size)
            }
            CompressionType::Zstd => {
                let mut encoder = zstd::Encoder::new(encrypt_layer, 3)
                    .map_err(Self::compression_error("Zstd", "init", name))?;
                let original_size = io::copy(&mut source, &mut encoder)
                    .map_err(Self::compression_error("Zstd", "compression", name))?;
                let layer = encoder
                    .finish()
                    .map_err(Self::compression_error("Zstd", "finish", name))?;
                let compressed_size = layer
                    .finish()
                    .map_err(|e| Self::classify_stream_error(e, name))?;

                (original_size, compressed_size)
            }
            CompressionType::Deflate => {
                let mut encoder = flate2::write::DeflateEncoder::new(
                    encrypt_layer,
                    flate2::Compression::default(),
                );
                let original_size = io::copy(&mut source, &mut encoder)
                    .map_err(Self::compression_error("Deflate", "compression", name))?;
                let layer = encoder
                    .finish()
                    .map_err(Self::compression_error("Deflate", "finish", name))?;
                let compressed_size = layer
                    .finish()
                    .map_err(|e| Self::classify_stream_error(e, name))?;

                (original_size, compressed_size)
            }
            CompressionType::Lz4 => {
                let mut encoder = lz4::EncoderBuilder::new()
                    .build(encrypt_layer)
                    .map_err(Self::compression_error("LZ4", "init", name))?;
                let original_size = io::copy(&mut source, &mut encoder)
                    .map_err(Self::compression_error("LZ4", "compression", name))?;
                let (layer, result) = encoder.finish();
                result.map_err(Self::compression_error("LZ4", "finish", name))?;
                let compressed_size = layer
                    .finish()
                    .map_err(|e| Self::classify_stream_error(e, name))?;

                (original_size, compressed_size)
            }
        };

        Ok((original_size, compressed_size, nonce))
    }

    fn pack_nonce(prefix: [u8; 7]) -> u64 {
        let mut buf8 = [0u8; 8];
        buf8[..7].copy_from_slice(&prefix);
        u64::from_le_bytes(buf8)
    }

    fn compression_error(
        compressor: &str,
        failure_point: &str,
        name: &str,
    ) -> impl FnOnce(io::Error) -> WriterError {
        move |error: io::Error| {
            if error
                .get_ref()
                .is_some_and(|inner| inner.is::<ChunkEncryptionFailed>())
            {
                WriterError::EncryptionFailure {
                    name: name.to_string(),
                    error,
                }
            } else {
                WriterError::CompressionFailure {
                    compressor: compressor.to_string(),
                    failure_point: failure_point.to_string(),
                    name: name.to_string(),
                    error,
                }
            }
        }
    }

    fn classify_stream_error(error: io::Error, name: &str) -> WriterError {
        let is_encryption_failure = error
            .get_ref()
            .is_some_and(|inner| inner.is::<ChunkEncryptionFailed>());

        if is_encryption_failure {
            WriterError::EncryptionFailure {
                name: name.to_string(),
                error,
            }
        } else {
            WriterError::Io(error)
        }
    }
}

/// Counts bytes written to `inner`, so callers can learn the final on-disk size regardless of what's
/// writing through it.
struct CountingWriter<W: Write> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

///Internal marker embedded in an `io::Error` when chunk encryption fails inside [`ChunkedEncryptWriter`].
/// lets callers distinguish between an encryption failure and any other `io::Error` that might surface in the
/// `write` chain since nothing using `Write::write`/`flush` can directly return a [`WriterError`]
#[derive(Debug)]
struct ChunkEncryptionFailed;

impl std::fmt::Display for ChunkEncryptionFailed {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "chunk encryption failed")
    }
}

impl std::error::Error for ChunkEncryptionFailed {}

/// Buffers incoming plaintext up to `CHUNK_SIZE`, encrypting and forwarding full chunks as they fill.
/// `finish()` must be called explicitly once writing is done, to flush and authenticate whatever's
/// left in the buffer as the final chunk (`encrypt_last`)
struct ChunkedEncryptWriter<W: Write> {
    inner: W,
    encryptor: EncryptorBE32<ChaCha20Poly1305>,
    entry_name: Vec<u8>,
    buf: Vec<u8>,
}

impl<W: Write> Write for ChunkedEncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);

        while self.buf.len() >= CHUNK_SIZE {
            let chunk: Vec<u8> = self.buf.drain(..CHUNK_SIZE).collect();
            let payload = Payload {
                msg: &chunk,
                aad: &self.entry_name,
            };
            let ciphertext = self
                .encryptor
                .encrypt_next(payload)
                .map_err(|_| io::Error::other(ChunkEncryptionFailed))?;
            self.inner.write_all(&ciphertext)?;
        }

        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write> ChunkedEncryptWriter<W> {
    fn finish(mut self) -> io::Result<W> {
        let payload = Payload {
            msg: &self.buf,
            aad: &self.entry_name,
        };
        let ciphertext = self
            .encryptor
            .encrypt_last(payload)
            .map_err(|_| io::Error::other(ChunkEncryptionFailed))?;
        self.inner.write_all(&ciphertext)?;
        Ok(self.inner)
    }
}

enum EncryptLayer<W: Write> {
    Plain(CountingWriter<W>),
    Encrypted(ChunkedEncryptWriter<CountingWriter<W>>),
}

impl<W: Write> Write for EncryptLayer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            EncryptLayer::Plain(w) => w.write(buf),
            EncryptLayer::Encrypted(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            EncryptLayer::Plain(w) => w.flush(),
            EncryptLayer::Encrypted(w) => w.flush(),
        }
    }
}

impl<W: Write> EncryptLayer<W> {
    /// Finalizes this layer (calling `encrypt_last` if encrypted) and returns the final byte count.
    fn finish(self) -> io::Result<u64> {
        match self {
            EncryptLayer::Plain(w) => Ok(w.count),
            EncryptLayer::Encrypted(w) => {
                let counting = w.finish()?;
                Ok(counting.count)
            }
        }
    }
}

#[cfg(feature = "reader")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::AlpackReader;
    use lipsum::lipsum;
    use pretty_assertions::assert_eq;
    use std::fs;
    use tempfile::env::temp_dir;

    const TEST_KEY: [u8; 32] = *b"testtesttesttesttesttesttesttest";

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = temp_dir().join(name);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn round_trip_single_file_plain() {
        let root = scratch_dir("writer_plain");
        let file_path = root.join("hello.txt");
        fs::write(&file_path, b"Hello, World!").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::None, false, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = reader.extract("hello.txt").unwrap();
        assert_eq!(data, b"Hello, World!")
    }

    #[test]
    fn round_trip_single_file_encrypted() {
        let root = scratch_dir("writer_encrypted");
        let file_path = root.join("hello.txt");
        fs::write(&file_path, b"Hello, World!").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::None, true, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = reader.extract("hello.txt").unwrap();
        assert_eq!(data, b"Hello, World!")
    }

    #[test]
    fn round_trip_single_file_encrypted_deflate() {
        let root = scratch_dir("writer_encrypted_deflate");
        let file_path = root.join("hello.txt");
        fs::write(&file_path, b"Hello, World!").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::Deflate, true, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = reader.extract("hello.txt").unwrap();
        assert_eq!(data, b"Hello, World!")
    }

    #[test]
    fn round_trip_single_file_plain_deflate() {
        let root = scratch_dir("writer_plain_deflate");
        let file_path = root.join("hello.txt");
        fs::write(&file_path, b"Hello, World!").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::Deflate, false, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = reader.extract("hello.txt").unwrap();
        assert_eq!(data, b"Hello, World!")
    }

    #[test]
    fn round_trip_single_file_encrypted_zstd() {
        let root = scratch_dir("writer_encrypted_zstd");
        let file_path = root.join("hello.txt");
        fs::write(&file_path, b"Hello, World!").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::Zstd, true, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = reader.extract("hello.txt").unwrap();
        assert_eq!(data, b"Hello, World!")
    }

    #[test]
    fn round_trip_single_file_plain_zstd() {
        let root = scratch_dir("writer_plain_zstd");
        let file_path = root.join("hello.txt");
        fs::write(&file_path, b"Hello, World!").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::Zstd, true, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = reader.extract("hello.txt").unwrap();
        assert_eq!(data, b"Hello, World!")
    }

    #[test]
    fn round_trip_single_file_encrypted_lz4() {
        let root = scratch_dir("writer_encrypted_lz4");
        let file_path = root.join("hello.txt");
        fs::write(&file_path, b"Hello, World!").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::Lz4, true, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = reader.extract("hello.txt").unwrap();
        assert_eq!(data, b"Hello, World!")
    }

    #[test]
    fn round_trip_single_file_plain_lz4() {
        let root = scratch_dir("writer_plain_lz4");
        let file_path = root.join("hello.txt");
        fs::write(&file_path, b"Hello, World!").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::Lz4, false, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = reader.extract("hello.txt").unwrap();
        assert_eq!(data, b"Hello, World!")
    }

    #[test]
    fn round_trip_single_file_large() {
        let root = scratch_dir("writer_large");
        let file_path = root.join("hello.txt");
        let content = lipsum(300000);
        fs::write(&file_path, &content).unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::Lz4, true, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = String::from_utf8(reader.extract("hello.txt").unwrap()).unwrap();
        assert_eq!(data, content)
    }

    #[test]
    fn round_trip_single_file_meta() {
        let root = scratch_dir("writer_meta");
        let file_path = root.join("hello.txt");
        let content = lipsum(30);
        fs::write(&file_path, &content).unwrap();

        let meta_file_path = root.join("hello.txt.meta.toml");
        let meta_content = r#"[Pack]
        Compression = "deflate"
        Encrypted = false"#;

        fs::write(&meta_file_path, meta_content).unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        writer
            .add(&file_path, CompressionType::Lz4, true, 0, 0)
            .unwrap();
        writer.finalise().unwrap();

        let reader = AlpackReader::open(&archive_path, TEST_KEY).unwrap();
        let data = String::from_utf8(reader.extract("hello.txt").unwrap()).unwrap();
        assert_eq!(data, content)
    }

    #[test]
    fn add_fails_when_path_not_under_root() {
        let root = scratch_dir("writer_not_in_root");
        let outside = temp_dir().join("definitely_not_in_root.txt");
        fs::write(&outside, b"x").unwrap();

        let archive_path = root.join("archive.alpack");
        let mut writer = AlpackWriter::new(&archive_path, &root, TEST_KEY);
        let result = writer.add(&outside, CompressionType::None, false, 0, 0);

        assert!(matches!(result, Err(WriterError::NotInRoot { .. })))
    }
}
