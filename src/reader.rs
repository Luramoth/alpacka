use crate::format::{CompressionType, Entry, Header, ENTRY_SIZE, HEADER_SIZE, MAGIC_NUMBER, MAX_NAME_LENGTH, VERSION};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Cursor};
use std::path::Path;
use std::string::String;
use positioned_io::ReadAt;

pub struct Reader{
    pub header: Header,
    file: File,
    entries: HashMap<String, Entry>
}

impl Reader {
    /// Creates a new Alpack reader, catalogs all the entries of the archive to be referenced later
    pub fn new(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("could not open {}: {}", path.to_str().unwrap().to_string(), e))?;


        let mut reader = BufReader::new(&file);


        let mut header_buf = [0u8; HEADER_SIZE];

        if reader.read_exact(&mut header_buf).is_err() {
            Err("header corrupt")?}

        let header: Header = wincode::deserialize(&header_buf)
            .map_err(|e| format!("Error: header malformed: {e}"))?;

        if header.magic != MAGIC_NUMBER{
            Err("Invalid Alpack archive")?;}
        if header.version > VERSION{
            Err("Version of Alpack archive is beyond current capabilities")?}

        let mut entries: HashMap<String, Entry> = HashMap::with_capacity(header.entry_count as usize);

        for i in 0..header.entry_count {
            let entry_pos = header.index_offset + (i) * (ENTRY_SIZE as u64);
            if reader.seek(SeekFrom::Start(entry_pos)).is_err() {
                println!("Error: invalid index offset for entry, skipping");
                continue;
            }

            let mut entry_buf = [0u8; ENTRY_SIZE];

            if reader.read_exact(&mut entry_buf).is_err() {
                println!("Error: Invalid entry, skipping");
                continue;
            }

            let entry: Entry = match wincode::deserialize(&entry_buf) {
                Ok(e) => e,
                Err(e) => {
                    println!("Error: Invalid entry: {e}, skipping");
                    continue;
                }
            };

            if reader.seek(SeekFrom::Start(header.string_table_offset + entry.name_offset)).is_err() {
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

        Ok (Reader{
            header,
            file,
            entries,
        })
    }

    pub fn extract(&self, name: &str) -> Result<Vec<u8>, String> {
        let entry = self.entries.get(name)
            .ok_or_else(|| format!("no such entry: {name}"))?;

        let abs_offset = self.header.data_offset + entry.data_offset;

        let mut compressed = vec![0u8; entry.compressed_size as usize];
        self.file
            .read_exact_at(abs_offset, &mut compressed)
            .map_err(|e| format!("failed to read entry data for {name}: {e}"))?;

        let mut decoder = Self::decompressor(Cursor::new(compressed), entry.compression_type)?;

        let mut decompressed = Vec::with_capacity(entry.original_size as usize);
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| format!("failed to decompress entry {name}: {e}"))?;

        Ok(decompressed)
    }

    pub fn stream(&self, name: &str) -> Result<Box<dyn Read + Send + '_>, String> {
        let entry = self.entries.get(name)
            .ok_or_else(|| format!("no such entry: {name}"))?;

        let abs_offset = self.header.data_offset + entry.data_offset;

        let bounded = BoundedPositionedReader {
            file: &self.file,
            pos: abs_offset,
            remaining: entry.compressed_size,
        };

        Self::decompressor(bounded, entry.compression_type)
    }

    fn decompressor<'a, R: Read + Send +'a>( source: R, compression_type: CompressionType ) -> Result<Box<dyn Read + Send + 'a>, String> {
        match compression_type {
            CompressionType::None => Ok(Box::new(source)),
            CompressionType::Zstd => Ok(Box::new(zstd::stream::read::Decoder::new(source).map_err(|e| format!("Zstd decoder failed: {e}"))?)),
            CompressionType::Deflate => Ok(Box::new(flate2::read::DeflateDecoder::new(source))),
            CompressionType::Lz4 => Ok(Box::new(lz4::Decoder::new(source).map_err(|e| format!("lz4 decoder failed {e}"))?)),
        }
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
        let n = self.file.read_at(self.pos, &mut  buf[..capacity])?;
        self.pos += n as u64;
        self.remaining -= n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::CompressionType;
    use lipsum::lipsum;
    use pretty_assertions::assert_eq;
    use rand::RngExt;
    use std::io::{BufWriter, Error, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::thread;
    use tempfile::env::temp_dir;
    use wincode::serialize_into;

    fn compress(data: &[u8], compression_type: CompressionType) -> Vec<u8> {
        match compression_type {
            CompressionType::None => data.to_vec(),
            CompressionType::Zstd => zstd::encode_all(data, 3).expect("zstd encode failed"),
            CompressionType::Deflate => {
                let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(data).expect("deflate write failed");
                encoder.finish().expect("deflate finish failed")
            }
            CompressionType::Lz4 => {
                let mut encoder = lz4::EncoderBuilder::new().build(Vec::new()).expect("lz4 build failed");
                encoder.write_all(data).expect("lz4 write failed");
                let (compressed, result) = encoder.finish();
                result.expect("lz4 finish failed");
                compressed
            }
        }
    }

    fn build_test_archive(
        header: &mut Header,
        name: &str,
        first_entry_words: Option<usize>,
        first_entry_compression: Option<CompressionType>
    ) -> Result<PathBuf, Error> {
        let temp_dir = temp_dir().join(name);
        let mut writer = BufWriter::new(File::create(&temp_dir)?);
        let mut names: Vec<String> = Vec::new();
        let mut entries: Vec<Entry> = Vec::new();
        let mut data: Vec<u8> = Vec::new();

        let mut rng = rand::rng();

        header.data_offset = HEADER_SIZE as u64;

        let mut current_name_table_offset = 0;
        let mut data_length = 0;
        for i in 0..header.entry_count {
            let name = format!("fake/file.{}", i);

            let (content, compression_type) = if i == 0 {
                (lipsum(first_entry_words.unwrap_or(3)), first_entry_compression.unwrap_or(CompressionType::None))
            } else {
                (lipsum(rng.random_range(0..100)), CompressionType::None)
            };

            let original_bytes = content.as_bytes();
            let compressed_bytes = compress(original_bytes, compression_type);

            entries.push(Entry {
                custom1: 0,
                custom2: 0,
                data_offset: data_length,
                compressed_size: compressed_bytes.len() as u64,
                original_size: original_bytes.len() as u64,
                compression_type,
                name_offset: current_name_table_offset as u64,
                name_length: name.len() as u64,
                reserved: 0,
            });

            current_name_table_offset += name.len();
            data_length += compressed_bytes.len() as u64;
            names.push(name);
            data.extend_from_slice(&compressed_bytes);
        }

        header.string_table_offset = header.data_offset + data_length;

        header.index_offset = header.string_table_offset + current_name_table_offset as u64;

        serialize_into(&mut writer, &*header).expect("failed to serialise header");
        writer.write_all(data.as_slice())?;
        for name in names.iter(){
            writer.write_all(name.as_bytes())?;
        }
        for entry in entries {
            serialize_into(&mut writer, &entry).expect("failed to serialise entry");
        }

        writer.flush()?;
        drop(writer);

        Ok(temp_dir)
    }

    fn build_simple_archive(header: &mut Header, name: &str) -> Result<PathBuf, Error> {
        build_test_archive(header, name, None, None)
    }

    #[test]
    fn reader_constructor_reads_correctly() {
        let entries: u64 = 1000;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: entries,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_simple_archive(&mut header, "test.alpack").unwrap();

        let reader = Reader::new(path.as_path()).unwrap();

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
            reserved: 0,
        };
        let magic_fail_path = build_simple_archive(&mut magic_fail_header, "fail.alpack").unwrap();

        assert!(Reader::new(magic_fail_path.as_path()).is_err());
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
            reserved: 0,
        };
        let version_fail_path = build_simple_archive(&mut version_fail_header, "future.alpack").unwrap();

        assert!(Reader::new(version_fail_path.as_path()).is_err());
    }

    #[test]
    fn reader_constructor_fails_missing_file() {
        let path = Path::new("/this/does/not/exist.alpack");

        assert!(Reader::new(path).is_err());
    }

    #[test]
    fn reader_constructor_fails_truncated_header() {
        let path = temp_dir().join("truncated.alpack");

        std::fs::write(&path, [0u8; 10]).unwrap();

        assert!(Reader::new(&path).is_err());
    }

    #[test]
    fn reader_constructor_fails_invalid_utf8_name() {
        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_simple_archive(&mut header, "bad_utf8.alpack").unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[header.string_table_offset as usize] = 0x80; // invalid UTF-8 lead byte
        std::fs::write(&path, bytes).unwrap();

        let reader = Reader::new(&path).unwrap();
        assert!(reader.entries.is_empty())
    }

    #[test]
    fn extract_extracts_none_successfully() {
        let word_count: usize = 30;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "none_compression.alpack", Some(word_count), Some(CompressionType::None)).unwrap();

        let reader = Reader::new(&path).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_extracts_zstd_successfully() {
        let word_count: usize = 30;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "zstd_compression.alpack", Some(word_count), Some(CompressionType::Zstd)).unwrap();

        let reader = Reader::new(&path).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_extracts_deflate_successfully() {
        let word_count: usize = 30;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "deflate_compression.alpack", Some(word_count), Some(CompressionType::Deflate)).unwrap();

        let reader = Reader::new(&path).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn extract_extracts_lz4_successfully() {
        let word_count: usize = 30;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "lz4_compression.alpack", Some(word_count), Some(CompressionType::Lz4)).unwrap();

        let reader = Reader::new(&path).unwrap();
        let bytes = reader.extract("fake/file.0").unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_none_successfully() {
        let word_count: usize = 30;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "none_compression_stream.alpack", Some(word_count), Some(CompressionType::None)).unwrap();

        let reader = Reader::new(&path).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_zstd_successfully() {
        let word_count: usize = 30;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "zstd_compression_stream.alpack", Some(word_count), Some(CompressionType::Zstd)).unwrap();

        let reader = Reader::new(&path).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_deflate_successfully() {
        let word_count: usize = 30;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "deflate_compression_stream.alpack", Some(word_count), Some(CompressionType::Deflate)).unwrap();

        let reader = Reader::new(&path).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_extracts_lz4_successfully() {
        let word_count: usize = 30;

        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "lz4_compression_stream.alpack", Some(word_count), Some(CompressionType::Lz4)).unwrap();

        let reader = Reader::new(&path).unwrap();
        let mut stream = reader.stream("fake/file.0").unwrap();

        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text, lipsum(word_count))
    }

    #[test]
    fn stream_works_across_threads() {
        let word_count: usize = 30;
        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 1,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "stream_threaded.alpack", Some(word_count), Some(CompressionType::Lz4)).unwrap();

        let reader = Arc::new(Reader::new(&path).unwrap());
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
}