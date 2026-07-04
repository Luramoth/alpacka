use std::string::String;
use std::collections::HashMap;
use std::fs::{File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use crate::format::{Entry, Header, ENTRY_SIZE, HEADER_SIZE, MAGIC_NUMBER, VERSION};

pub struct Reader{
    pub header: Header,
    reader: BufReader<File>,
    entries: HashMap<String, Entry>
}

impl Reader {
    pub fn new(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("could not open {}: {}", path.to_str().unwrap().to_string(), e))?;


        let mut reader = BufReader::new(file);


        let mut header_buf = [0u8; HEADER_SIZE];

        if reader.read_exact(&mut header_buf).is_err() {
            Err("header corrupt")?}

        let header: Header = wincode::deserialize(&header_buf)
            .map_err(|e| format!("Error: header malformed: {e}"))?;

        if header.magic != MAGIC_NUMBER{
            Err("Invalid Alpack archive")?;}
        if header.version > VERSION{
            Err("Version of Alpack archive is beyond current capabilities")?}

        if reader.seek(SeekFrom::Start(header.index_offset as u64)).is_err() {
            Err("Broken Index offset")?}

        let mut entries: HashMap<String, Entry> = HashMap::with_capacity(header.entry_count as usize);

        for _ in 0..header.entry_count {
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

            if reader.seek(SeekFrom::Start((header.string_table_offset + entry.name_offset) as u64)).is_err() {
                println!("Error: invalid String Table offset, skipping entry.");
                continue;
            }

            let mut name_buf: Vec<u8> = Vec::new();
            if reader.read_until(0, &mut name_buf).is_err() {
                println!("Error: invalid String table entry, skipping.");
                continue;
            }
            name_buf.pop();
            let name = match String::from_utf8(name_buf) {
                Ok(n) => n,
                Err(e) => {
                    println!("Error: invalid string table entry, skipping");
                    continue;
                }
            };


            entries.insert(name, entry);
        }

        Ok (Reader{
            reader,
            header,
            entries,
        })
    }
}


#[cfg(test)]
mod tests {
    use std::fmt::format;
    use std::io::{BufWriter, Error, Write};
    use std::path::{Path, PathBuf};
    use tempfile::env::temp_dir;
    use wincode::serialize_into;
    use pretty_assertions::assert_eq;
    use crate::format::CompressionType;
    use super::*;

    fn build_test_archive(header: &mut Header, name: &str) -> Result<PathBuf, Error> {
        let temp_dir = temp_dir().join(name);
        let mut writer = BufWriter::new(File::create(&temp_dir)?);
        let content = "lorem ipsum dolor";
        let mut names: Vec<String> = Vec::new();
        let mut entries: Vec<Entry> = Vec::new();

        header.data_offset = HEADER_SIZE as u32;
        header.string_table_offset = (HEADER_SIZE + (content.len() * header.entry_count as usize)) as u32;

        for i in 0..header.entry_count {
            let mut current_name_table_offset = 0;
            for name in names.iter() {
                current_name_table_offset += name.len()
            }

            names.push(format(format_args!("fake/file.{}\0", i)));
            entries.push(Entry {
                custom1: 0,
                custom2: 0,
                data_offset: content.len() as u32 * i,
                compressed_size: content.len() as u32,
                original_size: content.len() as u32,
                compression_type: CompressionType::None as u32,
                name_offset: current_name_table_offset as u32,
                reserved: 0,
            });
        }
        let mut string_table_end = 0;
        for name in names.iter() {
            string_table_end += name.len() as u32
        }

        header.index_offset = header.string_table_offset + string_table_end;

        serialize_into(&mut writer, &*header).expect("failed to serialise header");
        for _ in 0..header.entry_count {
            writer.write_all(content.as_bytes())?;
        }
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

    #[test]
    fn reader_constructor_reads_correctly() {
        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 10,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        let path = build_test_archive(&mut header, "test.alpack").unwrap();

        let reader = Reader::new(path.as_path()).unwrap();

        assert_eq!(reader.header.magic, MAGIC_NUMBER);
        assert_eq!(reader.header.version, VERSION);
        assert_eq!(reader.header.entry_count, 10);
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
        let magic_fail_path = build_test_archive(&mut magic_fail_header, "fail.alpack").unwrap();

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
        let version_fail_path = build_test_archive(&mut version_fail_header, "future.alpack").unwrap();

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
        let path = build_test_archive(&mut header, "bad_utf8.alpack").unwrap();

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[header.string_table_offset as usize] = 0x80; // invalid UTF-8 lead byte
        std::fs::write(&path, bytes).unwrap();

        let reader = Reader::new(&path).unwrap();
        assert!(reader.entries.is_empty())
    }
}