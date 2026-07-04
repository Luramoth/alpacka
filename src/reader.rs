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
    use crate::format::CompressionType;
    use super::*;

    fn build_test_archive(header: &mut Header) -> Result<PathBuf, Error> {
        let temp_dir = temp_dir().join("test.alpack");
        let mut writer = BufWriter::new(File::create(&temp_dir)?);
        let content = "lorem ipsum dolor";
        let mut names: Vec<String> = Vec::new();
        let mut entries: Vec<Entry> = Vec::new();
        let mut index_offset = 0;

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
    fn idk() {
        let mut header = Header {
            magic: MAGIC_NUMBER,
            version: VERSION,
            entry_count: 2,
            data_offset: 0,
            string_table_offset: 0,
            index_offset: 0,
            reserved: 0,
        };
        build_test_archive(&mut header).unwrap();
    }
}