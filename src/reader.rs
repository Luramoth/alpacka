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