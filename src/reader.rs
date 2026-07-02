use std::collections::HashMap;
use std::fs::{File};
use std::io::{BufReader, Read, Seek, SeekFrom};
use crate::format::{Entry, Header, ENTRY_SIZE, HEADER_SIZE, MAGIC_NUMBER, VERSION};

pub struct Reader{
    pub header: Header,
    reader: BufReader<File>,
    entries: HashMap<String, Entry>
}

impl Reader {
    pub fn new(path: String) -> Result<Self, String> {
        let file = File::open(path).unwrap();
        let mut reader = BufReader::new(file);


        let mut header_buf = [0u8; HEADER_SIZE];

        reader.read_exact(&mut header_buf).expect("Couldn't read file contents");

        let header = Header {
            magic: u32::from_le_bytes(header_buf[0..4].try_into().unwrap()),
            version: u32::from_le_bytes(header_buf[4..8].try_into().unwrap()),
            entry_count: u32::from_le_bytes(header_buf[8..12].try_into().unwrap()),
            data_offset: u32::from_le_bytes(header_buf[12..16].try_into().unwrap()),
            string_table_offset: u32::from_le_bytes(header_buf[16..20].try_into().unwrap()),
            index_offset: u32::from_le_bytes(header_buf[20..24].try_into().unwrap()),
            reserved: u32::from_le_bytes(header_buf[24.. 28].try_into().unwrap()),
        };

        if header.magic != MAGIC_NUMBER{
            Err("Invalid Alpack archive")?;}
        if header.version > VERSION{
            Err("Version of Alpack archive is beyond current capabilities")?}

        reader.seek(SeekFrom::Start(header.index_offset as u64)).expect("Invalid archive index offset");
        let mut entries: HashMap<String, Entry> = HashMap::with_capacity(header.entry_count as usize);

        for _ in 0..header.entry_count {
            let mut entry_buf = [0u8; ENTRY_SIZE];

            reader.read_exact(&mut entry_buf).expect("Could not read Entry");

            let entry = Entry {
                custom1: u32::from_le_bytes(entry_buf[0..4].try_into().unwrap()),
                custom2: u32::from_le_bytes(entry_buf[4..8].try_into().unwrap()),
                data_offset: u32::from_le_bytes(entry_buf[8..12].try_into().unwrap()),
                compressed_size: u32::from_le_bytes(entry_buf[12..16].try_into().unwrap()),
                original_size: u32::from_le_bytes(entry_buf[16..20].try_into().unwrap()),
                compression_type: u32::from_le_bytes(entry_buf[20..24].try_into().unwrap()),
                name_offset: u32::from_le_bytes(entry_buf[24..28].try_into().unwrap()),
                reserved: u32::from_le_bytes(entry_buf[28..32].try_into().unwrap()),
            };

            reader.seek(SeekFrom::Start((header.string_table_offset + entry.name_offset) as u64)).expect("Invalid String tame offset");
            let mut name = String::new();
            let err = reader.read_to_string(&mut name);

            if err.is_err() {
                println!("Invalid string table entry. name offset: {0}", entry.name_offset);
                continue;
            }


            entries.insert(name, entry);
        }

        Ok (Reader{
            reader,
            header,
            entries,
        })
    }
}