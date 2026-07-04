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
    pub fn new(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|e| format!("could not open {}: {}", path.to_str().unwrap().to_string(), e))?;


        let mut reader = BufReader::new(file);


        let mut header_buf = [0u8; HEADER_SIZE];

        if reader.read_exact(&mut header_buf).is_err() {
            Err("header corrupt")?}

        let header = Header {
            magic: u32::from_le_bytes(header_buf[0..4].try_into().map_err(|_| "header malformed")?),
            version: u32::from_le_bytes(header_buf[4..8].try_into().map_err(|_| "header malformed")?),
            entry_count: u32::from_le_bytes(header_buf[8..12].try_into().map_err(|_| "header malformed")?),
            data_offset: u32::from_le_bytes(header_buf[12..16].try_into().map_err(|_| "header malformed")?),
            string_table_offset: u32::from_le_bytes(header_buf[16..20].try_into().map_err(|_| "header malformed")?),
            index_offset: u32::from_le_bytes(header_buf[20..24].try_into().map_err(|_| "header malformed")?),
            reserved: u32::from_le_bytes(header_buf[24.. 28].try_into().map_err(|_| "header malformed")?),
        };

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

            let entry = Entry {
                custom1: u32::from_le_bytes(entry_buf[0..4].try_into().map_err(|_| "entry malformed")?),
                custom2: u32::from_le_bytes(entry_buf[4..8].try_into().map_err(|_| "entry malformed")?),
                data_offset: u32::from_le_bytes(entry_buf[8..12].try_into().map_err(|_| "entry malformed")?),
                compressed_size: u32::from_le_bytes(entry_buf[12..16].try_into().map_err(|_| "entry malformed")?),
                original_size: u32::from_le_bytes(entry_buf[16..20].try_into().map_err(|_| "entry malformed")?),
                compression_type: u32::from_le_bytes(entry_buf[20..24].try_into().map_err(|_| "entry malformed")?),
                name_offset: u32::from_le_bytes(entry_buf[24..28].try_into().map_err(|_| "entry malformed")?),
                reserved: u32::from_le_bytes(entry_buf[28..32].try_into().map_err(|_| "entry malformed")?),
            };

            if reader.seek(SeekFrom::Start((header.string_table_offset + entry.name_offset) as u64)).is_err() {
                println!("Error: invalid String Table offset, skipping entry.");
                continue;
            }

            let mut name = String::new();
            if reader.read_to_string(&mut name).is_err() {
                println!("Error: invalid String table entry, skipping.");
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