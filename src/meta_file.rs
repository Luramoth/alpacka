use std::fs;
use crate::format::CompressionType;

#[allow(non_snake_case)]
#[derive(serde::Deserialize)]
#[serde(default)]
pub struct Meta {
    Pack: Pack,
}

#[allow(non_snake_case)]
#[derive(serde::Deserialize)]
#[serde(default)]
pub struct Pack{
    Compression: String,
    ForceCompression: bool,
}

impl Default for Meta {
    fn default() -> Self {
        Meta {
            Pack: Pack::default()
        }
    }
}

impl Default for Pack {
    fn default() -> Self {
        Pack {
            Compression: "zstd".to_string(),
            ForceCompression: false,
        }
    }
}

pub fn load_or_default(path: &str) -> Meta {
    if fs::exists(path).is_err() {

    }

    let text = fs::read_to_string(path).unwrap();
    toml::from_str(&text).unwrap()
}

impl Meta {
    pub fn get_compression_type(&mut self) -> CompressionType {
        match self.Pack.Compression.to_lowercase().as_str() {
            "none" => CompressionType::None,
            "deflate" => CompressionType::Deflate,
            "lz4" => CompressionType::Lz4,
            "zstd" => CompressionType::Zstd,
            _ => CompressionType::Zstd,
        }
    }
}