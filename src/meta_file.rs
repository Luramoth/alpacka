use std::fs;
use std::path::Path;
use crate::format::CompressionType;

#[allow(non_snake_case)]
#[derive(serde::Deserialize)]
#[serde(default)]
pub struct Meta {
    pub Pack: Pack,
}

#[derive(serde::Deserialize)]
#[serde(default)]
pub struct Pack{
    pub compression: String,
    pub force_compression: bool,
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
            compression: "zstd".to_string(),
            force_compression: false,
        }
    }
}

pub fn load_or_default(path: &Path) -> Meta {
    let result = fs::read_to_string(path);
    let text: String;

    if result.is_err() {
        return Meta::default();
    }

    text = result.unwrap();

    toml::from_str(&text).unwrap_or_else(|_| {Meta::default()})
}

impl Meta {
    pub fn get_compression_type(&self) -> CompressionType {
        match self.Pack.compression.to_lowercase().as_str() {
            "none" => CompressionType::None,
            "deflate" => CompressionType::Deflate,
            "lz4" => CompressionType::Lz4,
            "zstd" => CompressionType::Zstd,
            _ => CompressionType::Zstd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq};
    use tempfile::env::temp_dir;

    #[test]
    fn get_compression_type_returns_correct_compression_types() {

        let none = Meta {Pack: Pack{ compression: "none".to_string(), force_compression: false}};
        let deflate = Meta {Pack: Pack{ compression: "deflate".to_string(), force_compression: false}};
        let lz4 = Meta {Pack: Pack{ compression: "lz4".to_string(), force_compression: false}};
        let zstd = Meta {Pack: Pack{ compression: "zstd".to_string(), force_compression: false}};
        let fake = Meta {Pack: Pack{ compression: "fake".to_string(), force_compression: false}};

        assert_eq!(none.get_compression_type(), CompressionType::None);
        assert_eq!(deflate.get_compression_type(), CompressionType::Deflate);
        assert_eq!(lz4.get_compression_type(), CompressionType::Lz4);
        assert_eq!(zstd.get_compression_type(), CompressionType::Zstd);
        assert_eq!(fake.get_compression_type(), CompressionType::Zstd);
    }

    #[test]
    fn load_or_default_works() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("file.meta.toml");
        //let mut temp_toml = File::create(temp_path).unwrap();
        let content = r#"[Pack]
        compression = "deflate"
        force_compression = true"#;

        fs::write(&temp_path, content).unwrap();

        let meta: Meta = load_or_default(&temp_path);

        assert_eq!(meta.Pack.compression, "deflate");
        assert_eq!(meta.Pack.force_compression, true);

        assert_eq!(meta.get_compression_type(), CompressionType::Deflate);
    }

    #[test]
    fn load_or_default_gives_default() {
        // test incorrect file
        let fake_meta = load_or_default(Path::new("not/real/dir/to/fake.meta.toml"));

        assert_eq!(fake_meta.Pack.compression, "zstd");
        assert_eq!(fake_meta.Pack.force_compression, false);

        // test a broken file
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("broken.meta.toml");
        let content = r#"[Pack]
        compression = "fake"
        force_compression = wont work"#;

        fs::write(&temp_path, content).unwrap();

        let broken_meta: Meta = load_or_default(&temp_path);

        assert_eq!(broken_meta.Pack.compression, "zstd");
        assert_eq!(broken_meta.Pack.force_compression, false);
    }
}