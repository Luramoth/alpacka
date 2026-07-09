use std::fs;
use std::path::Path;
use crate::format::CompressionType;


#[derive(serde::Deserialize, Eq, PartialEq)]
pub struct Meta {
    #[serde(rename = "Pack")]
    pub pack: Pack,
}

#[derive(serde::Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Pack{
    #[serde(default)]
    pub compression: Option<String>,
    #[serde(default = "default_encrypted")]
    pub encrypted: bool,
}

fn default_encrypted() -> bool {true}

impl Default for Meta {
    fn default() -> Self {
        Meta {
            pack: Pack::default()
        }
    }
}

impl Default for Pack {
    fn default() -> Self {
        Pack {
            compression: None,
            encrypted: true,
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
    pub fn get_compression_type(&self) -> Option<CompressionType> {
        match self.pack.compression.as_deref()?.to_lowercase().as_str() {
            "none" => Some(CompressionType::None),
            "deflate" => Some(CompressionType::Deflate),
            "lz4" => Some(CompressionType::Lz4),
            "zstd" => Some(CompressionType::Zstd),
            what => {
                println!("Unrecognised compression: {what}, defaulting to packager default");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq};
    use tempfile::env::temp_dir;

    #[test]
    fn get_compression_type_returns_none() {
        let none = Meta {pack: Pack{ compression: Some("none".to_string()), encrypted: true}};

        assert_eq!(none.get_compression_type().unwrap(), CompressionType::None);
    }

    #[test]
    fn get_compression_type_returns_deflate() {
        let deflate = Meta {pack: Pack{ compression: Some("deflate".to_string()), encrypted: true}};

        assert_eq!(deflate.get_compression_type().unwrap(), CompressionType::Deflate);
    }

    #[test]
    fn get_compression_type_returns_lz4() {
        let lz4 = Meta {pack: Pack{ compression: Some("lz4".to_string()), encrypted: true}};

        assert_eq!(lz4.get_compression_type().unwrap(), CompressionType::Lz4);
    }

    #[test]
    fn get_compression_type_returns_zstd() {
        let zstd = Meta {pack: Pack{ compression: Some("zstd".to_string()), encrypted: true}};

        assert_eq!(zstd.get_compression_type().unwrap(), CompressionType::Zstd);
    }

    #[test]
    fn get_compression_type_returns_none_fallback() {
        let fake = Meta {pack: Pack{ compression: Some("fake".to_string()), encrypted: true}};

        assert_eq!(fake.get_compression_type(), None);
    }

    #[test]
    fn load_or_default_works() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("file.meta.toml");
        let content = r#"[Pack]
        Compression = "deflate"
        Encrypted = false"#;

        fs::write(&temp_path, content).unwrap();

        let meta: Meta = load_or_default(&temp_path);

        assert_eq!(meta.pack.compression.unwrap(), "deflate");
        assert_eq!(meta.pack.encrypted, false);
    }

    #[test]
    fn load_or_default_gives_default_on_missing_file() {
        let fake_meta = load_or_default(Path::new("not/real/dir/to/fake.meta.toml"));

        assert_eq!(fake_meta.pack.compression, None);
        assert_eq!(fake_meta.pack.encrypted, true);
    }

    #[test]
    fn load_or_default_gives_default_on_broken_file() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("broken.meta.toml");
        let content = r#"[Pack]
        Compression = "fake"
        Encrypted = dont feel like it"#;

        fs::write(&temp_path, content).unwrap();

        let broken_meta: Meta = load_or_default(&temp_path);

        assert_eq!(broken_meta.pack.compression, None);
        assert_eq!(broken_meta.pack.encrypted, true);
    }

    #[test]
    fn load_or_default_gives_default_on_compression_only_file() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("compression.meta.toml");
        let content = r#"[Pack]
        Compression = "lz4""#;

        fs::write(&temp_path, content).unwrap();

        let meta: Meta = load_or_default(&temp_path);

        assert_eq!(meta.pack.compression.unwrap(), "lz4");
        assert_eq!(meta.pack.encrypted, true);
    }

    #[test]
    fn load_or_default_gives_default_on_encryption_only_file() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("encryption.meta.toml");
        let content = r#"[Pack]
        Encrypted = false"#;

        fs::write(&temp_path, content).unwrap();

        let meta: Meta = load_or_default(&temp_path);

        assert_eq!(meta.pack.compression, None);
        assert_eq!(meta.pack.encrypted, false);
    }
}