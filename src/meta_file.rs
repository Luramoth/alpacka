use std::fs;
use std::path::Path;
use crate::format::CompressionType;


#[derive(serde::Deserialize)]
#[serde(default)]
pub struct Meta {
    #[serde(rename = "Pack")]
    pub pack: Pack,
}

#[derive(serde::Deserialize)]
#[serde(default)]
#[serde(rename_all = "PascalCase")]
pub struct Pack{
    pub compression: String,
    pub force_compression: bool,
    pub encrypted: bool,
}

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
            compression: "zstd".to_string(),
            force_compression: false,
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
    pub fn get_compression_type(&self) -> CompressionType {
        match self.pack.compression.to_lowercase().as_str() {
            "none" => CompressionType::None,
            "deflate" => CompressionType::Deflate,
            "lz4" => CompressionType::Lz4,
            "zstd" => CompressionType::Zstd,
            what => {
                println!("Unrecognised compression: {what}, defaulting to zstd");
                CompressionType::Zstd
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
        let none = Meta {pack: Pack{ compression: "none".to_string(), force_compression: false, encrypted: true}};

        assert_eq!(none.get_compression_type(), CompressionType::None);
    }

    #[test]
    fn get_compression_type_returns_deflate() {
        let deflate = Meta {pack: Pack{ compression: "deflate".to_string(), force_compression: false, encrypted: true}};

        assert_eq!(deflate.get_compression_type(), CompressionType::Deflate);
    }

    #[test]
    fn get_compression_type_returns_lz4() {
        let lz4 = Meta {pack: Pack{ compression: "lz4".to_string(), force_compression: false, encrypted: true}};

        assert_eq!(lz4.get_compression_type(), CompressionType::Lz4);
    }

    #[test]
    fn get_compression_type_returns_zstd() {
        let zstd = Meta {pack: Pack{ compression: "zstd".to_string(), force_compression: false, encrypted: true}};

        assert_eq!(zstd.get_compression_type(), CompressionType::Zstd);
    }

    #[test]
    fn get_compression_type_returns_zstd_fallback() {
        let fake = Meta {pack: Pack{ compression: "fake".to_string(), force_compression: false, encrypted: true}};

        assert_eq!(fake.get_compression_type(), CompressionType::Zstd);
    }

    #[test]
    fn load_or_default_works() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("file.meta.toml");
        let content = r#"[Pack]
        Compression = "deflate"
        ForceCompression = true
        Encrypted = false"#;

        fs::write(&temp_path, content).unwrap();

        let meta: Meta = load_or_default(&temp_path);

        assert_eq!(meta.pack.compression, "deflate");
        assert_eq!(meta.pack.force_compression, true);
        assert_eq!(meta.pack.encrypted, false);

        assert_eq!(meta.get_compression_type(), CompressionType::Deflate);
    }

    #[test]
    fn load_or_default_gives_default_on_missing_file() {
        let fake_meta = load_or_default(Path::new("not/real/dir/to/fake.meta.toml"));

        assert_eq!(fake_meta.pack.compression, "zstd");
        assert_eq!(fake_meta.pack.force_compression, false);
        assert_eq!(fake_meta.pack.encrypted, true);
    }

    #[test]
    fn load_or_default_gives_default_on_broken_file() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("broken.meta.toml");
        let content = r#"[Pack]
        Compression = "fake"
        ForceCompression = wont work
        Encrypted = dont feel like it"#;

        fs::write(&temp_path, content).unwrap();

        let broken_meta: Meta = load_or_default(&temp_path);

        assert_eq!(broken_meta.pack.compression, "zstd");
        assert_eq!(broken_meta.pack.force_compression, false);
        assert_eq!(broken_meta.pack.encrypted, true);
    }

    #[test]
    fn load_or_default_gives_default_on_compression_only_file() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("compression.meta.toml");
        let content = r#"[Pack]
        Compression = "lz4""#;

        fs::write(&temp_path, content).unwrap();

        let broken_meta: Meta = load_or_default(&temp_path);

        assert_eq!(broken_meta.pack.compression, "lz4");
        assert_eq!(broken_meta.pack.force_compression, false);
        assert_eq!(broken_meta.pack.encrypted, true);
    }

    #[test]
    fn load_or_default_gives_default_on_force_compression_only_file() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("force_compression.meta.toml");
        let content = r#"[Pack]
        ForceCompression = true"#;

        fs::write(&temp_path, content).unwrap();

        let broken_meta: Meta = load_or_default(&temp_path);

        assert_eq!(broken_meta.pack.compression, "zstd");
        assert_eq!(broken_meta.pack.force_compression, true);
        assert_eq!(broken_meta.pack.encrypted, true);
    }

    #[test]
    fn load_or_default_gives_default_on_encryption_only_file() {
        let temp_dir = temp_dir();

        let temp_path = temp_dir.as_path().join("encryption.meta.toml");
        let content = r#"[Pack]
        Encrypted = false"#;

        fs::write(&temp_path, content).unwrap();

        let broken_meta: Meta = load_or_default(&temp_path);

        assert_eq!(broken_meta.pack.compression, "zstd");
        assert_eq!(broken_meta.pack.force_compression, false);
        assert_eq!(broken_meta.pack.encrypted, false);
    }
}