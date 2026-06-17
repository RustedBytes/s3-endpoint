use serde::{Deserialize, Serialize};

/// Supported S3 checksum algorithms.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
    /// CRC32 checksum.
    #[serde(rename = "CRC32")]
    Crc32,
    /// CRC32C checksum.
    #[serde(rename = "CRC32C")]
    Crc32c,
    /// SHA1 checksum.
    #[serde(rename = "SHA1")]
    Sha1,
    /// SHA256 checksum.
    #[serde(rename = "SHA256")]
    Sha256,
    /// SHA512 checksum.
    #[serde(rename = "SHA512")]
    Sha512,
}

/// S3 multipart checksum type.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChecksumType {
    /// Per-part checksum composition.
    #[serde(rename = "COMPOSITE")]
    Composite,
    /// Full-object checksum.
    #[serde(rename = "FULL_OBJECT")]
    FullObject,
}
