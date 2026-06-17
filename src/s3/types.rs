use std::{fmt, num::NonZeroU16, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Validated S3 bucket name used after request-target parsing.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct BucketName(String);

impl BucketName {
    /// Parses a bucket name from request input.
    ///
    /// Returns an error when the value is empty or contains path separators or
    /// control characters. This type intentionally keeps validation narrower
    /// than AWS bucket-creation rules because this endpoint receives existing
    /// bucket identifiers and must mainly prevent path traversal and malformed
    /// storage keys.
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::EmptyBucketName);
        }
        if value
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'\\') || byte.is_ascii_control())
        {
            return Err(DomainError::InvalidBucketName);
        }
        Ok(Self(value))
    }

    /// Returns the validated bucket name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BucketName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validated S3 object key used after request-target parsing.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ObjectKey(String);

impl ObjectKey {
    /// Parses an object key from request input.
    ///
    /// Returns an error when the key is empty or contains control characters.
    /// Slash characters are valid object-key bytes and are preserved.
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DomainError::EmptyObjectKey);
        }
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(DomainError::InvalidObjectKey);
        }
        Ok(Self(value))
    }

    /// Returns the validated object key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Entity tag value returned by object and part operations.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ETag(String);

impl ETag {
    /// Parses an ETag from request or persisted metadata.
    ///
    /// Returns an error when the value is empty or contains control characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(DomainError::InvalidETag);
        }
        Ok(Self(value))
    }

    /// Builds a single-part object ETag from a lowercase hexadecimal MD5 digest.
    ///
    /// The caller must pass a digest string that was produced by trusted digest
    /// code; this function only applies the S3 quote formatting.
    pub fn from_hex_md5(hex_md5: String) -> Self {
        Self(format!("\"{hex_md5}\""))
    }

    /// Builds a multipart object ETag from the multipart MD5 digest and part count.
    ///
    /// The caller must pass a digest string and part count computed from
    /// validated committed parts.
    pub fn from_multipart_md5(hex_md5: String, part_count: usize) -> Self {
        Self(format!("\"{hex_md5}-{part_count}\""))
    }

    /// Returns the formatted ETag as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ETag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Per-response request identifier surfaced in S3 XML errors and response headers.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct RequestId(String);

impl RequestId {
    /// Creates a new random request identifier.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Parses a request identifier from trusted external input.
    ///
    /// Returns an error when the value is empty or contains control characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(DomainError::InvalidRequestId);
        }
        Ok(Self(value))
    }

    /// Returns the request identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Multipart upload identifier.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct UploadId(String);

impl UploadId {
    /// Creates a new random upload ID.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    /// Parses a canonical UUID upload ID.
    ///
    /// Returns an error for non-UUID values or UUID strings that are not in the
    /// canonical hyphenated lowercase form.
    pub fn parse(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let Ok(uuid) = uuid::Uuid::parse_str(&value) else {
            return Err(DomainError::InvalidUploadId);
        };
        if uuid.to_string() != value {
            return Err(DomainError::InvalidUploadId);
        }
        Ok(Self(value))
    }

    /// Returns the upload ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for UploadId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for UploadId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Parsed HTTP Content-Length value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ContentLength(u64);

impl ContentLength {
    /// Wraps a known-valid content length.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the length in bytes.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ContentLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

impl FromStr for ContentLength {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value
            .parse::<u64>()
            .map_err(|_| DomainError::InvalidContentLength)?;
        Ok(Self::new(value))
    }
}

/// Multipart upload part number in the S3 range 1..=10000.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PartNumber(NonZeroU16);

impl PartNumber {
    /// Parses a multipart part number.
    ///
    /// Returns an error when the value is zero or greater than 10,000.
    pub fn parse(value: u16) -> Result<Self, DomainError> {
        let Some(value) = NonZeroU16::new(value) else {
            return Err(DomainError::InvalidPartNumber);
        };
        if value.get() > 10_000 {
            return Err(DomainError::InvalidPartNumber);
        }
        Ok(Self(value))
    }

    /// Returns the part number as an integer.
    pub fn get(self) -> u16 {
        self.0.get()
    }
}

impl fmt::Display for PartNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

impl FromStr for PartNumber {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value
            .parse::<u16>()
            .map_err(|_| DomainError::InvalidPartNumber)?;
        Self::parse(value)
    }
}

impl Serialize for PartNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.get())
    }
}

impl<'de> Deserialize<'de> for PartNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u16::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

/// Implemented S3 operation selected by method, target shape, and query string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum S3Operation {
    /// PutObject.
    PutObject,
    /// CreateMultipartUpload.
    CreateMultipartUpload,
    /// UploadPart.
    UploadPart {
        /// Multipart upload ID.
        upload_id: UploadId,
        /// Multipart part number.
        part_number: PartNumber,
    },
    /// CompleteMultipartUpload.
    CompleteMultipartUpload {
        /// Multipart upload ID.
        upload_id: UploadId,
    },
    /// AbortMultipartUpload.
    AbortMultipartUpload {
        /// Multipart upload ID.
        upload_id: UploadId,
    },
    /// ListParts.
    ListParts {
        /// Multipart upload ID.
        upload_id: UploadId,
    },
    /// HeadBucket.
    HeadBucket,
    /// HeadObject.
    HeadObject,
    /// GetObject.
    GetObject,
    /// DeleteObject.
    DeleteObject,
}

impl S3Operation {
    /// Returns the S3 operation name used for tracing and diagnostics.
    pub fn name(&self) -> &'static str {
        match self {
            Self::PutObject => "PutObject",
            Self::CreateMultipartUpload => "CreateMultipartUpload",
            Self::UploadPart { .. } => "UploadPart",
            Self::CompleteMultipartUpload { .. } => "CompleteMultipartUpload",
            Self::AbortMultipartUpload { .. } => "AbortMultipartUpload",
            Self::ListParts { .. } => "ListParts",
            Self::HeadBucket => "HeadBucket",
            Self::HeadObject => "HeadObject",
            Self::GetObject => "GetObject",
            Self::DeleteObject => "DeleteObject",
        }
    }

    /// Returns the IAM-style action used by authorization and tuning policies.
    pub fn action(&self) -> crate::config::S3Action {
        match self {
            Self::PutObject => crate::config::S3Action::PutObject,
            Self::CreateMultipartUpload => crate::config::S3Action::CreateMultipartUpload,
            Self::UploadPart { .. } => crate::config::S3Action::UploadPart,
            Self::CompleteMultipartUpload { .. } => {
                crate::config::S3Action::CompleteMultipartUpload
            }
            Self::AbortMultipartUpload { .. } => crate::config::S3Action::AbortMultipartUpload,
            Self::ListParts { .. } => crate::config::S3Action::ListMultipartUploadParts,
            Self::HeadBucket => crate::config::S3Action::HeadBucket,
            Self::HeadObject => crate::config::S3Action::HeadObject,
            Self::GetObject => crate::config::S3Action::GetObject,
            Self::DeleteObject => crate::config::S3Action::DeleteObject,
        }
    }
}

/// Parsed `x-amz-content-sha256` payload hash mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadHashMode {
    /// Header is absent.
    Missing,
    /// Literal `UNSIGNED-PAYLOAD`.
    UnsignedPayload,
    /// Fixed lowercase SHA256 hex digest.
    FixedSha256 {
        /// Original lowercase hex value.
        hex: String,
        /// Decoded digest bytes.
        digest: Vec<u8>,
    },
    /// Literal `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`.
    StreamingSignedPayload,
    /// Literal `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`.
    StreamingSignedPayloadTrailer,
    /// Literal `STREAMING-UNSIGNED-PAYLOAD-TRAILER`.
    StreamingUnsignedPayloadTrailer,
}

impl PayloadHashMode {
    /// Parses a payload hash header value.
    ///
    /// Returns an error when the value is not one of the S3 payload hash modes
    /// implemented by this endpoint.
    pub fn parse(value: Option<&str>) -> Result<Self, DomainError> {
        let Some(value) = value else {
            return Ok(Self::Missing);
        };
        match value {
            "UNSIGNED-PAYLOAD" => Ok(Self::UnsignedPayload),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => Ok(Self::StreamingSignedPayload),
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => Ok(Self::StreamingSignedPayloadTrailer),
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => Ok(Self::StreamingUnsignedPayloadTrailer),
            _ if is_lowercase_sha256_hex(value) => {
                let digest = hex::decode(value).map_err(|_| DomainError::InvalidPayloadHashMode)?;
                Ok(Self::FixedSha256 {
                    hex: value.to_owned(),
                    digest,
                })
            }
            _ => Err(DomainError::InvalidPayloadHashMode),
        }
    }

    /// Returns the literal value used in SigV4 canonical requests, if present.
    pub fn canonical_value(&self) -> Option<&str> {
        match self {
            Self::Missing => None,
            Self::UnsignedPayload => Some("UNSIGNED-PAYLOAD"),
            Self::FixedSha256 { hex, .. } => Some(hex),
            Self::StreamingSignedPayload => Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
            Self::StreamingSignedPayloadTrailer => {
                Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
            }
            Self::StreamingUnsignedPayloadTrailer => Some("STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
        }
    }
}

fn is_lowercase_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Resolved object request target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3Target {
    /// Bucket component of the target.
    pub bucket: BucketName,
    /// Object-key component of the target.
    pub key: ObjectKey,
    /// Whether the target was resolved from virtual-hosted-style addressing.
    pub virtual_hosted: bool,
}

/// Error returned when parsing S3 domain newtypes fails.
#[derive(Debug, Error)]
pub enum DomainError {
    /// Bucket name was empty.
    #[error("bucket name must not be empty")]
    EmptyBucketName,

    /// Bucket name contained path separators or control characters.
    #[error("bucket name contains invalid characters")]
    InvalidBucketName,

    /// Object key was empty.
    #[error("object key must not be empty")]
    EmptyObjectKey,

    /// Object key contained control characters.
    #[error("object key contains invalid characters")]
    InvalidObjectKey,

    /// Part number was outside the S3 range 1..=10000.
    #[error("part number must be in the range 1..=10000")]
    InvalidPartNumber,

    /// Content length was not an unsigned decimal integer.
    #[error("content length must be an integer")]
    InvalidContentLength,

    /// ETag was empty or contained control characters.
    #[error("ETag contains invalid characters")]
    InvalidETag,

    /// Request ID was empty or contained control characters.
    #[error("request ID contains invalid characters")]
    InvalidRequestId,

    /// Upload ID was not a canonical lowercase UUID.
    #[error("upload ID must be a canonical lowercase UUID")]
    InvalidUploadId,

    /// Payload hash mode was not supported.
    #[error("payload hash mode is invalid")]
    InvalidPayloadHashMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_name_rejects_path_separators_and_control_characters() {
        assert!(BucketName::parse("test-bucket").is_ok());
        assert!(matches!(
            BucketName::parse("bad/bucket"),
            Err(DomainError::InvalidBucketName)
        ));
        assert!(matches!(
            BucketName::parse("bad\\bucket"),
            Err(DomainError::InvalidBucketName)
        ));
        assert!(matches!(
            BucketName::parse("bad\nbucket"),
            Err(DomainError::InvalidBucketName)
        ));
    }

    #[test]
    fn object_key_preserves_slashes_but_rejects_control_characters() {
        assert_eq!(
            ObjectKey::parse("a//b.txt").expect("key").as_str(),
            "a//b.txt"
        );
        assert!(matches!(
            ObjectKey::parse("bad\nkey"),
            Err(DomainError::InvalidObjectKey)
        ));
    }

    #[test]
    fn request_id_rejects_empty_and_control_characters() {
        assert!(RequestId::parse("request-123").is_ok());
        assert!(matches!(
            RequestId::parse(""),
            Err(DomainError::InvalidRequestId)
        ));
        assert!(matches!(
            RequestId::parse("bad\nrequest"),
            Err(DomainError::InvalidRequestId)
        ));
    }

    #[test]
    fn upload_id_accepts_canonical_uuid() {
        let upload_id = UploadId::new();

        assert_eq!(
            UploadId::parse(upload_id.as_str()).expect("upload id"),
            upload_id
        );
    }

    #[test]
    fn upload_id_rejects_non_uuid_or_non_canonical_values() {
        assert!(matches!(
            UploadId::parse("../outside"),
            Err(DomainError::InvalidUploadId)
        ));
        assert!(matches!(
            UploadId::parse("550E8400-E29B-41D4-A716-446655440000"),
            Err(DomainError::InvalidUploadId)
        ));
    }

    #[test]
    fn upload_id_deserialization_uses_same_validation() {
        let result = serde_json::from_str::<UploadId>(r#""../outside""#);

        assert!(result.is_err());
    }

    #[test]
    fn etag_rejects_empty_and_control_characters() {
        assert_eq!(ETag::parse("\"abc\"").expect("etag").as_str(), "\"abc\"");
        assert!(matches!(ETag::parse(""), Err(DomainError::InvalidETag)));
        assert!(matches!(
            ETag::parse("bad\netag"),
            Err(DomainError::InvalidETag)
        ));
    }

    #[test]
    fn content_length_parses_unsigned_decimal_values() {
        assert_eq!(ContentLength::from_str("0").expect("length").get(), 0);
        assert_eq!(ContentLength::from_str("42").expect("length").get(), 42);
        assert!(matches!(
            ContentLength::from_str("-1"),
            Err(DomainError::InvalidContentLength)
        ));
        assert!(matches!(
            ContentLength::from_str("not-an-int"),
            Err(DomainError::InvalidContentLength)
        ));
    }

    #[test]
    fn payload_hash_mode_parses_supported_values() {
        let digest = "0".repeat(64);
        assert!(matches!(
            PayloadHashMode::parse(None).expect("missing"),
            PayloadHashMode::Missing
        ));
        assert!(matches!(
            PayloadHashMode::parse(Some("UNSIGNED-PAYLOAD")).expect("unsigned"),
            PayloadHashMode::UnsignedPayload
        ));
        assert!(matches!(
            PayloadHashMode::parse(Some(&digest)).expect("fixed"),
            PayloadHashMode::FixedSha256 { .. }
        ));
        assert!(matches!(
            PayloadHashMode::parse(Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD")).expect("streaming"),
            PayloadHashMode::StreamingSignedPayload
        ));
        assert!(matches!(
            PayloadHashMode::parse(Some("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"))
                .expect("streaming trailer"),
            PayloadHashMode::StreamingSignedPayloadTrailer
        ));
        assert!(matches!(
            PayloadHashMode::parse(Some("STREAMING-UNSIGNED-PAYLOAD-TRAILER"))
                .expect("unsigned trailer"),
            PayloadHashMode::StreamingUnsignedPayloadTrailer
        ));
    }

    #[test]
    fn payload_hash_mode_rejects_unsupported_or_non_lowercase_values() {
        assert!(matches!(
            PayloadHashMode::parse(Some(&"A".repeat(64))),
            Err(DomainError::InvalidPayloadHashMode)
        ));
        assert!(matches!(
            PayloadHashMode::parse(Some("not-supported")),
            Err(DomainError::InvalidPayloadHashMode)
        ));
    }
}
