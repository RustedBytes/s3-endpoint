//! S3 domain parsing and validated value types.

/// Bucket/key target resolution for path-style and virtual-hosted-style requests.
pub mod target;
/// Validated S3 scalar types used after request parsing.
pub mod types;
