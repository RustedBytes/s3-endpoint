use percent_encoding::percent_decode_str;
use thiserror::Error;

use super::types::{BucketName, ObjectKey, S3Target};

/// Resolves a bucket name from a request path and optional virtual-hosted host.
///
/// For virtual-hosted requests, the bucket is extracted from the host prefix
/// and the path must not contain an object key. For path-style requests, the
/// first path segment is parsed as the bucket. Returns an error when the bucket
/// is absent, invalid, or percent-encoding is malformed.
pub fn resolve_bucket_name(
    path: &str,
    host: Option<&str>,
    virtual_host_base_domain: Option<&str>,
) -> Result<BucketName, TargetError> {
    if let (Some(host), Some(base_domain)) = (host, virtual_host_base_domain)
        && let Some(bucket) = virtual_host_bucket(host, base_domain)
    {
        let path = path.strip_prefix('/').unwrap_or(path);
        if !path.is_empty() {
            return Err(TargetError::MissingKey);
        }
        return BucketName::parse(percent_decode(bucket)?).map_err(TargetError::InvalidDomain);
    }

    resolve_path_style_bucket(path)
}

/// Resolves a full S3 bucket/key target from a request path and host.
///
/// The resolver supports path-style and configured virtual-hosted-style
/// requests. It preserves slash characters in object keys and validates only
/// after percent-decoding; SigV4 canonicalization must still use the raw URI
/// path from the request.
pub fn resolve_s3_target(
    path: &str,
    host: Option<&str>,
    virtual_host_base_domain: Option<&str>,
) -> Result<S3Target, TargetError> {
    if let (Some(host), Some(base_domain)) = (host, virtual_host_base_domain)
        && let Some(bucket) = virtual_host_bucket(host, base_domain)
    {
        let key = path.strip_prefix('/').unwrap_or(path);
        let bucket =
            BucketName::parse(percent_decode(bucket)?).map_err(TargetError::InvalidDomain)?;
        let key = ObjectKey::parse(percent_decode(key)?).map_err(TargetError::InvalidDomain)?;
        return Ok(S3Target {
            bucket,
            key,
            virtual_hosted: true,
        });
    }

    resolve_path_style(path)
}

fn resolve_path_style_bucket(path: &str) -> Result<BucketName, TargetError> {
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.is_empty() {
        return Err(TargetError::MissingBucket);
    }

    match path.split_once('/') {
        Some((bucket, "")) => {
            BucketName::parse(percent_decode(bucket)?).map_err(TargetError::InvalidDomain)
        }
        Some(_) => Err(TargetError::MissingKey),
        None => BucketName::parse(percent_decode(path)?).map_err(TargetError::InvalidDomain),
    }
}

/// Resolves a path-style `/bucket/key` request target.
///
/// Returns an error when either bucket or key is missing, invalid, or contains
/// malformed percent-encoded UTF-8.
pub fn resolve_path_style(path: &str) -> Result<S3Target, TargetError> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let Some((bucket, key)) = path.split_once('/') else {
        return Err(TargetError::MissingKey);
    };

    let bucket = BucketName::parse(percent_decode(bucket)?).map_err(TargetError::InvalidDomain)?;
    let key = ObjectKey::parse(percent_decode(key)?).map_err(TargetError::InvalidDomain)?;

    Ok(S3Target {
        bucket,
        key,
        virtual_hosted: false,
    })
}

fn virtual_host_bucket<'a>(host: &'a str, base_domain: &str) -> Option<&'a str> {
    let host_without_port = host.split_once(':').map_or(host, |(host, _)| host);
    let base_without_port = base_domain
        .split_once(':')
        .map_or(base_domain, |(base, _)| base);
    let host_lower = host_without_port.to_ascii_lowercase();
    let suffix = format!(".{}", base_without_port.to_ascii_lowercase());
    let bucket_len = host_lower
        .strip_suffix(&suffix)
        .map(|bucket| bucket.len())?;
    let bucket = &host_without_port[..bucket_len];
    (!bucket.is_empty()).then_some(bucket)
}

/// Returns true when `host` contains a bucket prefix before `base_domain`.
///
/// Matching is case-insensitive and ignores ports on both values.
pub fn has_virtual_hosted_bucket(host: &str, base_domain: &str) -> bool {
    virtual_host_bucket(host, base_domain).is_some()
}

fn percent_decode(value: &str) -> Result<String, TargetError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| TargetError::InvalidPercentEncoding)
}

#[derive(Debug, Error)]
/// Errors returned while resolving S3 bucket/key targets.
pub enum TargetError {
    /// The request target did not include a bucket segment.
    #[error("request path must include bucket")]
    MissingBucket,

    /// The request target did not include an object key where one is required.
    #[error("request path must include bucket and key")]
    MissingKey,

    /// A percent-encoded path or host component was not valid UTF-8.
    #[error("path contains invalid percent-encoded UTF-8")]
    InvalidPercentEncoding,

    /// A decoded bucket or key failed domain validation.
    #[error("invalid target: {0}")]
    InvalidDomain(#[source] super::types::DomainError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_path_style_target() {
        let target =
            resolve_s3_target("/bucket/a//b.txt", Some("localhost:9000"), None).expect("target");

        assert_eq!(target.bucket.as_str(), "bucket");
        assert_eq!(target.key.as_str(), "a//b.txt");
        assert!(!target.virtual_hosted);
    }

    #[test]
    fn resolves_virtual_hosted_target() {
        let target = resolve_s3_target("/a//b.txt", Some("bucket.s3.local:9000"), Some("s3.local"))
            .expect("target");

        assert_eq!(target.bucket.as_str(), "bucket");
        assert_eq!(target.key.as_str(), "a//b.txt");
        assert!(target.virtual_hosted);
    }

    #[test]
    fn resolves_virtual_hosted_target_case_insensitively() {
        let target = resolve_s3_target("/key.txt", Some("bucket.S3.Local:9000"), Some("s3.local"))
            .expect("target");

        assert_eq!(target.bucket.as_str(), "bucket");
        assert_eq!(target.key.as_str(), "key.txt");
        assert!(target.virtual_hosted);
    }

    #[test]
    fn detects_virtual_hosted_bucket_case_insensitively() {
        assert!(has_virtual_hosted_bucket(
            "bucket.S3.Local:9000",
            "s3.local"
        ));
        assert!(!has_virtual_hosted_bucket("s3.local:9000", "s3.local"));
    }

    #[test]
    fn resolves_path_style_bucket() {
        let bucket = resolve_bucket_name("/bucket", Some("localhost:9000"), None).expect("bucket");

        assert_eq!(bucket.as_str(), "bucket");
    }

    #[test]
    fn resolves_virtual_hosted_bucket() {
        let bucket = resolve_bucket_name("/", Some("bucket.s3.local:9000"), Some("s3.local"))
            .expect("bucket");

        assert_eq!(bucket.as_str(), "bucket");
    }

    #[test]
    fn rejects_percent_decoded_separator_in_path_style_bucket() {
        assert!(matches!(
            resolve_s3_target("/bad%2Fbucket/key", Some("localhost:9000"), None),
            Err(TargetError::InvalidDomain(_))
        ));
    }

    #[test]
    fn rejects_percent_decoded_control_character_in_virtual_hosted_bucket() {
        assert!(matches!(
            resolve_s3_target("/key", Some("bad%0Abucket.s3.local"), Some("s3.local")),
            Err(TargetError::InvalidDomain(_))
        ));
    }
}
