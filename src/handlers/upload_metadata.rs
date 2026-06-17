use std::collections::BTreeMap;

use axum::http::{HeaderMap, header};

use crate::{
    error::S3Error,
    storage::{ChecksumAlgorithm, ChecksumType, UploadMetadata},
};

/// Collects persisted object metadata from upload request headers.
///
/// Duplicate metadata headers and non-ASCII values are rejected. The
/// transport-only `aws-chunked` content encoding is stripped before metadata is
/// stored.
pub(crate) fn collect_upload_metadata(headers: &HeaderMap) -> Result<UploadMetadata, S3Error> {
    Ok(UploadMetadata {
        content_type: optional_header(headers, header::CONTENT_TYPE.as_str())?,
        content_encoding: content_encoding_metadata(headers)?,
        content_disposition: optional_header(headers, header::CONTENT_DISPOSITION.as_str())?,
        content_language: optional_header(headers, header::CONTENT_LANGUAGE.as_str())?,
        cache_control: optional_header(headers, header::CACHE_CONTROL.as_str())?,
        expires: optional_header(headers, header::EXPIRES.as_str())?,
        tagging: optional_header(headers, "x-amz-tagging")?,
        checksum_algorithm: optional_checksum_algorithm(headers)?,
        checksum_type: optional_checksum_type(headers)?,
        user_metadata: collect_user_metadata(headers)?,
    })
}

fn content_encoding_metadata(headers: &HeaderMap) -> Result<Option<String>, S3Error> {
    let Some(value) = optional_header(headers, header::CONTENT_ENCODING.as_str())? else {
        return Ok(None);
    };
    let encodings = value
        .split(',')
        .map(str::trim)
        .filter(|encoding| !encoding.is_empty())
        .filter(|encoding| !encoding.eq_ignore_ascii_case("aws-chunked"))
        .collect::<Vec<_>>();
    Ok((!encodings.is_empty()).then(|| encodings.join(", ")))
}

fn optional_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, S3Error> {
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    if values.len() > 1 {
        return Err(S3Error::invalid_request(format!(
            "{name} must not appear more than once"
        )));
    }
    values
        .first()
        .map(|value| {
            value
                .to_str()
                .map(ToOwned::to_owned)
                .map_err(|_| S3Error::invalid_request(format!("{name} must be valid ASCII")))
        })
        .transpose()
}

fn optional_checksum_algorithm(headers: &HeaderMap) -> Result<Option<ChecksumAlgorithm>, S3Error> {
    let Some(value) = optional_header(headers, "x-amz-checksum-algorithm")? else {
        return Ok(None);
    };
    match value.to_ascii_uppercase().as_str() {
        "CRC32" => Ok(Some(ChecksumAlgorithm::Crc32)),
        "CRC32C" => Ok(Some(ChecksumAlgorithm::Crc32c)),
        "SHA1" => Ok(Some(ChecksumAlgorithm::Sha1)),
        "SHA256" => Ok(Some(ChecksumAlgorithm::Sha256)),
        "SHA512" => Ok(Some(ChecksumAlgorithm::Sha512)),
        _ => Err(S3Error::invalid_request("Checksum algorithm not supported")),
    }
}

fn optional_checksum_type(headers: &HeaderMap) -> Result<Option<ChecksumType>, S3Error> {
    let Some(value) = optional_header(headers, "x-amz-checksum-type")? else {
        return Ok(None);
    };
    match value.to_ascii_uppercase().as_str() {
        "COMPOSITE" => Ok(Some(ChecksumType::Composite)),
        "FULL_OBJECT" => Ok(Some(ChecksumType::FullObject)),
        _ => Err(S3Error::invalid_request(
            "x-amz-checksum-type must be COMPOSITE or FULL_OBJECT",
        )),
    }
}

fn collect_user_metadata(headers: &HeaderMap) -> Result<BTreeMap<String, String>, S3Error> {
    let mut metadata = BTreeMap::new();
    for result in headers.iter().filter_map(|(name, value)| {
        let name = name.as_str();
        if !name.starts_with("x-amz-meta-") {
            return None;
        }
        Some(
            value
                .to_str()
                .map(|value| (name.to_owned(), value.to_owned()))
                .map_err(|_| S3Error::invalid_request(format!("{name} must be valid ASCII"))),
        )
    }) {
        let (name, value) = result?;
        if metadata.insert(name.clone(), value).is_some() {
            return Err(S3Error::invalid_request(format!(
                "{name} must not appear more than once"
            )));
        }
    }
    Ok(metadata)
}
