use std::collections::{BTreeMap, BTreeSet};

use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use crate::error::S3Error;

const UNSUPPORTED_CHECKSUM_HEADERS: &[&str] = &[
    "x-amz-checksum-crc64nvme",
    "x-amz-checksum-xxhash64",
    "x-amz-checksum-xxhash3",
    "x-amz-checksum-xxhash128",
];
const CHECKSUM_HEADERS: &[&str] = &["content-md5"];
const SDK_CHECKSUM_ALGORITHM_HEADER: &str = "x-amz-sdk-checksum-algorithm";
const CHECKSUM_NAMES: &[ChecksumName] = &[
    ChecksumName::Crc32,
    ChecksumName::Crc32c,
    ChecksumName::Sha1,
    ChecksumName::Sha256,
    ChecksumName::Sha512,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChecksumName {
    Crc32,
    Crc32c,
    Sha1,
    Sha256,
    Sha512,
}

impl ChecksumName {
    pub(crate) fn header_name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
            Self::Sha512 => "x-amz-checksum-sha512",
        }
    }

    pub(crate) fn xml_element_name(self) -> &'static str {
        match self {
            Self::Crc32 => "ChecksumCRC32",
            Self::Crc32c => "ChecksumCRC32C",
            Self::Sha1 => "ChecksumSHA1",
            Self::Sha256 => "ChecksumSHA256",
            Self::Sha512 => "ChecksumSHA512",
        }
    }

    fn expected_len(self) -> usize {
        match self {
            Self::Crc32 | Self::Crc32c => 4,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    pub(crate) fn from_header_name(name: &str) -> Option<Self> {
        CHECKSUM_NAMES
            .iter()
            .copied()
            .find(|checksum| checksum.header_name() == name)
    }

    fn from_sdk_algorithm(algorithm: &str) -> Option<Self> {
        match algorithm.to_ascii_uppercase().as_str() {
            "CRC32" => Some(Self::Crc32),
            "CRC32C" => Some(Self::Crc32c),
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn encode_digest(self, digests: &ChecksumDigests) -> String {
        match self {
            Self::Crc32 => BASE64.encode(digests.crc32.to_be_bytes()),
            Self::Crc32c => BASE64.encode(digests.crc32c.to_be_bytes()),
            Self::Sha1 => BASE64.encode(&digests.sha1),
            Self::Sha256 => BASE64.encode(&digests.sha256),
            Self::Sha512 => BASE64.encode(&digests.sha512),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChecksumRequest {
    content_md5: Option<Vec<u8>>,
    checksum_crc32: Option<Vec<u8>>,
    checksum_crc32c: Option<Vec<u8>>,
    checksum_sha1: Option<Vec<u8>>,
    checksum_sha256: Option<Vec<u8>>,
    checksum_sha512: Option<Vec<u8>>,
    checksum_values: BTreeMap<String, String>,
}

impl ChecksumRequest {
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, S3Error> {
        Self::from_headers_and_trailers(headers, &BTreeMap::new())
    }

    pub fn from_headers_and_trailers(
        headers: &HeaderMap,
        trailers: &BTreeMap<String, String>,
    ) -> Result<Self, S3Error> {
        reject_unsupported_checksum_inputs(headers, trailers)?;
        reject_duplicate_checksum_inputs(headers, trailers)?;
        validate_declared_checksum_trailers(headers, trailers)?;
        let content_md5 = optional_base64_header(headers, trailers, "content-md5", 16)?;
        let checksum_crc32 = optional_checksum(headers, trailers, ChecksumName::Crc32)?;
        let checksum_crc32c = optional_checksum(headers, trailers, ChecksumName::Crc32c)?;
        let checksum_sha1 = optional_checksum(headers, trailers, ChecksumName::Sha1)?;
        let checksum_sha256 = optional_checksum(headers, trailers, ChecksumName::Sha256)?;
        let checksum_sha512 = optional_checksum(headers, trailers, ChecksumName::Sha512)?;
        let checksum_values = checksum_values(headers, trailers)?;
        validate_sdk_checksum_algorithm(headers, trailers)?;
        Ok(Self {
            content_md5,
            checksum_crc32,
            checksum_crc32c,
            checksum_sha1,
            checksum_sha256,
            checksum_sha512,
            checksum_values,
        })
    }

    pub fn validate(&self, digests: &ChecksumDigests) -> Result<(), S3Error> {
        if let Some(expected) = &self.content_md5
            && expected.as_slice() != digests.md5.as_slice()
        {
            return Err(S3Error::bad_digest(
                "The Content-MD5 you specified did not match what we received.",
            ));
        }

        if let Some(expected) = &self.checksum_crc32
            && expected.as_slice() != digests.crc32.to_be_bytes()
        {
            return Err(S3Error::bad_digest(
                "The provided x-amz-checksum header does not match what was computed.",
            ));
        }

        if let Some(expected) = &self.checksum_crc32c
            && expected.as_slice() != digests.crc32c.to_be_bytes()
        {
            return Err(S3Error::bad_digest(
                "The provided x-amz-checksum header does not match what was computed.",
            ));
        }

        if let Some(expected) = &self.checksum_sha1
            && expected.as_slice() != digests.sha1.as_slice()
        {
            return Err(S3Error::bad_digest(
                "The provided x-amz-checksum header does not match what was computed.",
            ));
        }

        if let Some(expected) = &self.checksum_sha256
            && expected.as_slice() != digests.sha256.as_slice()
        {
            return Err(S3Error::bad_digest(
                "The provided x-amz-checksum header does not match what was computed.",
            ));
        }

        if let Some(expected) = &self.checksum_sha512
            && expected.as_slice() != digests.sha512.as_slice()
        {
            return Err(S3Error::bad_digest(
                "The provided x-amz-checksum header does not match what was computed.",
            ));
        }

        Ok(())
    }

    pub fn checksum_values(&self) -> BTreeMap<String, String> {
        self.checksum_values.clone()
    }

    pub(crate) fn checksum_values_for_digests(
        &self,
        digests: &ChecksumDigests,
    ) -> BTreeMap<String, String> {
        let mut values = BTreeMap::new();
        if self.checksum_crc32.is_some() {
            values.insert(
                ChecksumName::Crc32.header_name().to_owned(),
                ChecksumName::Crc32.encode_digest(digests),
            );
        }
        if self.checksum_crc32c.is_some() {
            values.insert(
                ChecksumName::Crc32c.header_name().to_owned(),
                ChecksumName::Crc32c.encode_digest(digests),
            );
        }
        if self.checksum_sha1.is_some() {
            values.insert(
                ChecksumName::Sha1.header_name().to_owned(),
                ChecksumName::Sha1.encode_digest(digests),
            );
        }
        if self.checksum_sha256.is_some() {
            values.insert(
                ChecksumName::Sha256.header_name().to_owned(),
                ChecksumName::Sha256.encode_digest(digests),
            );
        }
        if self.checksum_sha512.is_some() {
            values.insert(
                ChecksumName::Sha512.header_name().to_owned(),
                ChecksumName::Sha512.encode_digest(digests),
            );
        }
        values
    }

    pub(crate) fn requires_md5(&self) -> bool {
        self.content_md5.is_some()
    }

    pub(crate) fn requires_crc32(&self) -> bool {
        self.checksum_crc32.is_some()
    }

    pub(crate) fn requires_crc32c(&self) -> bool {
        self.checksum_crc32c.is_some()
    }

    pub(crate) fn requires_sha1(&self) -> bool {
        self.checksum_sha1.is_some()
    }

    pub(crate) fn requires_sha256(&self) -> bool {
        self.checksum_sha256.is_some()
    }

    pub(crate) fn requires_sha512(&self) -> bool {
        self.checksum_sha512.is_some()
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChecksumDigests {
    pub md5: Vec<u8>,
    pub sha1: Vec<u8>,
    pub sha256: Vec<u8>,
    pub sha512: Vec<u8>,
    pub crc32: u32,
    pub crc32c: u32,
}

pub(crate) fn checksum_values_for_requested_headers(
    requested: &BTreeMap<String, String>,
    digests: &ChecksumDigests,
) -> BTreeMap<String, String> {
    requested
        .keys()
        .filter_map(|name| {
            let value = ChecksumName::from_header_name(name)?.encode_digest(digests);
            Some((name.clone(), value))
        })
        .collect()
}

fn checksum_values(
    headers: &HeaderMap,
    trailers: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, S3Error> {
    CHECKSUM_NAMES
        .iter()
        .copied()
        .filter_map(|checksum| {
            let name = checksum.header_name();
            let value =
                if let Some(value) = headers.get(name) {
                    Some(value.to_str().map_err(|_| {
                        S3Error::invalid_request(format!("{name} must be valid ASCII"))
                    }))
                } else {
                    trailers.get(name).map(|value| Ok(value.as_str()))
                }?;
            Some(value.map(|value| (name.to_owned(), value.to_owned())))
        })
        .collect()
}

fn optional_checksum(
    headers: &HeaderMap,
    trailers: &BTreeMap<String, String>,
    checksum: ChecksumName,
) -> Result<Option<Vec<u8>>, S3Error> {
    optional_base64_header(
        headers,
        trailers,
        checksum.header_name(),
        checksum.expected_len(),
    )
}

fn optional_base64_header(
    headers: &HeaderMap,
    trailers: &BTreeMap<String, String>,
    name: &str,
    expected_len: usize,
) -> Result<Option<Vec<u8>>, S3Error> {
    let value = if let Some(value) = headers.get(name) {
        value
            .to_str()
            .map_err(|_| S3Error::invalid_request(format!("{name} must be valid ASCII")))?
            .to_owned()
    } else if let Some(value) = trailers.get(name) {
        value.clone()
    } else {
        return Ok(None);
    };
    let decoded = BASE64
        .decode(value)
        .map_err(|_| S3Error::invalid_request(format!("{name} must be base64-encoded")))?;
    if decoded.len() != expected_len {
        return Err(S3Error::invalid_request(format!(
            "{name} must decode to {expected_len} bytes"
        )));
    }
    Ok(Some(decoded))
}

fn validate_sdk_checksum_algorithm(
    headers: &HeaderMap,
    trailers: &BTreeMap<String, String>,
) -> Result<(), S3Error> {
    let mut values = headers.get_all(SDK_CHECKSUM_ALGORITHM_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(S3Error::invalid_request(format!(
            "{SDK_CHECKSUM_ALGORITHM_HEADER} must not appear more than once"
        )));
    }
    let algorithm = value.to_str().map_err(|_| {
        S3Error::invalid_request(format!(
            "{SDK_CHECKSUM_ALGORITHM_HEADER} must be valid ASCII"
        ))
    })?;

    let checksum_header_name = ChecksumName::from_sdk_algorithm(algorithm)
        .ok_or_else(|| S3Error::invalid_request("Checksum algorithm not supported"))?
        .header_name();

    if headers.get(checksum_header_name).is_none() && !trailers.contains_key(checksum_header_name) {
        return Err(S3Error::invalid_request(format!(
            "{SDK_CHECKSUM_ALGORITHM_HEADER} requires a matching checksum header or trailer"
        )));
    }

    Ok(())
}

fn reject_unsupported_checksum_inputs(
    headers: &HeaderMap,
    trailers: &BTreeMap<String, String>,
) -> Result<(), S3Error> {
    for name in UNSUPPORTED_CHECKSUM_HEADERS {
        if headers.contains_key(*name) || trailers.contains_key(*name) {
            return Err(S3Error::invalid_request("Checksum algorithm not supported"));
        }
    }

    Ok(())
}

fn reject_duplicate_checksum_inputs(
    headers: &HeaderMap,
    trailers: &BTreeMap<String, String>,
) -> Result<(), S3Error> {
    for name in CHECKSUM_HEADERS
        .iter()
        .copied()
        .chain(CHECKSUM_NAMES.iter().map(|checksum| checksum.header_name()))
    {
        if headers.get_all(name).iter().count() > 1 {
            return Err(S3Error::invalid_request(format!(
                "{name} must not appear more than once"
            )));
        }
    }

    for checksum in CHECKSUM_NAMES {
        let name = checksum.header_name();
        if headers.contains_key(name) && trailers.contains_key(name) {
            return Err(S3Error::invalid_request(format!(
                "{name} must not be supplied as both header and trailer"
            )));
        }
    }

    Ok(())
}

fn validate_declared_checksum_trailers(
    headers: &HeaderMap,
    trailers: &BTreeMap<String, String>,
) -> Result<(), S3Error> {
    let mut values = headers.get_all("x-amz-trailer").iter();
    let Some(value) = values.next() else {
        return reject_undeclared_checksum_trailers(&BTreeSet::new(), trailers);
    };
    if values.next().is_some() {
        return Err(S3Error::invalid_request(
            "x-amz-trailer must not appear more than once",
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| S3Error::invalid_request("x-amz-trailer must be valid ASCII"))?;

    let mut declared_names = BTreeSet::new();
    for declared_name in value.split(',') {
        let declared_name = declared_name.trim().to_ascii_lowercase();
        if declared_name.is_empty() {
            return Err(S3Error::invalid_request(
                "x-amz-trailer contains an empty trailer name",
            ));
        }
        if !declared_names.insert(declared_name.clone()) {
            return Err(S3Error::invalid_request(format!(
                "x-amz-trailer declares trailer more than once: {declared_name}"
            )));
        }
        if UNSUPPORTED_CHECKSUM_HEADERS.contains(&declared_name.as_str()) {
            return Err(S3Error::invalid_request("Checksum algorithm not supported"));
        }
        if ChecksumName::from_header_name(&declared_name).is_none() {
            return Err(S3Error::invalid_request(format!(
                "x-amz-trailer contains unsupported trailer name: {declared_name}"
            )));
        }
        if !trailers.contains_key(declared_name.as_str()) {
            return Err(S3Error::invalid_request(format!(
                "Declared checksum trailer was not received: {declared_name}"
            )));
        }
    }

    reject_undeclared_checksum_trailers(&declared_names, trailers)
}

fn reject_undeclared_checksum_trailers(
    declared_names: &BTreeSet<String>,
    trailers: &BTreeMap<String, String>,
) -> Result<(), S3Error> {
    for checksum in CHECKSUM_NAMES {
        let name = checksum.header_name();
        if trailers.contains_key(name) && !declared_names.contains(name) {
            return Err(S3Error::invalid_request(format!(
                "Checksum trailer was not declared: {name}"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn checksum_request_rejects_duplicate_declared_trailer_names() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-trailer",
            HeaderValue::from_static("x-amz-checksum-crc32, X-Amz-Checksum-Crc32"),
        );
        let mut trailers = BTreeMap::new();
        trailers.insert("x-amz-checksum-crc32".to_owned(), "AAAAAA==".to_owned());

        let error = ChecksumRequest::from_headers_and_trailers(&headers, &trailers)
            .expect_err("duplicate trailer declaration");

        assert!(
            format!("{error:?}")
                .contains("x-amz-trailer declares trailer more than once: x-amz-checksum-crc32")
        );
    }

    #[test]
    fn checksum_request_rejects_duplicate_trailer_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-trailer",
            HeaderValue::from_static("x-amz-checksum-crc32"),
        );
        headers.append(
            "x-amz-trailer",
            HeaderValue::from_static("x-amz-checksum-crc32c"),
        );
        let mut trailers = BTreeMap::new();
        trailers.insert("x-amz-checksum-crc32".to_owned(), "AAAAAA==".to_owned());

        let error = ChecksumRequest::from_headers_and_trailers(&headers, &trailers)
            .expect_err("duplicate x-amz-trailer header");

        assert!(format!("{error:?}").contains("x-amz-trailer must not appear more than once"));
    }

    #[test]
    fn checksum_request_rejects_duplicate_checksum_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-md5",
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
        );
        headers.append(
            "content-md5",
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
        );

        let error = ChecksumRequest::from_headers(&headers).expect_err("duplicate checksum header");

        assert!(format!("{error:?}").contains("content-md5 must not appear more than once"));
    }

    #[test]
    fn checksum_request_rejects_duplicate_sdk_checksum_algorithm_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-sdk-checksum-algorithm",
            HeaderValue::from_static("CRC32"),
        );
        headers.append(
            "x-amz-sdk-checksum-algorithm",
            HeaderValue::from_static("CRC32"),
        );
        headers.insert("x-amz-checksum-crc32", HeaderValue::from_static("AAAAAA=="));

        let error =
            ChecksumRequest::from_headers(&headers).expect_err("duplicate SDK checksum algorithm");

        assert!(
            format!("{error:?}")
                .contains("x-amz-sdk-checksum-algorithm must not appear more than once")
        );
    }

    #[test]
    fn checksum_request_reports_required_digest_states() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-md5",
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
        );
        headers.insert("x-amz-checksum-crc32", HeaderValue::from_static("AAAAAA=="));
        headers.insert(
            "x-amz-checksum-sha256",
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        );
        let request = ChecksumRequest::from_headers(&headers).expect("checksum request");

        assert!(request.requires_md5());
        assert!(request.requires_crc32());
        assert!(!request.requires_crc32c());
        assert!(!request.requires_sha1());
        assert!(request.requires_sha256());
        assert!(!request.requires_sha512());
    }
}
