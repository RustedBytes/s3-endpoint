use hmac::{Hmac, Mac};
use sha2::Digest;
use std::path::{Path, PathBuf};

pub struct SignatureInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub canonical_query: &'a str,
    pub host: &'a str,
    pub amz_date: &'a str,
    pub payload_hash: &'a str,
    pub signed_headers: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
}

#[allow(dead_code)]
pub struct PresignInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub host: &'a str,
    pub amz_date: &'a str,
    pub expires: u32,
    pub signed_headers: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub session_token: Option<&'a str>,
}

pub fn authorization_header(input: SignatureInput<'_>) -> String {
    let date = &input.amz_date[..8];
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        input.method,
        input.path,
        input.canonical_query,
        canonical_headers_for_signature(&input),
        input.signed_headers,
        input.payload_hash
    );
    let canonical_request_hash = hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}",
        input.amz_date, date, input.region, canonical_request_hash
    );
    let signing_key = signing_key(input.secret_key, date, input.region);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}/{}/s3/aws4_request, SignedHeaders={}, Signature={}",
        input.access_key, date, input.region, input.signed_headers, signature
    )
}

#[allow(dead_code)]
pub fn presigned_url(input: PresignInput<'_>) -> String {
    let date = &input.amz_date[..8];
    let credential = format!(
        "{}/{}/{}/s3/aws4_request",
        input.access_key, date, input.region
    );
    let mut params = vec![
        ("X-Amz-Algorithm".to_owned(), "AWS4-HMAC-SHA256".to_owned()),
        ("X-Amz-Credential".to_owned(), credential),
        ("X-Amz-Date".to_owned(), input.amz_date.to_owned()),
        ("X-Amz-Expires".to_owned(), input.expires.to_string()),
        (
            "X-Amz-SignedHeaders".to_owned(),
            input.signed_headers.to_owned(),
        ),
    ];
    if let Some(session_token) = input.session_token {
        params.push(("X-Amz-Security-Token".to_owned(), session_token.to_owned()));
    }

    let mut encoded_params = params
        .into_iter()
        .map(|(name, value)| {
            (
                aws_uri_encode(name.as_bytes(), false),
                aws_uri_encode(value.as_bytes(), false),
            )
        })
        .collect::<Vec<_>>();
    encoded_params.sort();
    let canonical_query = encoded_params
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
        input.method,
        input.path,
        canonical_query,
        canonical_headers_for_presign(&input),
        input.signed_headers
    );
    let canonical_request_hash = hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}",
        input.amz_date, date, input.region, canonical_request_hash
    );
    let signing_key = signing_key(input.secret_key, date, input.region);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let query = format!("{canonical_query}&X-Amz-Signature={signature}");
    format!("{}?{}", input.path, query)
}

fn canonical_headers_for_signature(input: &SignatureInput<'_>) -> String {
    let mut headers = vec![
        ("host", input.host),
        ("x-amz-content-sha256", input.payload_hash),
        ("x-amz-date", input.amz_date),
    ];
    headers.sort_by(|left, right| left.0.cmp(right.0));
    headers
        .into_iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect()
}

#[allow(dead_code)]
fn canonical_headers_for_presign(input: &PresignInput<'_>) -> String {
    input
        .signed_headers
        .split(';')
        .map(|name| {
            let value = match name {
                "host" => input.host,
                "x-amz-date" => input.amz_date,
                _ => panic!("unsupported signed header in presign test helper: {name}"),
            };
            format!("{name}:{value}\n")
        })
        .collect()
}

fn signing_key(secret_key: &str, date: &str, region: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("valid hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[allow(dead_code)]
fn aws_uri_encode(bytes: &[u8], preserve_slash: bool) -> String {
    let mut encoded = String::new();
    for byte in bytes {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char);
            }
            b'/' if preserve_slash => encoded.push('/'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[allow(dead_code)]
pub fn stored_metadata_path(root: &Path, bucket: &str, key: &str) -> PathBuf {
    let digest = stored_object_digest(bucket, key);
    root.join("metadata")
        .join(&digest[..2])
        .join(format!("{digest}.json"))
}

#[allow(dead_code)]
pub fn stored_object_path(root: &Path, bucket: &str, key: &str) -> PathBuf {
    let digest = stored_object_digest(bucket, key);
    root.join("objects")
        .join(&digest[..2])
        .join(format!("{digest}.data"))
}

#[allow(dead_code)]
pub fn write_orphan_metadata(root: &Path, bucket: &str, key: &str) {
    let metadata_path = stored_metadata_path(root, bucket, key);
    std::fs::create_dir_all(metadata_path.parent().expect("metadata parent"))
        .expect("create metadata dir");
    std::fs::write(
        metadata_path,
        format!(
            "{{\n  \"bucket\": \"{bucket}\",\n  \"key\": \"{key}\",\n  \"size\": 5,\n  \"etag\": \"\\\"5d41402abc4b2a76b9719d911017c592\\\"\",\n  \"user_metadata\": {{}},\n  \"checksums\": {{}},\n  \"last_modified\": \"2026-06-16T00:00:00Z\"\n}}"
        ),
    )
    .expect("write orphaned metadata file");
}

fn stored_object_digest(bucket: &str, key: &str) -> String {
    hex::encode(sha2::Sha256::digest(format!("{bucket}/{key}").as_bytes()))
}
