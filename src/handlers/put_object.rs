use std::collections::BTreeMap;

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use tokio::io::AsyncWriteExt;

use crate::{
    AppState, auth,
    body::upload::write_upload_body,
    config::S3Action,
    error::S3Error,
    handlers::validate_supported_request_body_length,
    s3::{
        target::resolve_s3_target,
        types::{ETag, RequestId},
    },
    storage::{ChecksumAlgorithm, ChecksumType, ObjectMetadata},
};

pub(crate) async fn handle_put_object(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let path = request.uri().path().to_owned();
    let target = resolve_s3_target(
        &path,
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
        state.config.virtual_host_base_domain.as_deref(),
    )
    .map_err(|err| S3Error::invalid_request(err.to_string()).with_resource(path.clone()))?;

    let headers = request.headers().clone();
    validate_supported_request_body_length(&headers).map_err(|error| error.with_resource(path))?;
    validate_upload_headers(&headers)?;
    let auth_context = auth::authenticate(
        &state.auth,
        request.method(),
        request.uri(),
        request.headers(),
    )?;
    auth::authorize(
        &state.auth,
        &auth_context,
        &target.bucket,
        S3Action::PutObject,
    )?;

    let upload_metadata = collect_upload_metadata(&headers)?;
    let _object_writer_permit = state.try_acquire_object_writer()?;
    let _aws_chunked_decoder_permit = state.try_acquire_aws_chunked_decoder(&headers)?;

    let mut temp = state
        .object_store
        .create_temp_object(&target.bucket, &target.key)
        .await
        .map_err(|err| S3Error::internal(format!("failed to create temporary object: {err}")))?;

    let uploaded_body = match write_upload_body(
        &headers,
        request.into_body(),
        &mut temp.writer,
        "object body",
        auth_context.streaming_signing.as_ref(),
        state.config.upload_limits.max_object_size,
    )
    .await
    {
        Ok(uploaded_body) => uploaded_body,
        Err(error) => {
            discard_temp_object(temp, "object body upload failure").await;
            return Err(error);
        }
    };
    if let Err(err) = temp.writer.flush().await {
        discard_temp_object(temp, "object body flush failure").await;
        return Err(S3Error::internal(format!(
            "failed to flush object body: {err}"
        )));
    }

    let etag = ETag::from_hex_md5(hex::encode(&uploaded_body.md5_digest));
    let metadata = ObjectMetadata {
        bucket: target.bucket.clone(),
        key: target.key.clone(),
        size: uploaded_body.size.get(),
        etag: etag.clone(),
        content_type: upload_metadata.content_type,
        content_encoding: upload_metadata.content_encoding,
        content_disposition: upload_metadata.content_disposition,
        content_language: upload_metadata.content_language,
        cache_control: upload_metadata.cache_control,
        expires: upload_metadata.expires,
        tagging: upload_metadata.tagging,
        user_metadata: upload_metadata.user_metadata,
        checksums: uploaded_body.checksums.clone(),
        last_modified: chrono::Utc::now(),
    };

    state
        .object_store
        .commit_object(temp, metadata)
        .await
        .map_err(|err| S3Error::internal(format!("failed to commit object: {err}")))?;

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, etag.as_str())
        .header("x-amz-request-id", request_id.as_str())
        .header(header::CONTENT_LENGTH, "0");
    if !uploaded_body.checksums.is_empty() {
        response = response.header("x-amz-checksum-type", "FULL_OBJECT");
    }
    for (name, value) in &uploaded_body.checksums {
        response = response.header(name, value);
    }
    let response = response
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))?;

    Ok(crate::handlers::s3::record_decoded_body_bytes(
        response,
        uploaded_body.size.get(),
    ))
}

pub(crate) fn validate_upload_headers(headers: &HeaderMap) -> Result<(), S3Error> {
    const UNSUPPORTED_HEADERS: &[&str] = &[
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-aws-kms-key-id",
        "x-amz-server-side-encryption-context",
        "x-amz-server-side-encryption-customer-algorithm",
        "x-amz-server-side-encryption-customer-key",
        "x-amz-server-side-encryption-customer-key-md5",
        "x-amz-object-lock-mode",
        "x-amz-object-lock-retain-until-date",
        "x-amz-object-lock-legal-hold",
        "x-amz-website-redirect-location",
        "x-amz-copy-source",
        "x-amz-copy-source-if-match",
        "x-amz-copy-source-if-none-match",
        "x-amz-copy-source-if-modified-since",
        "x-amz-copy-source-if-unmodified-since",
        "x-amz-copy-source-range",
    ];

    for name in UNSUPPORTED_HEADERS {
        if headers.contains_key(*name) {
            return Err(S3Error::invalid_request(format!(
                "Unsupported upload header: {name}"
            )));
        }
    }

    Ok(())
}

async fn discard_temp_object(temp: crate::storage::TempObjectWriter, reason: &'static str) {
    if let Err(error) = temp.discard().await {
        tracing::debug!(
            reason,
            error = %error,
            "failed to discard temporary object after upload failure"
        );
    }
}

pub(crate) fn collect_upload_metadata(
    headers: &HeaderMap,
) -> Result<crate::storage::UploadMetadata, S3Error> {
    Ok(crate::storage::UploadMetadata {
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
