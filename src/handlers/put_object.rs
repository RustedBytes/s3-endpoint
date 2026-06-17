use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode, header},
    response::Response,
};

use crate::{
    AppState,
    body::{
        checksum::checksum_values_for_requested_headers,
        upload::{summarize_staged_upload, write_upload_body},
    },
    config::S3Action,
    error::S3Error,
    handlers::{
        request::{authenticate_request, authorize_request, resolve_request_target},
        upload_metadata::collect_upload_metadata,
        validate_supported_request_body_length,
    },
    middleware::{
        UploadProcessorContext, UploadProcessorOperation, process_staged_upload,
        processors_are_empty,
    },
    s3::types::{ETag, RequestId},
    storage::ObjectMetadata,
};

pub(crate) async fn handle_put_object(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let path = request.uri().path().to_owned();
    let target = resolve_request_target(&state, &request)?;

    let headers = request.headers().clone();
    validate_supported_request_body_length(&headers).map_err(|error| error.with_resource(path))?;
    validate_upload_headers(&headers)?;
    let auth_context = authenticate_request(&state, &request).await?;
    authorize_request(
        &state,
        &auth_context,
        &target.bucket,
        Some(&target.key),
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
    let staged = match temp.finish().await {
        Ok(staged) => staged,
        Err(error) => {
            return Err(S3Error::internal(format!(
                "failed to flush object body: {error}"
            )));
        }
    };

    let context = UploadProcessorContext {
        request_id: request_id.clone(),
        bucket: target.bucket.clone(),
        key: target.key.clone(),
        operation: UploadProcessorOperation::PutObject,
        original_size: uploaded_body.size,
        content_type: upload_metadata.content_type.clone(),
        user_metadata: upload_metadata.user_metadata.clone(),
    };
    let staged = match process_staged_upload(state.upload_processors(), staged, context).await {
        Ok(staged) => staged,
        Err(error) => {
            return Err(error);
        }
    };
    let final_body = match summarize_staged_upload(staged.path()).await {
        Ok(final_body) => final_body,
        Err(error) => {
            let _ = staged.discard().await;
            return Err(error);
        }
    };
    if final_body.size.get() > state.config.upload_limits.max_object_size {
        let _ = staged.discard().await;
        return Err(S3Error::entity_too_large(
            "Your proposed upload exceeds the maximum allowed size.",
        ));
    }

    let etag = ETag::from_hex_md5(hex::encode(&final_body.digests.md5));
    let response_checksums = if processors_are_empty(state.upload_processors()) {
        uploaded_body.checksums.clone()
    } else {
        checksum_values_for_requested_headers(&uploaded_body.checksums, &final_body.digests)
    };
    let metadata = ObjectMetadata {
        bucket: target.bucket.clone(),
        key: target.key.clone(),
        size: final_body.size.get(),
        etag: etag.clone(),
        content_type: upload_metadata.content_type,
        content_encoding: upload_metadata.content_encoding,
        content_disposition: upload_metadata.content_disposition,
        content_language: upload_metadata.content_language,
        cache_control: upload_metadata.cache_control,
        expires: upload_metadata.expires,
        tagging: upload_metadata.tagging,
        user_metadata: upload_metadata.user_metadata,
        checksums: response_checksums.clone(),
        last_modified: chrono::Utc::now(),
    };

    state
        .object_store
        .commit_staged_object(staged, metadata)
        .await
        .map_err(|err| S3Error::internal(format!("failed to commit object: {err}")))?;

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, etag.as_str())
        .header("x-amz-request-id", request_id.as_str())
        .header(header::CONTENT_LENGTH, "0");
    if !response_checksums.is_empty() {
        response = response.header("x-amz-checksum-type", "FULL_OBJECT");
    }
    for (name, value) in &response_checksums {
        response = response.header(name, value);
    }
    let response = response
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))?;

    Ok(crate::handlers::s3::record_decoded_body_bytes(
        response,
        final_body.size.get(),
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
