use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use sha2::Digest as Sha2Digest;

use crate::{
    AppState, auth,
    body::upload::validate_fixed_sha256_payload_hash,
    config::S3Action,
    error::S3Error,
    s3::{target::resolve_s3_target, types::RequestId},
};

pub(crate) async fn delete_object(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let auth_context = auth::authenticate(
        &state.auth,
        request.method(),
        request.uri(),
        request.headers(),
    )?;
    let path = request.uri().path().to_owned();
    let target = resolve_s3_target(
        &path,
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
        state.config.virtual_host_base_domain.as_deref(),
    )
    .map_err(|err| S3Error::invalid_request(err.to_string()).with_resource(path))?;
    auth::authorize(
        &state.auth,
        &auth_context,
        &target.bucket,
        S3Action::DeleteObject,
    )?;
    let empty_payload_digest = sha2::Sha256::digest([]);
    validate_fixed_sha256_payload_hash(request.headers(), empty_payload_digest.as_ref())?;

    state
        .object_store
        .delete_object(&target.bucket, &target.key)
        .await
        .map_err(|err| S3Error::internal(format!("failed to delete object: {err}")))?;

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("x-amz-request-id", request_id.as_str())
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))
}
