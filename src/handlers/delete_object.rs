use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};

use crate::{
    AppState, auth,
    config::S3Action,
    error::S3Error,
    handlers::request::{authorize_request, resolve_request_target, validate_empty_payload_hash},
    s3::types::RequestId,
};

pub(crate) async fn delete_object(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
    auth_context: auth::AuthContext,
) -> Result<Response, S3Error> {
    let target = resolve_request_target(&state, &request)?;
    let key_sha256 = crate::handlers::s3::object_key_sha256(&target.key);
    authorize_request(
        &state,
        &auth_context,
        &target.bucket,
        Some(&target.key),
        S3Action::DeleteObject,
    )?;
    validate_empty_payload_hash(&request)?;

    state
        .object_store
        .delete_object(&target.bucket, &target.key)
        .await
        .map_err(|err| S3Error::internal(format!("failed to delete object: {err}")))?;
    log::info!(
        "object deleted request_id={} bucket={} key_sha256={}",
        request_id,
        target.bucket.as_str(),
        key_sha256
    );

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("x-amz-request-id", request_id.as_str())
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))
}
