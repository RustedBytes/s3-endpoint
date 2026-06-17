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
    s3::{target::resolve_bucket_name, types::RequestId},
};

pub(crate) async fn head_bucket(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let auth_context = authenticate_request(&state, &request)?;
    let path = request.uri().path().to_owned();
    let bucket = resolve_bucket_name(
        &path,
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
        state.config.virtual_host_base_domain.as_deref(),
    )
    .map_err(|err| S3Error::invalid_request(err.to_string()).with_resource(path))?;
    auth::authorize(&state.auth, &auth_context, &bucket, S3Action::HeadBucket)?;
    let empty_payload_digest = sha2::Sha256::digest([]);
    validate_fixed_sha256_payload_hash(request.headers(), empty_payload_digest.as_ref())?;

    Response::builder()
        .status(StatusCode::OK)
        .header("x-amz-request-id", request_id.as_str())
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))
}

fn authenticate_request(
    state: &AppState,
    request: &Request<Body>,
) -> Result<auth::AuthContext, S3Error> {
    auth::authenticate(
        &state.auth,
        request.method(),
        request.uri(),
        request.headers(),
    )
}
