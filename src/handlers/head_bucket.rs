use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};

use crate::{
    AppState,
    config::S3Action,
    error::S3Error,
    handlers::request::{
        authenticate_request, authorize_request, resolve_request_bucket,
        validate_empty_payload_hash,
    },
    s3::types::RequestId,
};

pub(crate) async fn head_bucket(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let auth_context = authenticate_request(&state, &request)?;
    let bucket = resolve_request_bucket(&state, &request)?;
    authorize_request(&state, &auth_context, &bucket, None, S3Action::HeadBucket)?;
    validate_empty_payload_hash(&request)?;

    Response::builder()
        .status(StatusCode::OK)
        .header("x-amz-request-id", request_id.as_str())
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))
}
