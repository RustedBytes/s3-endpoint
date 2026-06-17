use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};

use crate::{
    AppState,
    config::S3Action,
    error::S3Error,
    handlers::request::{authenticate_and_authorize_target, validate_empty_payload_hash},
    s3::types::RequestId,
};

pub(crate) async fn delete_object(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let (_, target) =
        authenticate_and_authorize_target(&state, &request, S3Action::DeleteObject).await?;
    validate_empty_payload_hash(&request)?;

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
