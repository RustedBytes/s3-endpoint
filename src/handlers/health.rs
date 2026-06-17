use axum::http::StatusCode;

/// Returns a successful readiness response for the health endpoint.
pub async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}
