use axum::{
    Router,
    routing::{any, get},
};

use crate::{AppState, handlers};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health::health))
        .route("/", any(handlers::s3::handle_s3_request))
        .route("/{*path}", any(handlers::s3::handle_s3_request))
        .with_state(state)
}
