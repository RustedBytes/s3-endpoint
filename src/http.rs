use axum::{
    Router,
    routing::{any, get},
};

use crate::{AppState, handlers};

#[derive(Clone, Debug)]
pub(crate) struct RouterOptions {
    pub health_path: Option<String>,
}

pub fn router(state: AppState) -> Router {
    router_with_options(
        state,
        RouterOptions {
            health_path: Some("/health".to_owned()),
        },
    )
}

pub(crate) fn router_with_options(state: AppState, options: RouterOptions) -> Router {
    let router = Router::new()
        .route("/", any(handlers::s3::handle_s3_request))
        .route("/{*path}", any(handlers::s3::handle_s3_request));
    let router = if let Some(path) = options.health_path {
        router.route(&path, get(handlers::health::health))
    } else {
        router
    };
    router.with_state(state)
}
