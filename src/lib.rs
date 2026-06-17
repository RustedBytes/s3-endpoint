//! S3-compatible upload endpoint implementation.
//!
//! The crate exposes an Axum router plus typed configuration, authentication,
//! storage, and S3-domain modules for a focused S3-compatible subset:
//! single-object upload, multipart upload, object reads/metadata, deletion,
//! SigV4 header authentication, presigned URLs, and aws-chunked bodies.

#![forbid(unsafe_code)]

pub(crate) mod auth;
pub(crate) mod body;
/// Runtime configuration, credentials, authorization policy, and upload limits.
pub mod config;
/// S3 XML error construction and HTTP response conversion.
pub mod error;
pub(crate) mod handlers;
/// Developer tuning hooks for embedded applications.
pub mod hooks;
pub(crate) mod http;
/// S3-aware upload middleware extension points.
pub mod middleware;
/// S3 request target parsing and validated domain value types.
pub mod s3;
/// Filesystem-backed object and multipart storage types.
pub mod storage;

use std::{convert::Infallible, future::Future, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request},
    response::IntoResponse,
    routing::Route,
};
use hooks::{
    AuthenticationProvider, AuthenticationRequest, AuthenticationResult, AuthorizationContext,
    AuthorizationPolicy, ErrorMapper, RequestIdFactory, RequestObserver, S3ErrorContext,
    S3RequestContext, SharedAuthenticationProvider, SharedAuthorizationPolicy, SharedErrorMapper,
    SharedRequestIdFactory, SharedRequestObserver,
};
use middleware::{
    SharedUploadProcessor, UploadProcessor, UploadProcessorAction, UploadProcessorError,
    UploadProcessorFn, UploadProcessorHandle,
};
use storage::{FileMultipartStore, FileObjectStore};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::{Layer, Service};

#[derive(Clone)]
/// Shared application state for the S3 endpoint.
///
/// `AppState` owns validated configuration, credential state, filesystem-backed
/// object and multipart stores, and bounded admission controls. Construct it
/// with [`AppState::new`] or [`AppState::builder`] and pass it to [`router`] to
/// build the HTTP service.
pub struct AppState {
    /// Validated runtime configuration.
    pub config: config::Config,
    /// Credential lookup and authorization state.
    pub auth: Arc<config::AuthState>,
    /// Filesystem-backed committed object store.
    pub object_store: Arc<FileObjectStore>,
    /// Filesystem-backed multipart upload store.
    pub multipart_store: Arc<FileMultipartStore>,
    pub(crate) upload_processors: Arc<Vec<SharedUploadProcessor>>,
    request_observer: Option<SharedRequestObserver>,
    error_mapper: Option<SharedErrorMapper>,
    request_id_factory: SharedRequestIdFactory,
    authentication_provider: Option<SharedAuthenticationProvider>,
    authorization_policy: Option<SharedAuthorizationPolicy>,
    admission: Arc<AdmissionControl>,
}

impl AppState {
    /// Creates a builder for application state with optional upload processors.
    pub fn builder(config: config::Config) -> AppBuilder {
        AppBuilder {
            config,
            upload_processors: Vec::new(),
            request_observer: None,
            error_mapper: None,
            request_id_factory: Arc::new(s3::types::RequestId::new),
            authentication_provider: None,
            authorization_policy: None,
            health_path: Some("/health".to_owned()),
            router_layers: Vec::new(),
        }
    }

    /// Builds application state from configuration.
    ///
    /// This validates configuration and credentials, initializes storage
    /// directories, removes stale temporary/orphaned files, and creates bounded
    /// admission controls. Returns an error when configuration is invalid or
    /// storage cannot be initialized.
    pub async fn new(config: config::Config) -> Result<Self, AppInitError> {
        Self::builder(config).build().await
    }

    async fn from_builder(builder: AppBuilder) -> Result<Self, AppInitError> {
        let AppBuilder {
            config,
            upload_processors,
            request_observer,
            error_mapper,
            request_id_factory,
            authentication_provider,
            authorization_policy,
            health_path: _,
            router_layers: _,
        } = builder;
        config.validate()?;
        let upload_limits = config.upload_limits.validated()?;
        let auth = Arc::new(config::AuthState::new(&config.auth)?);
        let object_store = Arc::new(FileObjectStore::new(config.storage_root.clone()).await?);
        let multipart_store = Arc::new(FileMultipartStore::new(config.storage_root.clone()).await?);
        Ok(Self {
            config,
            auth,
            object_store,
            multipart_store,
            upload_processors: Arc::new(upload_processors),
            request_observer,
            error_mapper,
            request_id_factory,
            authentication_provider,
            authorization_policy,
            admission: Arc::new(AdmissionControl::new(&upload_limits)),
        })
    }

    pub(crate) fn upload_processors(&self) -> &[SharedUploadProcessor] {
        &self.upload_processors
    }

    pub(crate) fn request_id(&self) -> s3::types::RequestId {
        self.request_id_factory.request_id()
    }

    pub(crate) async fn authenticate_with_provider(
        &self,
        request: AuthenticationRequest,
    ) -> Option<Result<AuthenticationResult, error::S3Error>> {
        let provider = self.authentication_provider.as_ref()?;
        Some(provider.authenticate(request).await)
    }

    pub(crate) async fn observe_request(&self, context: S3RequestContext) {
        if let Some(observer) = &self.request_observer {
            observer.observe(context).await;
        }
    }

    pub(crate) async fn map_error(
        &self,
        context: S3ErrorContext,
        error: error::S3Error,
    ) -> error::S3Error {
        if let Some(mapper) = &self.error_mapper {
            mapper.map_error(context, error).await
        } else {
            error
        }
    }

    pub(crate) fn authorize_with_policy(
        &self,
        context: AuthorizationContext,
    ) -> Result<(), error::S3Error> {
        if let Some(policy) = &self.authorization_policy {
            policy.authorize(context)
        } else {
            Ok(())
        }
    }

    pub(crate) fn try_acquire_s3_request(&self) -> Result<OwnedSemaphorePermit, error::S3Error> {
        self.admission
            .s3_requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                error::S3Error::slow_down("too many active S3 requests; retry the request")
            })
    }

    pub(crate) fn try_acquire_object_writer(&self) -> Result<OwnedSemaphorePermit, error::S3Error> {
        self.admission
            .object_writers
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                error::S3Error::slow_down("too many active object uploads; retry the request")
            })
    }

    pub(crate) fn try_acquire_multipart_part_writer(
        &self,
    ) -> Result<OwnedSemaphorePermit, error::S3Error> {
        self.admission
            .multipart_part_writers
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                error::S3Error::slow_down(
                    "too many active multipart part uploads; retry the request",
                )
            })
    }

    pub(crate) fn try_acquire_aws_chunked_decoder(
        &self,
        headers: &HeaderMap,
    ) -> Result<Option<OwnedSemaphorePermit>, error::S3Error> {
        if !body::upload::is_aws_chunked_request(headers) {
            return Ok(None);
        }
        self.admission
            .aws_chunked_decoders
            .clone()
            .try_acquire_owned()
            .map(Some)
            .map_err(|_| {
                error::S3Error::slow_down("too many active aws-chunked uploads; retry the request")
            })
    }
}

/// Builder for [`AppState`].
pub struct AppBuilder {
    config: config::Config,
    upload_processors: Vec<SharedUploadProcessor>,
    request_observer: Option<SharedRequestObserver>,
    error_mapper: Option<SharedErrorMapper>,
    request_id_factory: SharedRequestIdFactory,
    authentication_provider: Option<SharedAuthenticationProvider>,
    authorization_policy: Option<SharedAuthorizationPolicy>,
    health_path: Option<String>,
    router_layers: Vec<RouterTransform>,
}

type RouterTransform = Arc<dyn Fn(Router) -> Router + Send + Sync>;

impl AppBuilder {
    /// Registers an upload processor.
    ///
    /// Processors run sequentially in registration order after decoded upload
    /// bytes have been validated and before the final object is committed.
    pub fn upload_processor<P>(mut self, processor: P) -> Self
    where
        P: UploadProcessor,
    {
        self.upload_processors.push(Arc::new(processor));
        self
    }

    /// Registers a closure-backed upload processor.
    ///
    /// The closure receives an owned [`UploadProcessorHandle`] so common async
    /// closures do not need to name [`futures_util::future::BoxFuture`].
    pub fn upload_processor_fn<F, Fut>(mut self, name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(UploadProcessorHandle) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<UploadProcessorAction, UploadProcessorError>> + Send + 'static,
    {
        self.upload_processors
            .push(Arc::new(UploadProcessorFn::new(name, handler)));
        self
    }

    /// Sets the health-check route path used by [`Self::build_router`].
    pub fn health_path(mut self, path: impl Into<String>) -> Self {
        self.health_path = Some(path.into());
        self
    }

    /// Disables the health-check route used by [`Self::build_router`].
    pub fn disable_health_route(mut self) -> Self {
        self.health_path = None;
        self
    }

    /// Applies a Tower layer to routers built by [`Self::build_router`].
    pub fn router_layer<L>(mut self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: Service<Request<Body>> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request<Body>>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request<Body>>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request<Body>>>::Future: Send + 'static,
    {
        self.router_layers
            .push(Arc::new(move |router| router.layer(layer.clone())));
        self
    }

    /// Registers a read-only request observer.
    pub fn on_request<O>(mut self, observer: O) -> Self
    where
        O: RequestObserver,
    {
        self.request_observer = Some(Arc::new(observer));
        self
    }

    /// Registers an S3 error mapper.
    pub fn on_error<M>(mut self, mapper: M) -> Self
    where
        M: ErrorMapper,
    {
        self.error_mapper = Some(Arc::new(mapper));
        self
    }

    /// Sets the request ID factory used for S3 responses and hooks.
    pub fn request_id_factory<F>(mut self, factory: F) -> Self
    where
        F: RequestIdFactory,
    {
        self.request_id_factory = Arc::new(factory);
        self
    }

    /// Registers a custom authentication provider.
    ///
    /// When configured, this provider replaces the built-in static SigV4 and
    /// anonymous authentication path. Built-in SigV4 remains the default when
    /// no custom provider is registered.
    pub fn authentication_provider<P>(mut self, provider: P) -> Self
    where
        P: AuthenticationProvider,
    {
        self.authentication_provider = Some(Arc::new(provider));
        self
    }

    /// Registers an additional authorization policy.
    pub fn authorization_policy<P>(mut self, policy: P) -> Self
    where
        P: AuthorizationPolicy,
    {
        self.authorization_policy = Some(Arc::new(policy));
        self
    }

    /// Builds application state.
    pub async fn build(self) -> Result<AppState, AppInitError> {
        AppState::from_builder(self).await
    }

    /// Builds application state and returns an Axum router.
    pub async fn build_router(self) -> Result<Router, AppInitError> {
        let health_path = self.health_path.clone();
        let router_layers = self.router_layers.clone();
        validate_health_path(health_path.as_deref())?;
        let state = AppState::from_builder(self).await?;
        let mut router = http::router_with_options(state, http::RouterOptions { health_path });
        for layer in router_layers {
            router = layer(router);
        }
        Ok(router)
    }
}

fn validate_health_path(path: Option<&str>) -> Result<(), AppInitError> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.starts_with('/') && path.len() > 1 && !path.contains('*') {
        Ok(())
    } else {
        Err(AppInitError::RouterConfig(
            "health path must start with '/' and must not contain wildcards".to_owned(),
        ))
    }
}

struct AdmissionControl {
    s3_requests: Arc<Semaphore>,
    object_writers: Arc<Semaphore>,
    multipart_part_writers: Arc<Semaphore>,
    aws_chunked_decoders: Arc<Semaphore>,
}

impl AdmissionControl {
    fn new(limits: &config::ValidatedUploadLimits) -> Self {
        Self {
            s3_requests: Arc::new(Semaphore::new(limits.max_concurrent_s3_requests.get())),
            object_writers: Arc::new(Semaphore::new(limits.max_active_object_writers.get())),
            multipart_part_writers: Arc::new(Semaphore::new(
                limits.max_active_multipart_part_writers.get(),
            )),
            aws_chunked_decoders: Arc::new(Semaphore::new(
                limits.max_active_aws_chunked_decoders.get(),
            )),
        }
    }
}

#[derive(Debug, Error)]
/// Errors returned while initializing [`AppState`].
pub enum AppInitError {
    /// Configuration or credential validation failed.
    #[error("invalid configuration")]
    Config(#[from] config::ConfigError),

    /// Storage initialization or cleanup failed.
    #[error("failed to initialize storage")]
    Store(#[from] storage::StoreError),

    /// Router tuning configuration is invalid.
    #[error("invalid router configuration: {0}")]
    RouterConfig(String),
}

/// Builds the Axum router for the S3 endpoint.
///
/// The returned router contains the health route and S3 operation dispatcher.
/// It does not bind sockets; callers choose how to serve it.
pub fn router(state: AppState) -> Router {
    http::router(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    };
    use futures_util::future::BoxFuture;
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[tokio::test]
    async fn app_state_rejects_invalid_upload_limits() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let result = AppState::new(config::Config {
            storage_root: temp_dir.path().to_path_buf(),
            auth: Default::default(),
            virtual_host_base_domain: None,
            upload_limits: config::UploadLimits {
                max_object_size: 1,
                max_part_size: 0,
                min_non_final_part_size: 1,
                ..Default::default()
            },
        })
        .await;

        let Err(error) = result else {
            panic!("invalid config should fail");
        };

        assert!(matches!(
            error,
            AppInitError::Config(config::ConfigError::InvalidUploadLimit(
                "max_part_size must be greater than 0"
            ))
        ));
    }

    #[tokio::test]
    async fn app_state_builder_registers_upload_processors_in_order() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::builder(config::Config {
            storage_root: temp_dir.path().to_path_buf(),
            auth: Default::default(),
            virtual_host_base_domain: None,
            upload_limits: Default::default(),
        })
        .upload_processor(NamedProcessor("first"))
        .upload_processor(NamedProcessor("second"))
        .build()
        .await
        .expect("create app state");

        assert_eq!(state.upload_processors.len(), 2);
    }

    #[tokio::test]
    async fn app_state_builder_registers_upload_processor_fn() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::builder(config::Config::new(temp_dir.path().to_path_buf()))
            .upload_processor_fn("keep", |upload| async move { Ok(upload.keep()) })
            .build()
            .await
            .expect("create app state");

        assert_eq!(state.upload_processors.len(), 1);
    }

    #[tokio::test]
    async fn build_router_serves_custom_health_path_and_s3_routes() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .health_path("/ready")
        .build_router()
        .await
        .expect("router");

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/ready")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("health response");
        assert_eq!(health.status(), StatusCode::NO_CONTENT);

        let head_bucket = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/test-bucket")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("head bucket response");
        assert_eq!(head_bucket.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn build_router_can_disable_health_route() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .disable_health_route()
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn authorization_policy_can_deny_allowed_request() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .authorization_policy(|context: hooks::AuthorizationContext| {
            assert_eq!(context.bucket.as_str(), "test-bucket");
            assert_eq!(
                context.key.as_ref().map(|key| key.as_str()),
                Some("blocked.txt")
            );
            Err(error::S3Error::access_denied("blocked by policy"))
        })
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test-bucket/blocked.txt")
                    .header(header::CONTENT_LENGTH, "2")
                    .body(Body::from("hi"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authentication_provider_can_replace_static_auth() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(config::Config::new(temp_dir.path().to_path_buf()))
            .authentication_provider(|request: hooks::AuthenticationRequest| async move {
                if request
                    .headers
                    .get("x-api-key")
                    .and_then(|value| value.to_str().ok())
                    == Some("let-me-in")
                {
                    Ok(hooks::AuthenticationResult::custom("tenant-a"))
                } else {
                    Err(error::S3Error::access_denied("invalid api key"))
                }
            })
            .build_router()
            .await
            .expect("router");

        let allowed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/test-bucket")
                    .header("x-api-key", "let-me-in")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("allowed response");
        assert_eq!(allowed.status(), StatusCode::OK);

        let denied = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/test-bucket")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("denied response");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authorization_policy_receives_custom_auth_principal() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(config::Config::new(temp_dir.path().to_path_buf()))
            .authentication_provider(|_request: hooks::AuthenticationRequest| async {
                Ok(hooks::AuthenticationResult::custom("tenant-a"))
            })
            .authorization_policy(|context: hooks::AuthorizationContext| {
                assert_eq!(
                    context.principal,
                    hooks::RequestPrincipal::Custom {
                        id: "tenant-a".to_owned()
                    }
                );
                Ok(())
            })
            .build_router()
            .await
            .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/test-bucket")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn error_mapper_can_rewrite_error_and_preserve_request_id() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .request_id_factory(|| s3::types::RequestId::parse("fixed-request-id").expect("request id"))
        .on_error(|context: hooks::S3ErrorContext, _error| async move {
            assert_eq!(context.request_id.as_str(), "fixed-request-id");
            error::S3Error::access_denied("mapped error")
        })
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/test-bucket/missing.txt")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get("x-amz-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("fixed-request-id")
        );
    }

    #[tokio::test]
    async fn request_observer_receives_parsed_request_context() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let observed = Arc::new(Mutex::new(Vec::new()));
        let observed_clone = Arc::clone(&observed);
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .request_id_factory(|| s3::types::RequestId::parse("observed-request").expect("request id"))
        .on_request(move |context: hooks::S3RequestContext| {
            let observed = Arc::clone(&observed_clone);
            async move {
                observed.lock().expect("observed lock").push(context);
            }
        })
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/test-bucket")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let observed = observed.lock().expect("observed lock");
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].request_id.as_str(), "observed-request");
        assert_eq!(observed[0].operation, "HeadBucket");
        assert_eq!(
            observed[0].bucket.as_ref().map(|bucket| bucket.as_str()),
            Some("test-bucket")
        );
    }

    #[tokio::test]
    async fn upload_processor_fn_can_transform_stored_object() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .upload_processor_fn("uppercase", |upload| async move {
            let bytes = upload.read_current().await?;
            let upper = bytes
                .into_iter()
                .map(|byte| byte.to_ascii_uppercase())
                .collect::<Vec<_>>();
            upload.write_replacement(upper).await?;
            Ok(upload.replace())
        })
        .build_router()
        .await
        .expect("router");

        let put = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test-bucket/greeting.txt")
                    .header(header::CONTENT_LENGTH, "5")
                    .body(Body::from("hello"))
                    .expect("request"),
            )
            .await
            .expect("put response");
        assert_eq!(put.status(), StatusCode::OK);

        let get = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/test-bucket/greeting.txt")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("get response");
        assert_eq!(get.status(), StatusCode::OK);
        let body = to_bytes(get.into_body(), 1024).await.expect("body");
        assert_eq!(&body[..], b"HELLO");
    }

    #[tokio::test]
    async fn app_state_new_registers_no_upload_processors() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::new(config::Config {
            storage_root: temp_dir.path().to_path_buf(),
            auth: Default::default(),
            virtual_host_base_domain: None,
            upload_limits: Default::default(),
        })
        .await
        .expect("create app state");

        assert!(state.upload_processors.is_empty());
    }

    struct NamedProcessor(&'static str);

    impl middleware::UploadProcessor for NamedProcessor {
        fn process<'a>(
            &'a self,
            _request: middleware::UploadProcessorRequest<'a>,
        ) -> BoxFuture<
            'a,
            Result<middleware::UploadProcessorAction, middleware::UploadProcessorError>,
        > {
            let _name = self.0;
            Box::pin(async { Ok(middleware::UploadProcessorAction::Keep) })
        }
    }

    #[tokio::test]
    async fn app_state_rejects_invalid_auth_config() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let result = AppState::new(config::Config {
            storage_root: temp_dir.path().to_path_buf(),
            auth: config::AuthConfig {
                region: "US-EAST-1".to_owned(),
                ..Default::default()
            },
            virtual_host_base_domain: None,
            upload_limits: Default::default(),
        })
        .await;

        let Err(error) = result else {
            panic!("invalid auth config should fail");
        };

        assert!(matches!(
            error,
            AppInitError::Config(config::ConfigError::InvalidAuthConfig(
                "region must be a non-empty lowercase AWS region identifier"
            ))
        ));
    }

    #[tokio::test]
    async fn s3_request_admission_rejects_when_limit_is_exhausted() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::new(config::Config::new(temp_dir.path().to_path_buf()))
            .await
            .expect("create app state");
        let permits = (0..state.config.upload_limits.max_concurrent_s3_requests)
            .map(|_| state.try_acquire_s3_request().expect("permit"))
            .collect::<Vec<_>>();

        let error = state
            .try_acquire_s3_request()
            .expect_err("S3 request limit should reject");
        let response = error.into_response_with_request_id(&s3::types::RequestId::new());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(permits);
        let _permit = state
            .try_acquire_s3_request()
            .expect("permit released after drop");
    }

    #[tokio::test]
    async fn router_returns_slow_down_when_s3_request_admission_is_exhausted() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::new(config::Config::new(temp_dir.path().to_path_buf()))
            .await
            .expect("create app state");
        let _permits = (0..state.config.upload_limits.max_concurrent_s3_requests)
            .map(|_| state.try_acquire_s3_request().expect("permit"))
            .collect::<Vec<_>>();

        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test-bucket/admission.txt")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("send request");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read response body");
        let body = std::str::from_utf8(&body).expect("utf8 body");
        assert!(body.contains("<Code>SlowDown</Code>"));
        assert!(body.contains("too many active S3 requests"));
    }

    #[tokio::test]
    async fn object_writer_admission_rejects_when_limit_is_exhausted() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::new(config::Config::new(temp_dir.path().to_path_buf()))
            .await
            .expect("create app state");
        let permits = (0..state.config.upload_limits.max_active_object_writers)
            .map(|_| state.try_acquire_object_writer().expect("permit"))
            .collect::<Vec<_>>();

        let error = state
            .try_acquire_object_writer()
            .expect_err("object writer limit should reject");
        let response = error.into_response_with_request_id(&s3::types::RequestId::new());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(permits);
        let _permit = state
            .try_acquire_object_writer()
            .expect("permit released after drop");
    }

    #[tokio::test]
    async fn admission_limits_are_configurable() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::new(config::Config {
            storage_root: temp_dir.path().to_path_buf(),
            auth: Default::default(),
            virtual_host_base_domain: None,
            upload_limits: config::UploadLimits {
                max_concurrent_s3_requests: 1,
                max_active_object_writers: 1,
                max_active_multipart_part_writers: 1,
                max_active_aws_chunked_decoders: 1,
                ..Default::default()
            },
        })
        .await
        .expect("create app state");

        let _request = state.try_acquire_s3_request().expect("request permit");
        assert!(state.try_acquire_s3_request().is_err());

        let _object = state.try_acquire_object_writer().expect("object permit");
        assert!(state.try_acquire_object_writer().is_err());

        let _part = state
            .try_acquire_multipart_part_writer()
            .expect("part permit");
        assert!(state.try_acquire_multipart_part_writer().is_err());

        let mut headers = HeaderMap::new();
        headers.insert("content-encoding", HeaderValue::from_static("aws-chunked"));
        let _decoder = state
            .try_acquire_aws_chunked_decoder(&headers)
            .expect("decoder permit")
            .expect("aws-chunked permit");
        assert!(state.try_acquire_aws_chunked_decoder(&headers).is_err());
    }

    #[tokio::test]
    async fn multipart_part_writer_admission_rejects_when_limit_is_exhausted() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::new(config::Config::new(temp_dir.path().to_path_buf()))
            .await
            .expect("create app state");
        let permits = (0..state.config.upload_limits.max_active_multipart_part_writers)
            .map(|_| state.try_acquire_multipart_part_writer().expect("permit"))
            .collect::<Vec<_>>();

        let error = state
            .try_acquire_multipart_part_writer()
            .expect_err("multipart part writer limit should reject");
        let response = error.into_response_with_request_id(&s3::types::RequestId::new());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(permits);
        let _permit = state
            .try_acquire_multipart_part_writer()
            .expect("permit released after drop");
    }

    #[tokio::test]
    async fn aws_chunked_decoder_admission_only_applies_to_aws_chunked_requests() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::new(config::Config::new(temp_dir.path().to_path_buf()))
            .await
            .expect("create app state");
        let permits = (0..state.config.upload_limits.max_active_aws_chunked_decoders)
            .map(|_| {
                state
                    .admission
                    .aws_chunked_decoders
                    .clone()
                    .try_acquire_owned()
                    .expect("permit")
            })
            .collect::<Vec<_>>();

        let plain_headers = HeaderMap::new();
        assert!(
            state
                .try_acquire_aws_chunked_decoder(&plain_headers)
                .expect("plain request")
                .is_none()
        );

        let mut aws_chunked_headers = HeaderMap::new();
        aws_chunked_headers.insert("content-encoding", HeaderValue::from_static("aws-chunked"));
        let error = state
            .try_acquire_aws_chunked_decoder(&aws_chunked_headers)
            .expect_err("aws-chunked decoder limit should reject");
        let response = error.into_response_with_request_id(&s3::types::RequestId::new());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        drop(permits);
        assert!(
            state
                .try_acquire_aws_chunked_decoder(&aws_chunked_headers)
                .expect("permit released after drop")
                .is_some()
        );
    }
}
