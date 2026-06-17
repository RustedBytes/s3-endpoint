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

use std::{collections::HashSet, convert::Infallible, future::Future, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request},
    response::IntoResponse,
    routing::Route,
};
use hooks::{
    AuthenticationProvider, AuthenticationRequest, AuthenticationResult, AuthorizationContext,
    AuthorizationPolicy, Clock, ErrorMapper, OperationContext, OperationPolicy, RequestIdFactory,
    RequestObserver, ResponseMapper, S3ErrorContext, S3RequestContext, S3ResponseContext,
    SharedAuthenticationProvider, SharedAuthorizationPolicy, SharedClock, SharedErrorMapper,
    SharedOperationPolicy, SharedRequestIdFactory, SharedRequestObserver, SharedResponseMapper,
    SharedTargetPolicy, SharedTenantLimitsProvider, SharedUploadPolicy, SystemClock, TargetContext,
    TargetPolicy, TenantLimitContext, TenantLimitsProvider, TenantOperationLease,
    TenantOperationOutcome, UploadPolicy, UploadPolicyContext,
};
use middleware::{
    SharedUploadProcessor, UploadProcessor, UploadProcessorAction, UploadProcessorError,
    UploadProcessorFn, UploadProcessorHandle,
};
use storage::{
    FileMultipartStore, FileObjectStore, MultipartStore, ObjectStore, SharedMultipartStore,
    SharedObjectStore,
};
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
    pub object_store: SharedObjectStore,
    /// Filesystem-backed multipart upload store.
    pub multipart_store: SharedMultipartStore,
    pub(crate) io_tuning: config::IoTuning,
    pub(crate) upload_processors: Arc<Vec<SharedUploadProcessor>>,
    request_observer: Option<SharedRequestObserver>,
    error_mapper: Option<SharedErrorMapper>,
    response_mapper: Option<SharedResponseMapper>,
    request_id_factory: SharedRequestIdFactory,
    clock: SharedClock,
    authentication_provider: Option<SharedAuthenticationProvider>,
    authorization_policy: Option<SharedAuthorizationPolicy>,
    operation_policy: Option<SharedOperationPolicy>,
    target_policy: Option<SharedTargetPolicy>,
    upload_policy: Option<SharedUploadPolicy>,
    tenant_limits_provider: SharedTenantLimitsProvider,
    disabled_operations: Arc<HashSet<config::S3Action>>,
    admission: Arc<AdmissionControl>,
}

impl AppState {
    /// Creates a builder for application state with optional upload processors.
    pub fn builder(config: config::Config) -> AppBuilder {
        AppBuilder {
            config,
            upload_processors: Vec::new(),
            object_store: None,
            multipart_store: None,
            io_tuning: config::IoTuning::default(),
            multipart_lifecycle: config::MultipartLifecycle::default(),
            request_observer: None,
            error_mapper: None,
            response_mapper: None,
            request_id_factory: Arc::new(s3::types::RequestId::new),
            clock: Arc::new(SystemClock),
            authentication_provider: None,
            authorization_policy: None,
            operation_policy: None,
            target_policy: None,
            upload_policy: None,
            tenant_limits_provider: Arc::new(hooks::NoopTenantLimitsProvider),
            disabled_operations: HashSet::new(),
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
            object_store,
            multipart_store,
            io_tuning,
            multipart_lifecycle,
            request_observer,
            error_mapper,
            response_mapper,
            request_id_factory,
            clock,
            authentication_provider,
            authorization_policy,
            operation_policy,
            target_policy,
            upload_policy,
            tenant_limits_provider,
            disabled_operations,
            health_path: _,
            router_layers: _,
        } = builder;
        config.validate()?;
        io_tuning.validate()?;
        let upload_limits = config.upload_limits.validated()?;
        let auth = Arc::new(config::AuthState::new(&config.auth)?);
        let object_store = match object_store {
            Some(store) => store,
            None => Arc::new(FileObjectStore::new(config.storage_root.clone()).await?),
        };
        let multipart_store = match multipart_store {
            Some(store) => store,
            None => Arc::new(
                FileMultipartStore::new_with_options(
                    config.storage_root.clone(),
                    multipart_lifecycle,
                    clock.clone(),
                )
                .await?,
            ),
        };
        Ok(Self {
            config,
            auth,
            object_store,
            multipart_store,
            io_tuning,
            upload_processors: Arc::new(upload_processors),
            request_observer,
            error_mapper,
            response_mapper,
            request_id_factory,
            clock,
            authentication_provider,
            authorization_policy,
            operation_policy,
            target_policy,
            upload_policy,
            tenant_limits_provider,
            disabled_operations: Arc::new(disabled_operations),
            admission: Arc::new(AdmissionControl::new(&upload_limits)),
        })
    }

    pub(crate) fn upload_processors(&self) -> &[SharedUploadProcessor] {
        &self.upload_processors
    }

    pub(crate) fn request_id(&self) -> s3::types::RequestId {
        self.request_id_factory.request_id()
    }

    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.clock.now()
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

    pub(crate) async fn map_response(
        &self,
        context: S3ResponseContext,
        response: axum::response::Response,
    ) -> axum::response::Response {
        if let Some(mapper) = &self.response_mapper {
            mapper.map_response(context, response).await
        } else {
            response
        }
    }

    pub(crate) fn allow_operation(&self, context: OperationContext) -> Result<(), error::S3Error> {
        if self.disabled_operations.contains(&context.action) {
            return Err(error::S3Error::method_not_allowed());
        }
        if let Some(policy) = &self.operation_policy {
            policy.allow_operation(context)
        } else {
            Ok(())
        }
    }

    pub(crate) fn allow_target(&self, context: TargetContext) -> Result<(), error::S3Error> {
        if let Some(policy) = &self.target_policy {
            policy.allow_target(context)
        } else {
            Ok(())
        }
    }

    pub(crate) fn allow_upload(&self, context: UploadPolicyContext) -> Result<(), error::S3Error> {
        if let Some(policy) = &self.upload_policy {
            policy.allow_upload(context)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn begin_tenant_operation(
        &self,
        context: TenantLimitContext,
    ) -> Result<TenantOperationLease, error::S3Error> {
        self.tenant_limits_provider.begin_operation(context).await
    }

    pub(crate) async fn finish_tenant_operation(
        &self,
        context: TenantLimitContext,
        outcome: TenantOperationOutcome,
    ) {
        self.tenant_limits_provider
            .finish_operation(context, outcome)
            .await;
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
    object_store: Option<SharedObjectStore>,
    multipart_store: Option<SharedMultipartStore>,
    io_tuning: config::IoTuning,
    multipart_lifecycle: config::MultipartLifecycle,
    request_observer: Option<SharedRequestObserver>,
    error_mapper: Option<SharedErrorMapper>,
    response_mapper: Option<SharedResponseMapper>,
    request_id_factory: SharedRequestIdFactory,
    clock: SharedClock,
    authentication_provider: Option<SharedAuthenticationProvider>,
    authorization_policy: Option<SharedAuthorizationPolicy>,
    operation_policy: Option<SharedOperationPolicy>,
    target_policy: Option<SharedTargetPolicy>,
    upload_policy: Option<SharedUploadPolicy>,
    tenant_limits_provider: SharedTenantLimitsProvider,
    disabled_operations: HashSet<config::S3Action>,
    health_path: Option<String>,
    router_layers: Vec<RouterTransform>,
}

type RouterTransform = Arc<dyn Fn(Router) -> Router + Send + Sync>;

impl AppBuilder {
    /// Replaces the default filesystem object store.
    pub fn object_store<S>(mut self, store: S) -> Self
    where
        S: ObjectStore,
    {
        self.object_store = Some(Arc::new(store));
        self
    }

    /// Replaces the default filesystem multipart store.
    pub fn multipart_store<S>(mut self, store: S) -> Self
    where
        S: MultipartStore,
    {
        self.multipart_store = Some(Arc::new(store));
        self
    }

    /// Replaces low-level I/O buffer tuning.
    pub fn io_tuning(mut self, io_tuning: config::IoTuning) -> Self {
        self.io_tuning = io_tuning;
        self
    }

    /// Replaces multipart lifecycle and startup cleanup tuning.
    pub fn multipart_lifecycle(mut self, lifecycle: config::MultipartLifecycle) -> Self {
        self.multipart_lifecycle = lifecycle;
        self
    }

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

    /// Registers an HTTP response mapper.
    pub fn on_response<M>(mut self, mapper: M) -> Self
    where
        M: ResponseMapper,
    {
        self.response_mapper = Some(Arc::new(mapper));
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

    /// Sets the clock used for generated object and multipart timestamps.
    pub fn clock<C>(mut self, clock: C) -> Self
    where
        C: Clock,
    {
        self.clock = Arc::new(clock);
        self
    }

    /// Registers a custom authentication provider.
    ///
    /// When configured, this provider replaces the built-in static SigV4 and
    /// anonymous authentication path. Built-in SigV4 remains the default when
    /// no custom provider is registered. Target, upload, authorization, and
    /// tenant-limit hooks still run after custom authentication succeeds.
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

    /// Registers an additional operation policy.
    pub fn operation_policy<P>(mut self, policy: P) -> Self
    where
        P: OperationPolicy,
    {
        self.operation_policy = Some(Arc::new(policy));
        self
    }

    /// Disables one implemented S3 operation by action.
    pub fn disable_operation(mut self, action: config::S3Action) -> Self {
        self.disabled_operations.insert(action);
        self
    }

    /// Registers an additional bucket/key target policy.
    pub fn target_policy<P>(mut self, policy: P) -> Self
    where
        P: TargetPolicy,
    {
        self.target_policy = Some(Arc::new(policy));
        self
    }

    /// Registers an additional upload policy.
    pub fn upload_policy<P>(mut self, policy: P) -> Self
    where
        P: UploadPolicy,
    {
        self.upload_policy = Some(Arc::new(policy));
        self
    }

    /// Registers a per-tenant operation limits provider.
    pub fn tenant_limits_provider<P>(mut self, provider: P) -> Self
    where
        P: TenantLimitsProvider,
    {
        self.tenant_limits_provider = Arc::new(provider);
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
        body::{Body, Bytes, to_bytes},
        http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    };
    use futures_util::{future::BoxFuture, stream};
    use std::{convert::Infallible, path::Path, sync::Mutex, time::Duration};
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

    #[tokio::test]
    async fn app_builder_rejects_invalid_io_tuning() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let result = AppState::builder(config::Config::new(temp_dir.path().to_path_buf()))
            .io_tuning(
                config::IoTuning::builder()
                    .object_stream_buffer_size(0)
                    .build(),
            )
            .build()
            .await;

        assert!(matches!(
            result,
            Err(AppInitError::Config(config::ConfigError::InvalidIoTuning(
                "object_stream_buffer_size must be greater than 0"
            )))
        ));
    }

    #[tokio::test]
    async fn disabled_operation_rejects_before_handler_dispatch() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .disable_operation(config::S3Action::GetObject)
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/test-bucket/file.txt")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn operation_policy_can_deny_specific_operations() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .operation_policy(|context: hooks::OperationContext| {
            assert_eq!(context.action, config::S3Action::HeadBucket);
            Err(error::S3Error::access_denied("operation blocked"))
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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn response_mapper_can_add_headers() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .on_response(
            |context: hooks::S3ResponseContext, mut response: axum::response::Response| async move {
                assert_eq!(context.operation, "HeadBucket");
                response
                    .headers_mut()
                    .insert("x-app-trace", HeaderValue::from_static("trace-1"));
                response
            },
        )
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
        assert_eq!(
            response
                .headers()
                .get("x-app-trace")
                .and_then(|value| value.to_str().ok()),
            Some("trace-1")
        );
    }

    #[tokio::test]
    async fn target_policy_can_deny_key_prefixes() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .target_policy(|context: hooks::TargetContext| {
            if context
                .key
                .as_ref()
                .is_some_and(|key| key.as_str().starts_with("private/"))
            {
                return Err(error::S3Error::access_denied("private prefix"));
            }
            Ok(())
        })
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/test-bucket/private/file.txt")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn upload_policy_can_deny_uploads_before_body_is_stored() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .upload_policy(|context: hooks::UploadPolicyContext| {
            assert_eq!(context.action, config::S3Action::PutObject);
            Err(error::S3Error::access_denied("uploads disabled"))
        })
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test-bucket/file.txt")
                    .header(header::CONTENT_LENGTH, "4")
                    .body(Body::from("body"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn clock_controls_object_last_modified_metadata() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let fixed_now = chrono::DateTime::parse_from_rfc3339("2026-06-17T12:34:56Z")
            .expect("timestamp")
            .with_timezone(&chrono::Utc);
        let state = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .clock(move || fixed_now)
        .build()
        .await
        .expect("state");
        let app = router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test-bucket/file.txt")
                    .header(header::CONTENT_LENGTH, "4")
                    .body(Body::from("body"))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let metadata = state
            .object_store
            .head_object(
                &s3::types::BucketName::parse("test-bucket").expect("bucket"),
                &s3::types::ObjectKey::parse("file.txt").expect("key"),
            )
            .await
            .expect("metadata read")
            .expect("metadata");
        assert_eq!(metadata.last_modified, fixed_now);
    }

    #[tokio::test]
    async fn builder_accepts_custom_store_trait_objects() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let object_store = storage::FileObjectStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("object store");
        let multipart_store = storage::FileMultipartStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("multipart store");

        let state = AppState::builder(config::Config::new(temp_dir.path().to_path_buf()))
            .object_store(object_store)
            .multipart_store(multipart_store)
            .build()
            .await
            .expect("state");

        assert!(state.upload_processors.is_empty());
    }

    #[tokio::test]
    async fn tenant_limits_provider_can_deny_before_handler_execution() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .tenant_limits_provider(DenyTenantLimitsProvider)
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

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn tenant_limits_timeout_returns_slow_down_and_preserves_request_id() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let finishes = Arc::new(Mutex::new(Vec::new()));
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .request_id_factory(|| s3::types::RequestId::parse("timeout-request").expect("request id"))
        .tenant_limits_provider(RecordingTenantLimitsProvider {
            begins: Arc::new(Mutex::new(Vec::new())),
            finishes: Arc::clone(&finishes),
            timeout: Some(std::time::Duration::from_millis(1)),
            permit_drops: None,
        })
        .upload_processor_fn("slow", |_upload| async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            Ok(middleware::UploadProcessorAction::Keep)
        })
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test-bucket/slow.txt")
                    .header(header::CONTENT_LENGTH, "4")
                    .body(Body::from("slow"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get("x-amz-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("timeout-request")
        );
        let finishes = finishes.lock().expect("finishes lock");
        assert_eq!(finishes.len(), 1);
        assert!(finishes[0].1.timed_out);
        assert_eq!(finishes[0].1.error_code.as_deref(), Some("SlowDown"));
    }

    #[tokio::test]
    async fn custom_auth_with_invalid_principal_id_is_rejected() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(config::Config::new(temp_dir.path().to_path_buf()))
            .request_id_factory(|| {
                s3::types::RequestId::parse("invalid-principal").expect("request id")
            })
            .authentication_provider(|_request: hooks::AuthenticationRequest| async {
                Ok(hooks::AuthenticationResult::custom("tenant\nid"))
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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get("x-amz-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("invalid-principal")
        );
    }

    #[tokio::test]
    async fn custom_auth_success_still_runs_downstream_policies() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(config::Config::new(temp_dir.path().to_path_buf()))
            .authentication_provider(|_request: hooks::AuthenticationRequest| async {
                hooks::AuthenticationResult::try_custom("tenant-a")
                    .map_err(|err| error::S3Error::access_denied(err.to_string()))
            })
            .authorization_policy(|_context: hooks::AuthorizationContext| {
                Err(error::S3Error::access_denied("policy denied"))
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

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn timed_out_put_object_discards_temporary_object_file() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .tenant_limits_provider(RecordingTenantLimitsProvider {
            begins: Arc::new(Mutex::new(Vec::new())),
            finishes: Arc::new(Mutex::new(Vec::new())),
            timeout: Some(Duration::from_millis(1)),
            permit_drops: None,
        })
        .upload_processor_fn("slow", |_upload| async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(middleware::UploadProcessorAction::Keep)
        })
        .build_router()
        .await
        .expect("router");

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test-bucket/slow.txt")
                    .header(header::CONTENT_LENGTH, "4")
                    .body(Body::from("slow"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_dir_empty_eventually(&temp_dir.path().join("tmp")).await;
    }

    #[tokio::test]
    async fn timed_out_upload_part_discards_temporary_part_file() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .tenant_limits_provider(RecordingTenantLimitsProvider {
            begins: Arc::new(Mutex::new(Vec::new())),
            finishes: Arc::new(Mutex::new(Vec::new())),
            timeout: Some(Duration::from_millis(1)),
            permit_drops: None,
        })
        .build_router()
        .await
        .expect("router");

        let create = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/test-bucket/parts.txt?uploads")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("create response");
        assert_eq!(create.status(), StatusCode::OK);
        let body = to_bytes(create.into_body(), usize::MAX)
            .await
            .expect("create body");
        let upload_id = upload_id_from_xml(std::str::from_utf8(&body).expect("xml utf8"));

        let delayed = stream::once(async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok::<_, Infallible>(Bytes::from_static(b"part"))
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!(
                        "/test-bucket/parts.txt?partNumber=1&uploadId={}",
                        upload_id
                    ))
                    .header(header::CONTENT_LENGTH, "4")
                    .body(Body::from_stream(delayed))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_no_multipart_tmp_files_eventually(temp_dir.path()).await;
    }

    #[tokio::test]
    async fn tenant_limits_provider_permit_is_dropped_after_completion() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let drops = Arc::new(Mutex::new(0_usize));
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .tenant_limits_provider(RecordingTenantLimitsProvider {
            begins: Arc::new(Mutex::new(Vec::new())),
            finishes: Arc::new(Mutex::new(Vec::new())),
            timeout: None,
            permit_drops: Some(Arc::clone(&drops)),
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
        assert_eq!(*drops.lock().expect("drop lock"), 1);
    }

    #[tokio::test]
    async fn tenant_limits_finish_receives_operation_outcomes() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let begins = Arc::new(Mutex::new(Vec::new()));
        let finishes = Arc::new(Mutex::new(Vec::new()));
        let app = AppState::builder(
            config::Config::builder(temp_dir.path())
                .allow_anonymous(true)
                .build(),
        )
        .tenant_limits_provider(RecordingTenantLimitsProvider {
            begins: Arc::clone(&begins),
            finishes: Arc::clone(&finishes),
            timeout: None,
            permit_drops: None,
        })
        .build_router()
        .await
        .expect("router");

        let head = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/test-bucket")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("head response");
        assert_eq!(head.status(), StatusCode::OK);

        let missing = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/test-bucket/missing.txt")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("missing response");
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let put = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test-bucket/body.txt")
                    .header(header::CONTENT_LENGTH, "5")
                    .body(Body::from("hello"))
                    .expect("request"),
            )
            .await
            .expect("put response");
        assert_eq!(put.status(), StatusCode::OK);

        let begins = begins.lock().expect("begins lock");
        assert_eq!(begins.len(), 3);
        assert!(
            begins
                .iter()
                .all(|context| context.tenant.as_str() == "anonymous")
        );
        assert_eq!(begins[0].action, config::S3Action::HeadBucket);
        assert_eq!(begins[1].action, config::S3Action::GetObject);
        assert_eq!(begins[2].action, config::S3Action::PutObject);

        let finishes = finishes.lock().expect("finishes lock");
        assert_eq!(finishes.len(), 3);
        assert_eq!(finishes[0].1.status, StatusCode::OK);
        assert_eq!(finishes[1].1.status, StatusCode::NOT_FOUND);
        assert_eq!(finishes[1].1.error_code.as_deref(), Some("NoSuchKey"));
        assert_eq!(finishes[2].1.status, StatusCode::OK);
        assert_eq!(finishes[2].1.decoded_bytes, Some(5));
    }

    #[tokio::test]
    async fn tenant_limits_use_custom_auth_principal_and_authenticate_once() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let auth_calls = Arc::new(Mutex::new(0_usize));
        let begins = Arc::new(Mutex::new(Vec::new()));
        let auth_calls_clone = Arc::clone(&auth_calls);
        let app = AppState::builder(config::Config::new(temp_dir.path().to_path_buf()))
            .authentication_provider(move |_request: hooks::AuthenticationRequest| {
                let auth_calls = Arc::clone(&auth_calls_clone);
                async move {
                    *auth_calls.lock().expect("auth calls lock") += 1;
                    Ok(hooks::AuthenticationResult::custom("tenant-a"))
                }
            })
            .tenant_limits_provider(RecordingTenantLimitsProvider {
                begins: Arc::clone(&begins),
                finishes: Arc::new(Mutex::new(Vec::new())),
                timeout: None,
                permit_drops: None,
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
        assert_eq!(*auth_calls.lock().expect("auth calls lock"), 1);
        let begins = begins.lock().expect("begins lock");
        assert_eq!(begins.len(), 1);
        assert_eq!(begins[0].tenant.as_str(), "tenant-a");
        assert_eq!(
            begins[0].principal,
            hooks::RequestPrincipal::Custom {
                id: "tenant-a".to_owned()
            }
        );
    }

    struct DenyTenantLimitsProvider;

    impl hooks::TenantLimitsProvider for DenyTenantLimitsProvider {
        fn begin_operation<'a>(
            &'a self,
            _context: hooks::TenantLimitContext,
        ) -> BoxFuture<'a, Result<hooks::TenantOperationLease, error::S3Error>> {
            Box::pin(async { Err(error::S3Error::slow_down("tenant quota exceeded")) })
        }

        fn finish_operation<'a>(
            &'a self,
            _context: hooks::TenantLimitContext,
            _outcome: hooks::TenantOperationOutcome,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async {})
        }
    }

    struct RecordingTenantLimitsProvider {
        begins: Arc<Mutex<Vec<hooks::TenantLimitContext>>>,
        finishes: Arc<Mutex<Vec<(hooks::TenantLimitContext, hooks::TenantOperationOutcome)>>>,
        timeout: Option<std::time::Duration>,
        permit_drops: Option<Arc<Mutex<usize>>>,
    }

    impl hooks::TenantLimitsProvider for RecordingTenantLimitsProvider {
        fn begin_operation<'a>(
            &'a self,
            context: hooks::TenantLimitContext,
        ) -> BoxFuture<'a, Result<hooks::TenantOperationLease, error::S3Error>> {
            let timeout = self.timeout;
            let permit_drops = self.permit_drops.clone();
            self.begins.lock().expect("begins lock").push(context);
            Box::pin(async move {
                let mut lease = hooks::TenantOperationLease::new();
                if let Some(timeout) = timeout {
                    lease = lease.timeout(timeout);
                }
                if let Some(permit_drops) = permit_drops {
                    lease = lease.permit(DropCounter(permit_drops));
                }
                Ok(lease)
            })
        }

        fn finish_operation<'a>(
            &'a self,
            context: hooks::TenantLimitContext,
            outcome: hooks::TenantOperationOutcome,
        ) -> BoxFuture<'a, ()> {
            self.finishes
                .lock()
                .expect("finishes lock")
                .push((context, outcome));
            Box::pin(async {})
        }
    }

    struct DropCounter(Arc<Mutex<usize>>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            *self.0.lock().expect("drop counter lock") += 1;
        }
    }

    async fn assert_dir_empty_eventually(path: &Path) {
        for _ in 0..20 {
            if dir_entries(path).is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("directory still contains entries: {:?}", dir_entries(path));
    }

    async fn assert_no_multipart_tmp_files_eventually(root: &Path) {
        for _ in 0..20 {
            let tmp_files = multipart_tmp_files(root);
            if tmp_files.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "multipart storage still contains tmp files: {:?}",
            multipart_tmp_files(root)
        );
    }

    fn dir_entries(path: &Path) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(path)
            .map(|entries| {
                entries
                    .map(|entry| entry.expect("dir entry").path())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    fn multipart_tmp_files(root: &Path) -> Vec<std::path::PathBuf> {
        let multipart = root.join("multipart");
        let mut tmp_files = Vec::new();
        for upload in dir_entries(&multipart) {
            for entry in dir_entries(&upload) {
                if entry
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".tmp"))
                {
                    tmp_files.push(entry);
                }
            }
        }
        tmp_files
    }

    fn upload_id_from_xml(xml: &str) -> String {
        let start = xml.find("<UploadId>").expect("upload id start") + "<UploadId>".len();
        let end = xml[start..].find("</UploadId>").expect("upload id end") + start;
        xml[start..end].to_owned()
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
