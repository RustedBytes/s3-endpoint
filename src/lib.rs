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
pub(crate) mod http;
/// S3 request target parsing and validated domain value types.
pub mod s3;
/// Filesystem-backed object and multipart storage types.
pub mod storage;

use std::sync::Arc;

use axum::{Router, http::HeaderMap};
use storage::{FileMultipartStore, FileObjectStore};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone)]
/// Shared application state for the S3 endpoint.
///
/// `AppState` owns validated configuration, credential state, filesystem-backed
/// object and multipart stores, and bounded admission controls. Construct it
/// with [`AppState::new`] and pass it to [`router`] to build the HTTP service.
pub struct AppState {
    /// Validated runtime configuration.
    pub config: config::Config,
    /// Credential lookup and authorization state.
    pub auth: Arc<config::AuthState>,
    /// Filesystem-backed committed object store.
    pub object_store: Arc<FileObjectStore>,
    /// Filesystem-backed multipart upload store.
    pub multipart_store: Arc<FileMultipartStore>,
    admission: Arc<AdmissionControl>,
}

impl AppState {
    /// Builds application state from configuration.
    ///
    /// This validates configuration and credentials, initializes storage
    /// directories, removes stale temporary/orphaned files, and creates bounded
    /// admission controls. Returns an error when configuration is invalid or
    /// storage cannot be initialized.
    pub async fn new(config: config::Config) -> Result<Self, AppInitError> {
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
            admission: Arc::new(AdmissionControl::new(&upload_limits)),
        })
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
        body::Body,
        http::{HeaderMap, HeaderValue, Request, StatusCode},
    };
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
