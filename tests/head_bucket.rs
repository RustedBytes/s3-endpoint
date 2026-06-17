use std::collections::BTreeSet;

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header},
};
use s3_endpoint::{
    AppState,
    config::{AuthConfig, Config, S3Action},
    router,
};
use tower::ServiceExt;

mod common;

async fn test_state(virtual_host_base_domain: Option<String>) -> (AppState, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    (state, temp_dir)
}

#[tokio::test]
async fn head_bucket_accepts_path_style_bucket() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send head bucket");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    assert!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body")
            .is_empty()
    );
}

#[tokio::test]
async fn head_bucket_accepts_virtual_hosted_bucket() {
    let (state, _temp_dir) = test_state(Some("s3.local".to_owned())).await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/")
                .header(header::HOST, "test-bucket.s3.local")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send head bucket");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
}

#[tokio::test]
async fn head_routes_object_path_to_head_object() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/object.txt")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send head bucket");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    assert_empty_body(response).await;
}

#[tokio::test]
async fn head_bucket_rejects_actual_sha256_empty_payload_hash_mismatch() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket")
                .header("x-amz-content-sha256", "0".repeat(64))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send head bucket");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    assert_empty_body(response).await;
}

#[tokio::test]
async fn head_bucket_rejects_unsupported_payload_hash_mode() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket")
                .header("x-amz-content-sha256", "NOT-A-SUPPORTED-PAYLOAD-MODE")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send head bucket");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_has_request_id(&response);
}

#[tokio::test]
async fn head_bucket_accepts_signed_request_allowed_by_auth_policy() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_buckets: BTreeSet::from(["test-bucket".to_owned()]),
            allowed_actions: BTreeSet::from([S3Action::HeadBucket]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let authorization = common::authorization_header(common::SignatureInput {
        method: "HEAD",
        path: "/test-bucket",
        canonical_query: "",
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers: "host;x-amz-content-sha256;x-amz-date",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send head bucket");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
}

#[tokio::test]
async fn head_bucket_rejects_signed_request_for_disallowed_action() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::PutObject]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let authorization = common::authorization_header(common::SignatureInput {
        method: "HEAD",
        path: "/test-bucket",
        canonical_query: "",
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers: "host;x-amz-content-sha256;x-amz-date",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send head bucket");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    assert_empty_body(response).await;
}

fn assert_has_request_id(response: &axum::response::Response) {
    let value = response
        .headers()
        .get("x-amz-request-id")
        .expect("request id header")
        .to_str()
        .expect("request id ascii");
    assert!(!value.is_empty());
}

async fn assert_empty_body(response: axum::response::Response) {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert!(body.is_empty());
}
