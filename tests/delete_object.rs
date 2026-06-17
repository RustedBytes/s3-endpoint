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
async fn delete_object_removes_stored_object() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/delete-me.txt")
                .header(header::CONTENT_LENGTH, "6")
                .body(Body::from("delete"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test-bucket/delete-me.txt")
                .body(Body::empty())
                .expect("build delete"),
        )
        .await
        .expect("send delete");

    assert_eq!(delete.status(), StatusCode::NO_CONTENT);
    assert_has_request_id(&delete);
    assert_eq!(
        delete.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/delete-me.txt")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_object_succeeds_for_missing_object() {
    let (state, _temp_dir) = test_state(None).await;

    let delete = router(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test-bucket/missing.txt")
                .body(Body::empty())
                .expect("build delete"),
        )
        .await
        .expect("send delete");

    let status = delete.status();
    assert_has_request_id(&delete);
    let body = response_text(delete).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn delete_object_rejects_percent_decoded_control_character_in_key() {
    let (state, _temp_dir) = test_state(None).await;

    let delete = router(state)
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/test-bucket/bad%0Akey.txt")
                .body(Body::empty())
                .expect("build delete"),
        )
        .await
        .expect("send delete");

    assert_eq!(delete.status(), StatusCode::BAD_REQUEST);
    assert_has_request_id(&delete);
    let body = response_text(delete).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("object key contains invalid characters"));
}

#[tokio::test]
async fn delete_object_supports_virtual_hosted_style() {
    let (state, _temp_dir) = test_state(Some("s3.local".to_owned())).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/vh-delete.txt")
                .header(header::HOST, "test-bucket.s3.local")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/vh-delete.txt")
                .header(header::HOST, "test-bucket.s3.local")
                .body(Body::empty())
                .expect("build delete"),
        )
        .await
        .expect("send delete");
    let status = delete.status();
    assert_has_request_id(&delete);
    let body = response_text(delete).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/vh-delete.txt")
                .header(header::HOST, "test-bucket.s3.local")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_object_rejects_signed_request_for_disallowed_action() {
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
        method: "DELETE",
        path: "/test-bucket/private.txt",
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
                .method("DELETE")
                .uri("/test-bucket/private.txt")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build delete"),
        )
        .await
        .expect("send delete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_has_request_id(&response);
}

#[tokio::test]
async fn delete_object_accepts_presigned_url_allowed_by_delete_object_policy() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::DeleteObject]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/presigned-delete.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let url = common::presigned_url(common::PresignInput {
        method: "DELETE",
        path: "/test-bucket/presigned-delete.txt",
        host: "localhost:9000",
        amz_date: "20260616T120000Z",
        expires: 604_800,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    });
    let delete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .body(Body::empty())
                .expect("build delete"),
        )
        .await
        .expect("send delete");

    let status = delete.status();
    assert_has_request_id(&delete);
    let body = response_text(delete).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/presigned-delete.txt")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(get.status(), StatusCode::NOT_FOUND);
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

async fn response_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    std::str::from_utf8(&body).expect("utf8 body").to_owned()
}
