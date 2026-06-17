use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use crc::{CRC_32_ISO_HDLC, Crc};
use futures_util::{future::BoxFuture, stream};
use md5::{Digest as _, Md5};
use s3_endpoint::{
    AppState,
    config::{AccessKeyConfig, AuthConfig, Config, S3Action, UploadLimits},
    middleware::{
        UploadProcessor, UploadProcessorAction, UploadProcessorError, UploadProcessorRequest,
    },
    router,
    s3::types::{BucketName, ObjectKey, PartNumber},
    storage::{ChecksumAlgorithm, ChecksumType, UploadId, UploadState},
};
use tokio::io::AsyncReadExt;
use tower::ServiceExt;

mod common;

const MIN_MULTIPART_NON_FINAL_PART_SIZE: usize = 5 * 1024 * 1024;

async fn test_state() -> (AppState, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    (state, temp_dir)
}

#[tokio::test]
async fn multipart_create_upload_list_and_complete() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/multi.txt?uploads")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");
    assert_eq!(create.status(), StatusCode::OK);
    assert_has_request_id(&create);
    let create_body = response_text(create).await;
    let upload_id = tag_value(&create_body, "UploadId").expect("upload id");

    let first_part = vec![b'a'; MIN_MULTIPART_NON_FINAL_PART_SIZE];
    let etag1 =
        upload_part_bytes_for_key(app.clone(), &upload_id, "multi.txt", 1, first_part).await;
    let etag2 = upload_part(app.clone(), &upload_id, 2, "world").await;

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/test-bucket/multi.txt?uploadId={upload_id}"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::OK);
    assert_has_request_id(&list);
    let list_body = response_text(list).await;
    assert!(list_body.contains("<PartNumber>1</PartNumber>"));
    assert!(list_body.contains("<PartNumber>2</PartNumber>"));
    let last_modified = tag_value(&list_body, "LastModified").expect("last modified");
    assert!(last_modified.ends_with('Z'));
    assert!(last_modified.contains('.'));
    assert!(!last_modified.contains("+00:00"));

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/test-bucket/multi.txt?uploadId={upload_id}"))
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);
    assert_has_request_id(&complete);
    let complete_body = response_text(complete).await;
    assert!(
        complete_body.contains("<Location>http://localhost:9000/test-bucket/multi.txt</Location>")
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("multi.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.size,
        (MIN_MULTIPART_NON_FINAL_PART_SIZE + 5) as u64
    );
    assert!(metadata.etag.as_str().ends_with("-2\""));
    assert!(!temp_dir.path().join("multipart").join(&upload_id).exists());
}

#[tokio::test]
async fn multipart_processors_run_when_upload_is_completed() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let calls = Arc::new(AtomicUsize::new(0));
    let state = AppState::builder(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .upload_processor(CountingReplaceProcessor {
        calls: Arc::clone(&calls),
        replacement: b"clean multipart".to_vec(),
    })
    .build()
    .await
    .expect("create app state");
    let app = router(state.clone());

    let upload_id = create_upload(app.clone(), "/test-bucket/processed-multipart.txt").await;
    let etag = upload_part_for_key(
        app.clone(),
        &upload_id,
        "processed-multipart.txt",
        1,
        "dirty multipart",
    )
    .await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/processed-multipart.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build complete"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("processed-multipart.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, "clean multipart".len() as u64);
    assert_eq!(
        metadata.etag.as_str(),
        format!("\"{}\"", hex::encode(Md5::digest(b"clean multipart")))
    );

    let (_metadata, mut file) = state
        .object_store
        .open_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("processed-multipart.txt").expect("key"),
        )
        .await
        .expect("open object")
        .expect("object exists");
    let mut stored = Vec::new();
    file.read_to_end(&mut stored).await.expect("read object");
    assert_eq!(stored, b"clean multipart");
}

#[tokio::test]
async fn multipart_responses_escape_xml_sensitive_key_values() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let encoded_key = "xml%26%3C%3E%22%27.txt";
    let escaped_key = "xml&amp;&lt;&gt;&quot;&apos;.txt";

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/test-bucket/{encoded_key}?uploads"))
                .body(Body::empty())
                .expect("build create"),
        )
        .await
        .expect("send create");
    assert_eq!(create.status(), StatusCode::OK);
    let create_body = response_text(create).await;
    assert!(create_body.contains(&format!("<Key>{escaped_key}</Key>")));
    let upload_id = tag_value(&create_body, "UploadId").expect("upload id");

    let etag = upload_part_for_key(app.clone(), &upload_id, encoded_key, 1, "body").await;

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/test-bucket/{encoded_key}?uploadId={upload_id}"))
                .body(Body::empty())
                .expect("build list"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = response_text(list).await;
    assert!(list_body.contains(&format!("<Key>{escaped_key}</Key>")));

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/test-bucket/{encoded_key}?uploadId={upload_id}"))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build complete"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);
    let complete_body = response_text(complete).await;
    assert!(complete_body.contains(&format!("<Key>{escaped_key}</Key>")));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("xml&<>\"'.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, 4);
}

#[tokio::test]
async fn multipart_create_accepts_matching_actual_sha256_empty_payload_hash() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let payload_hash = hex::encode(sha2::Sha256::digest([]));

    let create = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/create-payload-hash.txt?uploads")
                .header("x-amz-content-sha256", payload_hash)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(create.status(), StatusCode::OK);
    let create_body = response_text(create).await;
    assert!(create_body.contains("<UploadId>"));
}

#[tokio::test]
async fn multipart_create_rejects_uppercase_actual_sha256_empty_payload_hash() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);
    let payload_hash = hex::encode(sha2::Sha256::digest([])).to_ascii_uppercase();

    let create = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/create-uppercase-payload-hash.txt?uploads")
                .header("x-amz-content-sha256", payload_hash)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    let body = response_text(create).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported x-amz-content-sha256 payload mode"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_rejects_actual_sha256_empty_payload_hash_mismatch() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);

    let create = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/create-bad-payload-hash.txt?uploads")
                .header("x-amz-content-sha256", "0".repeat(64))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    let body = response_text(create).await;
    assert!(body.contains("<Code>BadDigest</Code>"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_accepts_signed_request_allowed_by_auth_policy() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_buckets: BTreeSet::from(["test-bucket".to_owned()]),
            allowed_actions: BTreeSet::from([S3Action::CreateMultipartUpload]),
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
        method: "POST",
        path: "/test-bucket/policy-multipart.txt",
        canonical_query: "uploads=",
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers: "host;x-amz-content-sha256;x-amz-date",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/policy-multipart.txt?uploads")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("<UploadId>"));
    let upload_id = tag_value(&body, "UploadId").expect("upload id");
    let upload_id = UploadId::parse(upload_id).expect("valid upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert_eq!(
        session
            .owner_access_key_id
            .as_ref()
            .map(|access_key| access_key.as_str()),
        Some("test")
    );
}

#[tokio::test]
async fn multipart_operations_hide_uploads_owned_by_another_credential() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let allowed_actions = BTreeSet::from([
        S3Action::CreateMultipartUpload,
        S3Action::UploadPart,
        S3Action::ListMultipartUploadParts,
        S3Action::CompleteMultipartUpload,
        S3Action::AbortMultipartUpload,
    ]);
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_buckets: BTreeSet::from(["test-bucket".to_owned()]),
            allowed_actions: allowed_actions.clone(),
            credentials: vec![AccessKeyConfig {
                access_key_id: "client".to_owned(),
                secret_key: "clientsecret".to_owned(),
                session_token: None,
                active: true,
                allowed_buckets: BTreeSet::from(["test-bucket".to_owned()]),
                allowed_actions,
            }],
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: UploadLimits {
            min_non_final_part_size: 1,
            ..UploadLimits::default()
        },
    })
    .await
    .expect("create app state");
    let app = router(state.clone());
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let key = "owned-by-test.txt";

    let create_auth = common::authorization_header(common::SignatureInput {
        method: "POST",
        path: &format!("/test-bucket/{key}"),
        canonical_query: "uploads=",
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });
    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/test-bucket/{key}?uploads"))
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, create_auth)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");
    assert_eq!(create.status(), StatusCode::OK);
    let create_body = response_text(create).await;
    let upload_id = tag_value(&create_body, "UploadId").expect("upload id");

    let owner_part_auth = common::authorization_header(common::SignatureInput {
        method: "PUT",
        path: &format!("/test-bucket/{key}"),
        canonical_query: &format!("partNumber=1&uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });
    let owner_part = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/{key}?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, owner_part_auth)
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send owner part");
    assert_eq!(owner_part.status(), StatusCode::OK);
    let etag = owner_part
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("etag string")
        .to_owned();

    let client_part_auth = common::authorization_header(common::SignatureInput {
        method: "PUT",
        path: &format!("/test-bucket/{key}"),
        canonical_query: &format!("partNumber=2&uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "client",
        secret_key: "clientsecret",
        region: "us-east-1",
    });
    let client_part = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/{key}?partNumber=2&uploadId={upload_id}"
                ))
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, client_part_auth)
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send client part");
    assert_eq!(client_part.status(), StatusCode::NOT_FOUND);
    let body = response_text(client_part).await;
    assert!(body.contains("<Code>NoSuchUpload</Code>"));

    let client_list_auth = common::authorization_header(common::SignatureInput {
        method: "GET",
        path: &format!("/test-bucket/{key}"),
        canonical_query: &format!("uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "client",
        secret_key: "clientsecret",
        region: "us-east-1",
    });
    let client_list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/test-bucket/{key}?uploadId={upload_id}"))
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, client_list_auth)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send client list");
    assert_eq!(client_list.status(), StatusCode::NOT_FOUND);

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let client_complete_auth = common::authorization_header(common::SignatureInput {
        method: "POST",
        path: &format!("/test-bucket/{key}"),
        canonical_query: &format!("uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "client",
        secret_key: "clientsecret",
        region: "us-east-1",
    });
    let client_complete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/test-bucket/{key}?uploadId={upload_id}"))
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, client_complete_auth)
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send client complete");
    assert_eq!(client_complete.status(), StatusCode::NOT_FOUND);

    let client_abort_auth = common::authorization_header(common::SignatureInput {
        method: "DELETE",
        path: &format!("/test-bucket/{key}"),
        canonical_query: &format!("uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "client",
        secret_key: "clientsecret",
        region: "us-east-1",
    });
    let client_abort = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/test-bucket/{key}?uploadId={upload_id}"))
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, client_abort_auth)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send client abort");
    assert_eq!(client_abort.status(), StatusCode::NOT_FOUND);

    let parsed_upload_id = UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&parsed_upload_id)
        .expect("upload session");
    assert_eq!(session.parts.len(), 1);
    assert!(
        state
            .object_store
            .head_object(
                &BucketName::parse("test-bucket").expect("bucket"),
                &ObjectKey::parse(key).expect("key"),
            )
            .await
            .expect("read metadata")
            .is_none()
    );
}

#[tokio::test]
async fn multipart_create_rejects_signed_request_for_disallowed_action() {
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
        method: "POST",
        path: "/test-bucket/policy-denied.txt",
        canonical_query: "uploads=",
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers: "host;x-amz-content-sha256;x-amz-date",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/policy-denied.txt?uploads")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_rejects_anonymous_request_for_disallowed_bucket() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            allowed_buckets: BTreeSet::from(["other-bucket".to_owned()]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/anonymous-denied.txt?uploads")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_operations_reject_signed_requests_for_disallowed_actions() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::CreateMultipartUpload]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: UploadLimits {
            min_non_final_part_size: 1,
            ..UploadLimits::default()
        },
    })
    .await
    .expect("create app state");
    let app = router(state.clone());
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let upload_id = create_upload(app.clone(), "/test-bucket/policy-upload-part.txt").await;
    let upload_part_auth = common::authorization_header(common::SignatureInput {
        method: "PUT",
        path: "/test-bucket/policy-upload-part.txt",
        canonical_query: &format!("partNumber=1&uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });
    let upload_part = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/policy-upload-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, upload_part_auth)
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(upload_part.status(), StatusCode::FORBIDDEN);
    let parsed_upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&parsed_upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());

    let upload_id = create_upload(app.clone(), "/test-bucket/policy-list-parts.txt").await;
    upload_part_for_key(app.clone(), &upload_id, "policy-list-parts.txt", 1, "part").await;
    let list_auth = common::authorization_header(common::SignatureInput {
        method: "GET",
        path: "/test-bucket/policy-list-parts.txt",
        canonical_query: &format!("uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });
    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/policy-list-parts.txt?uploadId={upload_id}"
                ))
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, list_auth)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list parts");
    assert_eq!(list.status(), StatusCode::FORBIDDEN);

    let upload_id = create_upload(app.clone(), "/test-bucket/policy-complete.txt").await;
    let etag = upload_part_for_key(app.clone(), &upload_id, "policy-complete.txt", 1, "part").await;
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete_auth = common::authorization_header(common::SignatureInput {
        method: "POST",
        path: "/test-bucket/policy-complete.txt",
        canonical_query: &format!("uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });
    let complete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/policy-complete.txt?uploadId={upload_id}"
                ))
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, complete_auth)
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::FORBIDDEN);
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("policy-complete.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
    let parsed_upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    assert!(
        state
            .multipart_store
            .get_upload(&parsed_upload_id)
            .is_some()
    );

    let upload_id = create_upload(app.clone(), "/test-bucket/policy-abort.txt").await;
    let abort_auth = common::authorization_header(common::SignatureInput {
        method: "DELETE",
        path: "/test-bucket/policy-abort.txt",
        canonical_query: &format!("uploadId={upload_id}"),
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });
    let abort = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/test-bucket/policy-abort.txt?uploadId={upload_id}"
                ))
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, abort_auth)
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send abort");
    assert_eq!(abort.status(), StatusCode::FORBIDDEN);
    let parsed_upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    assert!(
        state
            .multipart_store
            .get_upload(&parsed_upload_id)
            .is_some()
    );
}

#[tokio::test]
async fn multipart_uploading_same_part_number_replaces_previous_part() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/replaced-part.txt").await;

    let old_etag =
        upload_part_for_key(app.clone(), &upload_id, "replaced-part.txt", 1, "old-body").await;
    let new_etag =
        upload_part_for_key(app.clone(), &upload_id, "replaced-part.txt", 1, "new-body").await;
    assert_ne!(old_etag, new_etag);

    let old_complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{old_etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let old_complete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/replaced-part.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, old_complete_xml.len().to_string())
                .body(Body::from(old_complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete with old etag");
    assert_eq!(old_complete.status(), StatusCode::BAD_REQUEST);
    let old_complete_body = response_text(old_complete).await;
    assert!(old_complete_body.contains("<Code>InvalidPart</Code>"));

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{new_etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/replaced-part.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("replaced-part.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, "new-body".len() as u64);
}

#[tokio::test]
async fn multipart_replace_part_restores_previous_file_when_session_persist_fails() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/replaced-part-rollback.txt").await;

    let old_body = "old-body-that-must-remain";
    let new_body = "new-body-that-must-not-publish";
    let old_etag = upload_part_for_key(
        app.clone(),
        &upload_id,
        "replaced-part-rollback.txt",
        1,
        old_body,
    )
    .await;

    let upload_dir = temp_dir.path().join("multipart").join(&upload_id);
    let session_path = upload_dir.join("session.json");
    std::fs::remove_file(&session_path).expect("remove session file");
    std::fs::create_dir(&session_path).expect("replace session file with directory");

    let replace = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/replaced-part-rollback.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, new_body.len().to_string())
                .body(Body::from(new_body))
                .expect("build request"),
        )
        .await
        .expect("send replacement part");
    assert_eq!(replace.status(), StatusCode::INTERNAL_SERVER_ERROR);

    std::fs::remove_dir(&session_path).expect("remove blocking session directory");
    let checksum = expected_crc32_checksum(old_body.as_bytes());
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{old_etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/replaced-part-rollback.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .header("x-amz-checksum-crc32", checksum)
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("replaced-part-rollback.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, old_body.len() as u64);
}

#[tokio::test]
async fn multipart_new_part_rolls_back_session_when_session_persist_fails() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/new-part-rollback.txt").await;

    let upload_dir = temp_dir.path().join("multipart").join(&upload_id);
    let session_path = upload_dir.join("session.json");
    std::fs::remove_file(&session_path).expect("remove session file");
    std::fs::create_dir(&session_path).expect("replace session file with directory");

    let upload = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/new-part-rollback.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(upload.status(), StatusCode::INTERNAL_SERVER_ERROR);

    std::fs::remove_dir(&session_path).expect("remove blocking session directory");
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);
    let session = state
        .multipart_store
        .get_upload(&UploadId::parse(&upload_id).expect("upload id"))
        .expect("upload session");
    assert!(session.parts.is_empty());

    let complete_xml = "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>\"missing\"</ETag></Part>\
         </CompleteMultipartUpload>";
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/new-part-rollback.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>InvalidPart</Code>"));
}

#[tokio::test]
async fn multipart_routes_percent_encoded_operation_query_names() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/encoded-query.txt?%75ploads")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");
    assert_eq!(create.status(), StatusCode::OK);
    let upload_id = tag_value(&response_text(create).await, "UploadId").expect("upload id");

    let upload_part = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/encoded-query.txt?part%4Eumber=1&upload%49d={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(upload_part.status(), StatusCode::OK);

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/encoded-query.txt?upload%49d={upload_id}&max%2Dparts=1"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = response_text(list).await;
    assert!(list_body.contains("<MaxParts>1</MaxParts>"));
    assert!(list_body.contains("<PartNumber>1</PartNumber>"));

    let etag = upload_part
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("etag")
        .to_owned();
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/encoded-query.txt?upload%49d={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("encoded-query.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn multipart_operations_reject_invalid_query_utf8() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/invalid-query-name.txt?%FFploads")
                .body(Body::empty())
                .expect("build create request"),
        )
        .await
        .expect("send create");
    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    let body = response_text(create).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("query string contains invalid percent-encoded UTF-8"));

    let upload_part = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/invalid-query-value.txt?partNumber=1&uploadId=%FF")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build upload part request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(upload_part.status(), StatusCode::BAD_REQUEST);
    let body = response_text(upload_part).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("query string contains invalid percent-encoded UTF-8"));
}

#[tokio::test]
async fn multipart_create_rejects_ambiguous_uploads_and_upload_id_query() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/ambiguous-query.txt?uploads&uploadId=existing")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("multipart operation query is ambiguous"));
}

#[tokio::test]
async fn multipart_create_rejects_duplicate_uploads_query_flag() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/duplicate-uploads-query.txt?uploads&upload%73=")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("uploads must not appear more than once"));
}

#[tokio::test]
async fn multipart_upload_part_rejects_duplicate_operation_query_params() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/duplicate-query.txt").await;

    let duplicate_upload_id = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/duplicate-query.txt?partNumber=1&uploadId={upload_id}&upload%49d={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(duplicate_upload_id.status(), StatusCode::BAD_REQUEST);
    let body = response_text(duplicate_upload_id).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("uploadId must not appear more than once"));

    let duplicate_part_number = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/duplicate-query.txt?partNumber=1&part%4Eumber=2&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(duplicate_part_number.status(), StatusCode::BAD_REQUEST);
    let body = response_text(duplicate_part_number).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("partNumber must not appear more than once"));
}

#[tokio::test]
async fn multipart_upload_part_rejects_upload_id_without_part_number() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/missing-part-number.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/missing-part-number.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("partNumber is required"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("missing-part-number.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn multipart_upload_part_rejects_part_number_without_upload_id() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/missing-upload-id.txt?partNumber=1")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("uploadId is required"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("missing-upload-id.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn multipart_list_parts_rejects_duplicate_pagination_query_param() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/duplicate-list-query.txt").await;
    upload_part_for_key(
        app.clone(),
        &upload_id,
        "duplicate-list-query.txt",
        1,
        "part",
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/duplicate-list-query.txt?uploadId={upload_id}&max-parts=1&max%2Dparts=2"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("max-parts must not appear more than once"));
}

#[tokio::test]
async fn multipart_operations_reject_malformed_upload_id_before_lookup() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/bad-upload-id.txt?uploadId=..%2Foutside")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("invalid upload ID"));
}

#[tokio::test]
async fn multipart_upload_survives_app_state_restart() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/restart.txt").await;
    let first_part = vec![b'r'; MIN_MULTIPART_NON_FINAL_PART_SIZE];
    let etag1 =
        upload_part_bytes_for_key(app.clone(), &upload_id, "restart.txt", 1, first_part).await;
    let etag2 = upload_part_for_key(app, &upload_id, "restart.txt", 2, "again").await;

    let restarted_state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("restart app state");
    let restarted_app = router(restarted_state.clone());

    let list = restarted_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/test-bucket/restart.txt?uploadId={upload_id}"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = response_text(list).await;
    assert!(list_body.contains("<PartNumber>1</PartNumber>"));
    assert!(list_body.contains("<PartNumber>2</PartNumber>"));

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = restarted_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/test-bucket/restart.txt?uploadId={upload_id}"))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);

    let metadata = restarted_state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("restart.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.size,
        (MIN_MULTIPART_NON_FINAL_PART_SIZE + 5) as u64
    );
}

#[tokio::test]
async fn multipart_restart_removes_stale_temp_files_and_keeps_session() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/restart-cleanup.txt").await;
    let first_part = vec![b'c'; MIN_MULTIPART_NON_FINAL_PART_SIZE];
    let etag1 = upload_part_bytes_for_key(
        app.clone(),
        &upload_id,
        "restart-cleanup.txt",
        1,
        first_part,
    )
    .await;
    let etag2 = upload_part_for_key(app, &upload_id, "restart-cleanup.txt", 2, "done").await;

    let upload_dir = temp_dir.path().join("multipart").join(&upload_id);
    std::fs::write(upload_dir.join("00003.interrupted.tmp"), b"partial part")
        .expect("write stale part temp file");
    std::fs::write(
        upload_dir.join("session.interrupted.tmp"),
        b"partial session",
    )
    .expect("write stale session temp file");

    let restarted_state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("restart app state");
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let restarted_app = router(restarted_state.clone());
    let list = restarted_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/restart-cleanup.txt?uploadId={upload_id}"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::OK);
    let list_body = response_text(list).await;
    assert!(list_body.contains("<PartNumber>1</PartNumber>"));
    assert!(list_body.contains("<PartNumber>2</PartNumber>"));

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = restarted_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/restart-cleanup.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);

    let metadata = restarted_state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("restart-cleanup.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.size,
        (MIN_MULTIPART_NON_FINAL_PART_SIZE + 4) as u64
    );
}

#[tokio::test]
async fn multipart_complete_preserves_initiated_metadata() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/metadata-multipart.txt?uploads")
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_ENCODING, "gzip")
                .header(header::CONTENT_DISPOSITION, "attachment")
                .header(header::CONTENT_LANGUAGE, "en-US")
                .header(header::CACHE_CONTROL, "no-cache")
                .header(header::EXPIRES, "Wed, 21 Oct 2026 07:28:00 GMT")
                .header("x-amz-tagging", "kind=multipart")
                .header("x-amz-meta-owner", "rust")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");
    assert_eq!(create.status(), StatusCode::OK);
    let upload_id = tag_value(&response_text(create).await, "UploadId").expect("upload id");

    let first_part = vec![b'm'; MIN_MULTIPART_NON_FINAL_PART_SIZE];
    let etag1 = upload_part_bytes_for_key(
        app.clone(),
        &upload_id,
        "metadata-multipart.txt",
        1,
        first_part,
    )
    .await;
    let etag2 = upload_part_for_key(
        app.clone(),
        &upload_id,
        "metadata-multipart.txt",
        2,
        "final",
    )
    .await;
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/metadata-multipart.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("metadata-multipart.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.content_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(metadata.content_encoding.as_deref(), Some("gzip"));
    assert_eq!(metadata.content_disposition.as_deref(), Some("attachment"));
    assert_eq!(metadata.content_language.as_deref(), Some("en-US"));
    assert_eq!(metadata.cache_control.as_deref(), Some("no-cache"));
    assert_eq!(
        metadata.expires.as_deref(),
        Some("Wed, 21 Oct 2026 07:28:00 GMT")
    );
    assert_eq!(metadata.tagging.as_deref(), Some("kind=multipart"));
    assert_eq!(
        metadata.user_metadata,
        BTreeMap::from([("x-amz-meta-owner".to_owned(), "rust".to_owned())])
    );
}

#[tokio::test]
async fn multipart_create_rejects_non_ascii_user_metadata_value() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/non-ascii-metadata-multipart.txt?uploads")
                .header(
                    "x-amz-meta-owner",
                    HeaderValue::from_bytes(b"\xFF").expect("header value"),
                )
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-meta-owner must be valid ASCII"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_rejects_duplicate_user_metadata_headers() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);
    let mut request = Request::builder()
        .method("POST")
        .uri("/test-bucket/duplicate-metadata-multipart.txt?uploads")
        .header("x-amz-meta-owner", "rust")
        .body(Body::empty())
        .expect("build request");
    request
        .headers_mut()
        .append("x-amz-meta-owner", HeaderValue::from_static("duplicate"));

    let response = app.oneshot(request).await.expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-meta-owner must not appear more than once"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_rejects_duplicate_persisted_metadata_headers() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);
    let mut request = Request::builder()
        .method("POST")
        .uri("/test-bucket/duplicate-content-type-multipart.txt?uploads")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::empty())
        .expect("build request");
    request.headers_mut().append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let response = app.oneshot(request).await.expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("content-type must not appear more than once"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_rejects_non_empty_body_framing_without_creating_session() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/non-empty-create.txt?uploads")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("CreateMultipartUpload requires Content-Length: 0"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_rejects_unsupported_object_lock_header() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/locked.txt?uploads")
                .header("x-amz-object-lock-mode", "GOVERNANCE")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported upload header"));
}

#[tokio::test]
async fn multipart_create_persists_checksum_algorithm_and_type() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/checksum-negotiated.txt?uploads")
                .header("x-amz-checksum-algorithm", "crc32c")
                .header("x-amz-checksum-type", "full_object")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::OK);
    let upload_id = tag_value(&response_text(response).await, "UploadId").expect("upload id");
    let upload_id = UploadId::parse(upload_id).expect("valid upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");

    assert_eq!(
        session.metadata.checksum_algorithm,
        Some(ChecksumAlgorithm::Crc32c)
    );
    assert_eq!(
        session.metadata.checksum_type,
        Some(ChecksumType::FullObject)
    );
}

#[tokio::test]
async fn multipart_create_rejects_unsupported_checksum_algorithm() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/unsupported-create-checksum.txt?uploads")
                .header("x-amz-checksum-algorithm", "CRC64NVME")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Checksum algorithm not supported"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_rejects_unsupported_checksum_type() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/unsupported-create-checksum-type.txt?uploads")
                .header("x-amz-checksum-type", "UNKNOWN")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-checksum-type must be COMPOSITE or FULL_OBJECT"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_create_rejects_percent_decoded_control_character_in_key() {
    let (state, temp_dir) = test_state().await;
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/bad%0Akey.txt?uploads")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("object key contains invalid characters"));

    let upload_dirs = std::fs::read_dir(temp_dir.path().join("multipart"))
        .expect("read multipart root")
        .collect::<Result<Vec<_>, _>>()
        .expect("read multipart entries");
    assert!(upload_dirs.is_empty());
}

#[tokio::test]
async fn multipart_complete_accepts_matching_full_object_checksum() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/complete-checksum.txt").await;
    let first_part = vec![b'c'; MIN_MULTIPART_NON_FINAL_PART_SIZE];
    let mut full_body = first_part.clone();
    full_body.extend_from_slice(b"final");
    let checksum = expected_crc32_checksum(&full_body);
    let etag1 = upload_part_bytes_for_key(
        app.clone(),
        &upload_id,
        "complete-checksum.txt",
        1,
        first_part,
    )
    .await;
    let etag2 =
        upload_part_for_key(app.clone(), &upload_id, "complete-checksum.txt", 2, "final").await;

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/complete-checksum.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .header("x-amz-checksum-crc32", &checksum)
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);
    assert_eq!(
        complete
            .headers()
            .get("x-amz-checksum-crc32")
            .expect("checksum response header"),
        checksum.as_str()
    );
    assert_eq!(
        complete
            .headers()
            .get("x-amz-checksum-type")
            .expect("checksum type response header"),
        "FULL_OBJECT"
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("complete-checksum.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.checksums.get("x-amz-checksum-crc32"),
        Some(&checksum)
    );
}

#[tokio::test]
async fn multipart_complete_validates_actual_sha256_against_completion_xml_not_final_object() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/complete-payload-hash.txt").await;
    let first_part = vec![b'h'; MIN_MULTIPART_NON_FINAL_PART_SIZE];
    let etag1 = upload_part_bytes_for_key(
        app.clone(),
        &upload_id,
        "complete-payload-hash.txt",
        1,
        first_part,
    )
    .await;
    let etag2 = upload_part_for_key(
        app.clone(),
        &upload_id,
        "complete-payload-hash.txt",
        2,
        "final",
    )
    .await;

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let payload_hash = hex::encode(sha2::Sha256::digest(complete_xml.as_bytes()));
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/complete-payload-hash.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .header("x-amz-content-sha256", payload_hash)
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("complete-payload-hash.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.size,
        (MIN_MULTIPART_NON_FINAL_PART_SIZE + "final".len()) as u64
    );
}

#[tokio::test]
async fn multipart_complete_rejects_actual_sha256_completion_xml_mismatch_without_closing_upload() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/complete-bad-payload-hash.txt").await;
    let first_part = vec![b'h'; MIN_MULTIPART_NON_FINAL_PART_SIZE];
    let etag1 = upload_part_bytes_for_key(
        app.clone(),
        &upload_id,
        "complete-bad-payload-hash.txt",
        1,
        first_part,
    )
    .await;
    let etag2 = upload_part_for_key(
        app.clone(),
        &upload_id,
        "complete-bad-payload-hash.txt",
        2,
        "final",
    )
    .await;

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/complete-bad-payload-hash.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .header("x-amz-content-sha256", "0".repeat(64))
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>BadDigest</Code>"));

    let parsed_upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&parsed_upload_id)
        .expect("upload session");
    assert_eq!(session.parts.len(), 2);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("complete-bad-payload-hash.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn multipart_complete_rejects_full_object_checksum_mismatch() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/complete-bad-checksum.txt").await;
    let first_part = vec![b'd'; MIN_MULTIPART_NON_FINAL_PART_SIZE];
    let etag1 = upload_part_bytes_for_key(
        app.clone(),
        &upload_id,
        "complete-bad-checksum.txt",
        1,
        first_part,
    )
    .await;
    let etag2 = upload_part_for_key(
        app.clone(),
        &upload_id,
        "complete-bad-checksum.txt",
        2,
        "final",
    )
    .await;

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/complete-bad-checksum.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .header("x-amz-checksum-crc32", "AAAAAA==")
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>BadDigest</Code>"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("complete-bad-checksum.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn multipart_list_parts_paginates_with_part_number_marker() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/paged.txt").await;
    upload_part_for_key(app.clone(), &upload_id, "paged.txt", 1, "one").await;
    upload_part_for_key(app.clone(), &upload_id, "paged.txt", 2, "two").await;
    upload_part_for_key(app.clone(), &upload_id, "paged.txt", 3, "three").await;

    let first_page = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/paged.txt?uploadId={upload_id}&max-parts=2"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send first list");
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page = response_text(first_page).await;
    assert!(first_page.contains("<PartNumber>1</PartNumber>"));
    assert!(first_page.contains("<PartNumber>2</PartNumber>"));
    assert!(!first_page.contains("<PartNumber>3</PartNumber>"));
    assert!(first_page.contains("<IsTruncated>true</IsTruncated>"));
    assert!(first_page.contains("<NextPartNumberMarker>2</NextPartNumberMarker>"));

    let second_page = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/paged.txt?uploadId={upload_id}&max-parts=2&part-number-marker=2"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send second list");
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page = response_text(second_page).await;
    assert!(!second_page.contains("<PartNumber>1</PartNumber>"));
    assert!(!second_page.contains("<PartNumber>2</PartNumber>"));
    assert!(second_page.contains("<PartNumber>3</PartNumber>"));
    assert!(second_page.contains("<PartNumberMarker>2</PartNumberMarker>"));
    assert!(second_page.contains("<IsTruncated>false</IsTruncated>"));
    assert!(!second_page.contains("<NextPartNumberMarker>"));
}

#[tokio::test]
async fn multipart_list_parts_caps_max_parts_at_1000() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/capped-list.txt").await;
    upload_part_for_key(app.clone(), &upload_id, "capped-list.txt", 1, "one").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/capped-list.txt?uploadId={upload_id}&max-parts=5000"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");

    assert_eq!(response.status(), StatusCode::OK);
    let body = response_text(response).await;
    assert!(body.contains("<MaxParts>1000</MaxParts>"));
    assert!(body.contains("<PartNumber>1</PartNumber>"));
}

#[tokio::test]
async fn multipart_list_parts_rejects_zero_max_parts() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/zero-max-parts.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/zero-max-parts.txt?uploadId={upload_id}&max-parts=0"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidArgument</Code>"));
    assert!(body.contains("max-parts must be in 1..=1000"));
}

#[tokio::test]
async fn multipart_list_parts_rejects_invalid_part_number_marker() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/bad-marker.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/bad-marker.txt?uploadId={upload_id}&part-number-marker=abc"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidArgument</Code>"));
    assert!(body.contains("part-number-marker must be an integer"));
}

#[tokio::test]
async fn multipart_upload_part_accepts_decoded_http_chunked_body() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/chunked-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/chunked-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::TRANSFER_ENCODING, "chunked")
                .body(Body::from("chunked-part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::ETAG).is_some());
}

#[tokio::test]
async fn multipart_upload_part_rejects_short_content_length_body() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/short-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/short-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "10")
                .body(Body::from("short"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Length does not match request body length"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_long_content_length_body() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/long-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/long-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("too long"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Length does not match request body length"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_invalid_content_length_before_creating_temp_file() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/bad-content-length-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/bad-content-length-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "not-a-number")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Length must be an integer"));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_duplicate_content_length_before_creating_temp_file() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/duplicate-content-length-part.txt",
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/duplicate-content-length-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Length must not appear more than once"));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_unsupported_transfer_encoding_before_creating_temp_file() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/unsupported-transfer-encoding-part.txt",
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/unsupported-transfer-encoding-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::TRANSFER_ENCODING, "gzip")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported Transfer-Encoding; only chunked is supported"));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_plain_content_length_with_transfer_encoding() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/content-length-with-transfer-encoding-part.txt",
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/content-length-with-transfer-encoding-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header(header::TRANSFER_ENCODING, "chunked")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains(
        "Content-Length must not be used with Transfer-Encoding for non aws-chunked uploads"
    ));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_body_larger_than_configured_part_limit() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: UploadLimits {
            max_part_size: 4,
            min_non_final_part_size: 1,
            ..UploadLimits::default()
        },
    })
    .await
    .expect("create app state");
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/too-large-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/too-large-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "5")
                .body(Body::from("12345"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = response_text(response).await;
    assert!(body.contains("<Code>EntityTooLarge</Code>"));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_cleans_temp_file_when_commit_fails_before_publish() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/commit-part-fails.txt").await;

    let parts_dir = temp_dir
        .path()
        .join("multipart")
        .join(&upload_id)
        .join("parts");
    std::fs::remove_dir_all(&parts_dir).expect("remove parts dir");
    std::fs::write(&parts_dir, b"not a directory").expect("replace parts dir with file");

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/commit-part-fails.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_unsupported_sse_customer_header() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/unsupported-part-header.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/unsupported-part-header.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-server-side-encryption-customer-algorithm", "AES256")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported upload header"));
}

#[tokio::test]
async fn multipart_upload_part_rejects_upload_part_copy_header() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/unsupported-part-copy.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/unsupported-part-copy.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "0")
                .header("x-amz-copy-source", "/test-bucket/source.txt")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported upload header: x-amz-copy-source"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_returns_validated_checksum_header() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/checksummed-part.txt").await;
    let body = b"checksummed multipart part";
    let checksum = expected_crc32_checksum(body);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/checksummed-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-checksum-crc32", &checksum)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-crc32")
            .expect("checksum response header"),
        checksum.as_str()
    );

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    let part = session
        .parts
        .get(&PartNumber::parse(1).expect("part number"))
        .expect("part metadata");
    assert_eq!(part.checksums.get("x-amz-checksum-crc32"), Some(&checksum));
}

#[tokio::test]
async fn multipart_list_parts_returns_part_checksum_elements() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/list-checksummed-part.txt").await;
    let body = b"checksummed multipart part";
    let checksum = expected_crc32_checksum(body);

    let upload_part = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/list-checksummed-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-checksum-crc32", &checksum)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(upload_part.status(), StatusCode::OK);

    let list_parts = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/list-checksummed-part.txt?uploadId={upload_id}"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list parts");

    assert_eq!(list_parts.status(), StatusCode::OK);
    let body = response_text(list_parts).await;
    assert!(body.contains("<PartNumber>1</PartNumber>"));
    assert!(body.contains(&format!("<ChecksumCRC32>{checksum}</ChecksumCRC32>")));
}

#[tokio::test]
async fn multipart_upload_part_accepts_matching_content_md5() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/content-md5-part.txt").await;
    let body = b"md5 validated multipart part";
    let content_md5 = BASE64.encode(Md5::digest(body));

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/content-md5-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("content-md5", content_md5)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
    assert!(response.headers().get(header::ETAG).is_some());

    let upload_id = UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(
        session
            .parts
            .contains_key(&PartNumber::parse(1).expect("part number"))
    );
}

#[tokio::test]
async fn multipart_upload_part_rejects_content_md5_mismatch() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/bad-content-md5-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/bad-content-md5-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header("content-md5", BASE64.encode([0_u8; 16]))
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>BadDigest</Code>"));
    assert!(body.contains("The Content-MD5 you specified did not match what we received."));

    let upload_id = UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_checksum_header_with_wrong_decoded_length() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/bad-checksum-length-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/bad-checksum-length-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-checksum-crc32", BASE64.encode([0_u8; 1]))
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-checksum-crc32 must decode to 4 bytes"));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_accepts_aws_chunked_trailer_checksum() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/aws-chunked-part.txt").await;
    let decoded = b"aws chunked multipart part";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);
    let expected_checksum = expected_crc32_checksum(decoded);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/aws-chunked-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::ETAG).is_some());
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-crc32")
            .expect("checksum response header"),
        expected_checksum.as_str()
    );

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    let part = session
        .parts
        .get(&PartNumber::parse(1).expect("part number"))
        .expect("part metadata");
    assert_eq!(
        part.checksums.get("x-amz-checksum-crc32"),
        Some(&expected_checksum)
    );
}

#[tokio::test]
async fn multipart_upload_part_accepts_aws_chunked_with_transfer_encoding_chunked() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/aws-chunked-transfer-encoding-part.txt",
    )
    .await;
    let decoded = b"aws chunked transfer encoded part";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);
    let expected_checksum = expected_crc32_checksum(decoded);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/aws-chunked-transfer-encoding-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::TRANSFER_ENCODING, "chunked")
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-crc32")
            .expect("checksum response header"),
        expected_checksum.as_str()
    );

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    let part = session
        .parts
        .get(&PartNumber::parse(1).expect("part number"))
        .expect("part metadata");
    assert_eq!(part.size, decoded.len() as u64);
    assert_eq!(
        part.checksums.get("x-amz-checksum-crc32"),
        Some(&expected_checksum)
    );
}

#[tokio::test]
async fn multipart_upload_part_rejects_aws_chunked_without_decoded_content_length() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/aws-chunked-missing-length-part.txt",
    )
    .await;
    let decoded = b"missing decoded length part";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/aws-chunked-missing-length-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-decoded-content-length is required"));
}

#[tokio::test]
async fn multipart_upload_part_rejects_aws_chunked_decoded_content_length_mismatch() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id =
        create_upload(app.clone(), "/test-bucket/aws-chunked-bad-length-part.txt").await;
    let decoded = b"bad decoded length part";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/aws-chunked-bad-length-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header(
                    "x-amz-decoded-content-length",
                    (decoded.len() + 1).to_string(),
                )
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("does not match decoded body length"));
}

#[tokio::test]
async fn multipart_upload_part_streams_split_aws_chunked_body() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/aws-chunked-split-part.txt").await;
    let decoded = b"split aws chunked multipart part";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/aws-chunked-split-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(split_body(encoded, 2))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get(header::ETAG).is_some());
}

#[tokio::test]
async fn multipart_upload_part_rejects_aws_chunked_trailer_checksum_mismatch() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/aws-chunked-bad-part.txt").await;
    let decoded = b"aws chunked multipart part";
    let encoded = aws_chunked_body_with_custom_trailer(decoded, "x-amz-checksum-crc32", "AAAAAA==");

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/aws-chunked-bad-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>BadDigest</Code>"));
}

#[tokio::test]
async fn multipart_upload_part_rejects_unsupported_checksum_header() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/unsupported-checksum-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/unsupported-checksum-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-checksum-crc64nvme", BASE64.encode([0_u8; 8]))
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Checksum algorithm not supported"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_non_ascii_sdk_checksum_algorithm() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id =
        create_upload(app.clone(), "/test-bucket/non-ascii-sdk-checksum-part.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/non-ascii-sdk-checksum-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header(
                    "x-amz-sdk-checksum-algorithm",
                    HeaderValue::from_bytes(b"\xFF").expect("header value"),
                )
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-sdk-checksum-algorithm must be valid ASCII"));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_sdk_checksum_algorithm_without_checksum_source() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/missing-sdk-checksum-source-part.txt",
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/missing-sdk-checksum-source-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(
        body.contains(
            "x-amz-sdk-checksum-algorithm requires a matching checksum header or trailer"
        )
    );
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_unsupported_payload_hash_mode() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/unsupported-payload-mode-part.txt",
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/unsupported-payload-mode-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-content-sha256", "NOT-A-SUPPORTED-PAYLOAD-MODE")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported x-amz-content-sha256 payload mode"));
}

#[tokio::test]
async fn multipart_upload_part_accepts_matching_actual_sha256_payload_hash() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/actual-sha256-part.txt").await;
    let body = b"actual sha256 multipart part";
    let payload_hash = hex::encode(sha2::Sha256::digest(body));

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/actual-sha256-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-content-sha256", payload_hash)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::OK);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    let part = session
        .parts
        .get(&PartNumber::parse(1).expect("part number"))
        .expect("part metadata");
    assert_eq!(part.size, body.len() as u64);
}

#[tokio::test]
async fn multipart_upload_part_rejects_actual_sha256_payload_hash_mismatch() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/bad-actual-sha256-part.txt").await;
    let body = b"actual sha256 multipart mismatch";

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/bad-actual-sha256-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-content-sha256", "0".repeat(64))
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>BadDigest</Code>"));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_unsupported_checksum_trailer() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/unsupported-checksum-trailer-part.txt",
    )
    .await;
    let decoded = b"unsupported trailer checksum part";
    let encoded =
        aws_chunked_body_with_custom_trailer(decoded, "x-amz-checksum-crc64nvme", "AAAAAAAAAAA=");

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/unsupported-checksum-trailer-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc64nvme")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Checksum algorithm not supported"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_missing_declared_checksum_trailer() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/missing-checksum-trailer-part.txt",
    )
    .await;
    let decoded = b"missing declared trailer part";
    let encoded = aws_chunked_body_without_trailers(decoded);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/missing-checksum-trailer-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Declared checksum trailer was not received"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_undeclared_checksum_trailer() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/undeclared-checksum-trailer-part.txt",
    )
    .await;
    let decoded = b"undeclared checksum trailer part";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/undeclared-checksum-trailer-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Checksum trailer was not declared: x-amz-checksum-crc32"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_unsupported_declared_trailer_name() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/unsupported-declared-trailer-part.txt",
    )
    .await;
    let decoded = b"unsupported declared trailer part";
    let encoded = aws_chunked_body_without_trailers(decoded);

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/unsupported-declared-trailer-part.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-meta-owner")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-trailer contains unsupported trailer name"));
    assert_upload_has_no_temp_part_files(temp_dir.path(), &upload_id);

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_upload_part_rejects_mismatched_key() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/right-key.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/wrong-key.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build request"),
        )
        .await
        .expect("send upload part");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_text(response).await;
    assert!(body.contains("<Code>NoSuchUpload</Code>"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.parts.is_empty());
}

#[tokio::test]
async fn multipart_list_parts_rejects_mismatched_key() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/list-right-key.txt").await;
    upload_part_for_key(app.clone(), &upload_id, "list-right-key.txt", 1, "part").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/list-wrong-key.txt?uploadId={upload_id}"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_text(response).await;
    assert!(body.contains("<Code>NoSuchUpload</Code>"));
}

#[tokio::test]
async fn multipart_no_body_operations_reject_actual_sha256_empty_payload_hash_mismatch() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/no-body-payload-hash.txt").await;
    upload_part_for_key(
        app.clone(),
        &upload_id,
        "no-body-payload-hash.txt",
        1,
        "part",
    )
    .await;

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/no-body-payload-hash.txt?uploadId={upload_id}"
                ))
                .header("x-amz-content-sha256", "0".repeat(64))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::BAD_REQUEST);
    let body = response_text(list).await;
    assert!(body.contains("<Code>BadDigest</Code>"));

    let abort = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/test-bucket/no-body-payload-hash.txt?uploadId={upload_id}"
                ))
                .header("x-amz-content-sha256", "0".repeat(64))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send abort");
    assert_eq!(abort.status(), StatusCode::BAD_REQUEST);
    let body = response_text(abort).await;
    assert!(body.contains("<Code>BadDigest</Code>"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert_eq!(session.parts.len(), 1);
}

#[tokio::test]
async fn multipart_control_operations_reject_unsupported_payload_hash_mode() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/unsupported-create.txt?uploads")
                .header("x-amz-content-sha256", "NOT-A-SUPPORTED-PAYLOAD-MODE")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");
    assert_eq!(create.status(), StatusCode::BAD_REQUEST);
    let body = response_text(create).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported x-amz-content-sha256 payload mode"));

    let upload_id = create_upload(app.clone(), "/test-bucket/unsupported-control.txt").await;
    upload_part_for_key(
        app.clone(),
        &upload_id,
        "unsupported-control.txt",
        1,
        "part",
    )
    .await;

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/unsupported-control.txt?uploadId={upload_id}"
                ))
                .header("x-amz-content-sha256", "NOT-A-SUPPORTED-PAYLOAD-MODE")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::BAD_REQUEST);
    let body = response_text(list).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported x-amz-content-sha256 payload mode"));

    let complete_xml = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag</ETag></Part></CompleteMultipartUpload>";
    let complete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/unsupported-control.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .header("x-amz-content-sha256", "NOT-A-SUPPORTED-PAYLOAD-MODE")
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported x-amz-content-sha256 payload mode"));

    let abort = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/test-bucket/unsupported-control.txt?uploadId={upload_id}"
                ))
                .header("x-amz-content-sha256", "NOT-A-SUPPORTED-PAYLOAD-MODE")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send abort");
    assert_eq!(abort.status(), StatusCode::BAD_REQUEST);
    let body = response_text(abort).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported x-amz-content-sha256 payload mode"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert_eq!(session.parts.len(), 1);
}

#[tokio::test]
async fn multipart_complete_rejects_mismatched_key_without_committing() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/complete-right-key.txt").await;
    let etag = upload_part_for_key(
        app.clone(),
        &upload_id,
        "complete-right-key.txt",
        1,
        "final",
    )
    .await;
    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/complete-wrong-key.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_text(response).await;
    assert!(body.contains("<Code>NoSuchUpload</Code>"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("complete-right-key.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    assert!(state.multipart_store.get_upload(&upload_id).is_some());
}

#[tokio::test]
async fn multipart_abort_rejects_mismatched_key_without_aborting() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/abort-right-key.txt").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/test-bucket/abort-wrong-key.txt?uploadId={upload_id}"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send abort");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_text(response).await;
    assert!(body.contains("<Code>NoSuchUpload</Code>"));

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    assert!(state.multipart_store.get_upload(&upload_id).is_some());
}

#[tokio::test]
async fn multipart_abort_rejects_non_empty_body_framing_without_aborting() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/abort-framed-body.txt").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/test-bucket/abort-framed-body.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build abort"),
        )
        .await
        .expect("send abort");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("AbortMultipartUpload requires Content-Length: 0"));

    let upload_id = UploadId::parse(upload_id).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&upload_id)
        .expect("upload session");
    assert!(session.is_open());
}

#[tokio::test]
async fn multipart_abort_removes_upload_session() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/test-bucket/abort.txt?uploads")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");
    let upload_id = tag_value(&response_text(create).await, "UploadId").expect("upload id");

    let abort = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/test-bucket/abort.txt?uploadId={upload_id}"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send abort");
    assert_eq!(abort.status(), StatusCode::NO_CONTENT);
    assert_has_request_id(&abort);
    assert_eq!(
        abort.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );

    let list = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/test-bucket/abort.txt?uploadId={upload_id}"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::NOT_FOUND);

    let upload_part = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/abort.txt?partNumber=1&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build upload part"),
        )
        .await
        .expect("send upload part");
    assert_eq!(upload_part.status(), StatusCode::NOT_FOUND);
    let body = response_text(upload_part).await;
    assert!(body.contains("<Code>NoSuchUpload</Code>"));
}

#[cfg(unix)]
#[tokio::test]
async fn multipart_abort_keeps_session_when_storage_delete_fails() {
    use std::os::unix::fs::PermissionsExt;

    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/abort-delete-fails.txt").await;
    upload_part_for_key(app.clone(), &upload_id, "abort-delete-fails.txt", 1, "part").await;

    let upload_dir = temp_dir.path().join("multipart").join(&upload_id);
    let blocker_dir = upload_dir.join("abort-cleanup-blocker");
    std::fs::create_dir(&blocker_dir).expect("create cleanup blocker");
    std::fs::set_permissions(&blocker_dir, std::fs::Permissions::from_mode(0o000))
        .expect("make cleanup blocker inaccessible");

    let abort = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!(
                    "/test-bucket/abort-delete-fails.txt?uploadId={upload_id}"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send abort");
    std::fs::set_permissions(&blocker_dir, std::fs::Permissions::from_mode(0o755))
        .expect("restore cleanup blocker permissions");

    assert_eq!(abort.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let parsed_upload_id =
        s3_endpoint::storage::UploadId::parse(upload_id.clone()).expect("upload id");
    let session = state
        .multipart_store
        .get_upload(&parsed_upload_id)
        .expect("upload session");
    assert_eq!(session.state, UploadState::Aborted);
    assert_eq!(session.parts.len(), 1);

    let upload_part = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/abort-delete-fails.txt?partNumber=2&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("part"))
                .expect("build upload part"),
        )
        .await
        .expect("send upload part");
    assert_eq!(upload_part.status(), StatusCode::NOT_FOUND);
}

#[cfg(unix)]
#[tokio::test]
async fn multipart_complete_succeeds_when_post_commit_cleanup_fails() {
    use std::os::unix::fs::PermissionsExt;

    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/complete-cleanup-fails.txt").await;
    let etag = upload_part_for_key(
        app.clone(),
        &upload_id,
        "complete-cleanup-fails.txt",
        1,
        "part",
    )
    .await;
    let upload_dir = temp_dir.path().join("multipart").join(&upload_id);
    let blocker_dir = upload_dir.join("cleanup-blocker");
    std::fs::create_dir(&blocker_dir).expect("create cleanup blocker");
    std::fs::set_permissions(&blocker_dir, std::fs::Permissions::from_mode(0o000))
        .expect("make cleanup blocker inaccessible");

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/complete-cleanup-fails.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");
    std::fs::set_permissions(&blocker_dir, std::fs::Permissions::from_mode(0o755))
        .expect("restore cleanup blocker permissions");

    assert_eq!(complete.status(), StatusCode::OK);
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("complete-cleanup-fails.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, 4);

    let parsed_upload_id =
        s3_endpoint::storage::UploadId::parse(upload_id.clone()).expect("upload id");
    assert!(
        state
            .multipart_store
            .get_upload(&parsed_upload_id)
            .is_none()
    );
    assert!(!upload_dir.join("session.json").exists());

    let list = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/test-bucket/complete-cleanup-fails.txt?uploadId={upload_id}"
                ))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send list");
    assert_eq!(list.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn multipart_complete_succeeds_when_session_file_cleanup_fails_after_commit() {
    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(
        app.clone(),
        "/test-bucket/complete-session-cleanup-fails.txt",
    )
    .await;
    let etag = upload_part_for_key(
        app.clone(),
        &upload_id,
        "complete-session-cleanup-fails.txt",
        1,
        "part",
    )
    .await;
    let upload_dir = temp_dir.path().join("multipart").join(&upload_id);
    let session_path = upload_dir.join("session.json");
    std::fs::remove_file(&session_path).expect("remove session file");
    std::fs::create_dir(&session_path).expect("replace session file with directory");

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/complete-session-cleanup-fails.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml.clone()))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::OK);
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("complete-session-cleanup-fails.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, 4);

    let parsed_upload_id = UploadId::parse(upload_id.clone()).expect("upload id");
    assert!(
        state
            .multipart_store
            .get_upload(&parsed_upload_id)
            .is_none()
    );

    let retry_complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/complete-session-cleanup-fails.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build retry request"),
        )
        .await
        .expect("send retry complete");
    assert_eq!(retry_complete.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn multipart_complete_rejects_wrong_etag() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/wrong-etag.txt").await;
    upload_part_for_key(app.clone(), &upload_id, "wrong-etag.txt", 1, "hello").await;

    let complete_xml = "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>\"not-the-etag\"</ETag></Part>\
         </CompleteMultipartUpload>";
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/test-bucket/wrong-etag.txt?uploadId={upload_id}"))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>InvalidPart</Code>"));
}

#[tokio::test]
async fn multipart_complete_accepts_escaped_etag_and_default_namespace() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/namespaced-complete.txt").await;
    let etag = upload_part_for_key(
        app.clone(),
        &upload_id,
        "namespaced-complete.txt",
        1,
        "hello",
    )
    .await;
    let escaped_etag = etag.replace('"', "&quot;");

    let complete_xml = format!(
        "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Part><PartNumber>1</PartNumber><ETag>{escaped_etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/namespaced-complete.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::OK);
    let body = response_text(complete).await;
    assert!(body.contains("<CompleteMultipartUploadResult"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("namespaced-complete.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, 5);
}

#[tokio::test]
async fn multipart_complete_rejects_out_of_order_parts() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/out-of-order.txt").await;
    let etag1 = upload_part_for_key(app.clone(), &upload_id, "out-of-order.txt", 1, "hello ").await;
    let etag2 = upload_part_for_key(app.clone(), &upload_id, "out-of-order.txt", 2, "world").await;

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/out-of-order.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>InvalidPart</Code>"));
}

#[tokio::test]
async fn multipart_complete_rejects_duplicate_part_numbers() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/duplicate-complete-part.txt").await;
    let etag = upload_part_for_key(
        app.clone(),
        &upload_id,
        "duplicate-complete-part.txt",
        1,
        "hello",
    )
    .await;

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         <Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/duplicate-complete-part.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>InvalidPart</Code>"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-complete-part.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());

    let upload_id = UploadId::parse(upload_id).expect("upload id");
    assert!(state.multipart_store.get_upload(&upload_id).is_some());
}

#[tokio::test]
async fn multipart_complete_rejects_small_non_final_part() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/small-non-final.txt").await;
    let etag1 =
        upload_part_for_key(app.clone(), &upload_id, "small-non-final.txt", 1, "small").await;
    let etag2 =
        upload_part_for_key(app.clone(), &upload_id, "small-non-final.txt", 2, "final").await;

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/small-non-final.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>EntityTooSmall</Code>"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("small-non-final.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn multipart_complete_rejects_object_larger_than_configured_limit() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: UploadLimits {
            max_object_size: 8,
            min_non_final_part_size: 1,
            ..UploadLimits::default()
        },
    })
    .await
    .expect("create app state");
    let app = router(state.clone());
    let upload_id = create_upload(app.clone(), "/test-bucket/too-large-complete.txt").await;
    let etag1 = upload_part_for_key(
        app.clone(),
        &upload_id,
        "too-large-complete.txt",
        1,
        "12345",
    )
    .await;
    let etag2 = upload_part_for_key(
        app.clone(),
        &upload_id,
        "too-large-complete.txt",
        2,
        "67890",
    )
    .await;

    let complete_xml = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/too-large-complete.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>EntityTooLarge</Code>"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("too-large-complete.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());

    let upload_id = s3_endpoint::storage::UploadId::parse(upload_id).expect("upload id");
    assert!(state.multipart_store.get_upload(&upload_id).is_some());
}

#[tokio::test]
async fn multipart_complete_rejects_malformed_xml() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/malformed.txt").await;

    let complete_xml = "<CompleteMultipartUpload><Part>";
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/test-bucket/malformed.txt?uploadId={upload_id}"))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>MalformedXML</Code>"));
}

#[tokio::test]
async fn multipart_complete_rejects_missing_etag() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state);
    let upload_id = create_upload(app.clone(), "/test-bucket/missing-etag.txt").await;
    upload_part_for_key(app.clone(), &upload_id, "missing-etag.txt", 1, "hello").await;

    let complete_xml = "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber></Part>\
         </CompleteMultipartUpload>";
    let complete = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/test-bucket/missing-etag.txt?uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, complete_xml.len().to_string())
                .body(Body::from(complete_xml))
                .expect("build request"),
        )
        .await
        .expect("send complete");

    assert_eq!(complete.status(), StatusCode::BAD_REQUEST);
    let body = response_text(complete).await;
    assert!(body.contains("<Code>MalformedXML</Code>"));
}

async fn upload_part(
    app: axum::Router,
    upload_id: &str,
    part_number: u16,
    body: &'static str,
) -> String {
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/multi.txt?partNumber={part_number}&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    response
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("etag string")
        .to_owned()
}

async fn create_upload(app: axum::Router, path: &str) -> String {
    let create = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("{path}?uploads"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send create");
    assert_eq!(create.status(), StatusCode::OK);
    assert_has_request_id(&create);
    tag_value(&response_text(create).await, "UploadId").expect("upload id")
}

async fn upload_part_for_key(
    app: axum::Router,
    upload_id: &str,
    key: &str,
    part_number: u16,
    body: &'static str,
) -> String {
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/{key}?partNumber={part_number}&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    response
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("etag string")
        .to_owned()
}

async fn upload_part_bytes_for_key(
    app: axum::Router,
    upload_id: &str,
    key: &str,
    part_number: u16,
    body: Vec<u8>,
) -> String {
    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!(
                    "/test-bucket/{key}?partNumber={part_number}&uploadId={upload_id}"
                ))
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("send upload part");
    if response.status() != StatusCode::OK {
        let status = response.status();
        panic!(
            "expected OK, got {status}: {}",
            response_text(response).await
        );
    }
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    response
        .headers()
        .get(header::ETAG)
        .expect("etag")
        .to_str()
        .expect("etag string")
        .to_owned()
}

async fn response_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    std::str::from_utf8(&body).expect("utf8 body").to_owned()
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

fn assert_upload_has_no_temp_part_files(root: &std::path::Path, upload_id: &str) {
    let upload_dir = root.join("multipart").join(upload_id);
    let entries = std::fs::read_dir(upload_dir)
        .expect("read upload dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("read upload entries");
    let temp_files = entries
        .iter()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".tmp"))
        })
        .collect::<Vec<_>>();
    assert!(temp_files.is_empty());
}

fn assert_tmp_dir_is_empty(root: &std::path::Path) {
    let tmp_dir = root.join("tmp");
    let entries = std::fs::read_dir(tmp_dir)
        .expect("read tmp dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("read tmp entries");
    assert!(entries.is_empty());
}

fn tag_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_owned())
}

fn aws_chunked_body_with_crc32_trailer(decoded: &[u8]) -> Vec<u8> {
    let checksum = expected_crc32_checksum(decoded);
    aws_chunked_body_with_custom_trailer(decoded, "x-amz-checksum-crc32", &checksum)
}

fn expected_crc32_checksum(decoded: &[u8]) -> String {
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(decoded);
    BASE64.encode(crc.to_be_bytes())
}

fn aws_chunked_body_with_custom_trailer(
    decoded: &[u8],
    trailer_name: &str,
    trailer_value: &str,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(format!("{:x}\r\n", decoded.len()).as_bytes());
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n0\r\n");
    encoded.extend_from_slice(format!("{trailer_name}: {trailer_value}\r\n\r\n").as_bytes());
    encoded
}

fn aws_chunked_body_without_trailers(decoded: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(format!("{:x}\r\n", decoded.len()).as_bytes());
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n0\r\n\r\n");
    encoded
}

fn split_body(bytes: Vec<u8>, chunk_size: usize) -> Body {
    let chunks = bytes
        .chunks(chunk_size)
        .map(|chunk| Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(chunk)))
        .collect::<Vec<_>>();
    Body::from_stream(stream::iter(chunks))
}

struct CountingReplaceProcessor {
    calls: Arc<AtomicUsize>,
    replacement: Vec<u8>,
}

impl UploadProcessor for CountingReplaceProcessor {
    fn process<'a>(
        &'a self,
        request: UploadProcessorRequest<'a>,
    ) -> BoxFuture<'a, Result<UploadProcessorAction, UploadProcessorError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::fs::write(request.replacement_path, &self.replacement)
                .map_err(|error| UploadProcessorError::Failed(error.to_string()))?;
            Ok(UploadProcessorAction::Replace)
        })
    }
}
