use std::{collections::BTreeSet, time::Duration};

use md5::{Digest, Md5};
use s3_endpoint::{
    AppState,
    config::{AuthConfig, Config},
    router,
    s3::types::{BucketName, ObjectKey},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn expect_100_continue_is_sent_before_accepted_upload_body() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            allowed_buckets: BTreeSet::from(["test-bucket".to_owned()]),
            ..Default::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("state");
    let object_store = state.object_store.clone();
    let (addr, server) = spawn_server(state).await;
    let body = b"expect continue body";
    let mut stream = TcpStream::connect(addr).await.expect("connect");

    stream
        .write_all(
            format!(
                "PUT /test-bucket/continue.txt HTTP/1.1\r\n\
                 Host: {addr}\r\n\
                 Expect: 100-continue\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .expect("write headers");

    let interim = read_header_block(&mut stream).await;
    assert!(
        interim.starts_with("HTTP/1.1 100 Continue"),
        "unexpected interim response: {interim:?}"
    );

    stream.write_all(body).await.expect("write body");
    let final_response = read_to_end(&mut stream).await;
    assert!(
        final_response.starts_with("HTTP/1.1 200 OK"),
        "unexpected final response: {final_response:?}"
    );
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));
    assert!(
        final_response.contains(&format!("etag: {expected_etag}"))
            || final_response.contains(&format!("ETag: {expected_etag}")),
        "missing expected ETag in response: {final_response:?}"
    );

    let metadata = object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("continue.txt").expect("key"),
        )
        .await
        .expect("head object")
        .expect("stored object");
    assert_eq!(metadata.size, body.len() as u64);

    server.abort();
}

#[tokio::test]
async fn expect_100_continue_is_not_sent_when_auth_fails() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config::new(temp_dir.path().to_path_buf()))
        .await
        .expect("state");
    let (addr, server) = spawn_server(state).await;
    let mut stream = TcpStream::connect(addr).await.expect("connect");

    stream
        .write_all(
            format!(
                "PUT /test-bucket/denied.txt HTTP/1.1\r\n\
                 Host: {addr}\r\n\
                 Expect: 100-continue\r\n\
                 Content-Length: 11\r\n\
                 Connection: close\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("write headers");

    let response = read_header_block(&mut stream).await;
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden"),
        "unexpected response: {response:?}"
    );
    assert!(
        !response.starts_with("HTTP/1.1 100 Continue"),
        "server sent 100 Continue before rejecting auth"
    );

    server.abort();
}

async fn spawn_server(state: AppState) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.expect("serve");
    });
    (addr, server)
}

async fn read_header_block(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut byte = [0_u8; 1];
        loop {
            stream.read_exact(&mut byte).await.expect("read byte");
            bytes.push(byte[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
    })
    .await
    .expect("response header timeout");
    String::from_utf8(bytes).expect("response headers utf8")
}

async fn read_to_end(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .expect("response timeout")
        .expect("read response");
    String::from_utf8(bytes).expect("response utf8")
}
