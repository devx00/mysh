//! Harness self-check: a server comes up and a client connects to it.

mod common;

use mysh::cli::ConnectOpts;

#[tokio::test]
async fn harness_connects() {
    let server = common::start_server(common::ServerOpts::default()).await;
    let conn = server
        .connect(ConnectOpts::default())
        .await
        .expect("connect");
    assert_eq!(conn.remote_key(), server.server_key);
    assert_eq!(conn.server_hello().name, "test-server");
    let rtt = conn.ping().await.expect("ping");
    assert!(rtt.as_secs() < 5);
    conn.close().await;
    server.stop().await;
}
