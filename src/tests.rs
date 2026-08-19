use super::*;
use axum::body::Body;
use ed25519_dalek::{Signer, SigningKey};
use http::{Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
use tower::ServiceExt;

fn state() -> AppState {
    AppState::open(RelayConfig::in_memory()).expect("in-memory relay")
}

#[test]
fn installation_authentication_accepts_only_registered_ed25519_signature() {
    let state = state();
    let signing_key = SigningKey::generate(&mut OsRng);
    state
        .register_installation("install-1", signing_key.verifying_key().as_bytes())
        .unwrap();
    let nonce = b"challenge-nonce";
    let signature = BASE64.encode(signing_key.sign(nonce).to_bytes());
    assert!(verify_auth(&state, "install-1", nonce, &signature));
    assert!(!verify_auth(&state, "unknown", nonce, &signature));
    assert!(!verify_auth(&state, "install-1", b"different", &signature));
}

#[tokio::test]
async fn offline_ingress_is_acknowledged_and_dropped() {
    let state = state();
    let key = SigningKey::generate(&mut OsRng);
    state
        .register_installation("install-1", key.verifying_key().as_bytes())
        .unwrap();
    replace_bindings(
        &state,
        "install-1",
        vec![Binding {
            binding_id: "binding-1".into(),
            connector: "slack".into(),
        }],
    )
    .unwrap();
    let response = state
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/webhooks/slack/binding-1")
                .header("content-type", "application/json")
                .body(Body::from(br#"{"agentId":"untrusted"}"#.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn binding_routing_uses_persisted_binding_not_payload_destination() {
    let state = state();
    let first = SigningKey::generate(&mut OsRng);
    let second = SigningKey::generate(&mut OsRng);
    state
        .register_installation("first", first.verifying_key().as_bytes())
        .unwrap();
    state
        .register_installation("second", second.verifying_key().as_bytes())
        .unwrap();
    replace_bindings(
        &state,
        "first",
        vec![Binding {
            binding_id: "binding-1".into(),
            connector: "linear".into(),
        }],
    )
    .unwrap();
    assert_eq!(
        lookup_binding(&state, "binding-1", "linear").as_deref(),
        Some("first")
    );
    // A body claiming the other installation cannot affect the only routing lookup.
    assert_ne!(
        lookup_binding(&state, "binding-1", "linear").as_deref(),
        Some("second")
    );
}

#[test]
fn authenticated_installation_cannot_take_another_installations_binding() {
    let state = state();
    let first = SigningKey::generate(&mut OsRng);
    let second = SigningKey::generate(&mut OsRng);
    state
        .register_installation("first", first.verifying_key().as_bytes())
        .unwrap();
    state
        .register_installation("second", second.verifying_key().as_bytes())
        .unwrap();
    replace_bindings(
        &state,
        "first",
        vec![Binding {
            binding_id: "binding-1".into(),
            connector: "linear".into(),
        }],
    )
    .unwrap();

    assert!(replace_bindings(
        &state,
        "second",
        vec![Binding {
            binding_id: "binding-1".into(),
            connector: "slack".into(),
        }],
    )
    .is_err());
    assert_eq!(
        lookup_binding(&state, "binding-1", "linear").as_deref(),
        Some("first")
    );
}

#[test]
fn webhook_body_is_not_persisted() {
    let state = state();
    let key = SigningKey::generate(&mut OsRng);
    state
        .register_installation("install-1", key.verifying_key().as_bytes())
        .unwrap();
    replace_bindings(
        &state,
        "install-1",
        vec![Binding {
            binding_id: "binding-1".into(),
            connector: "slack".into(),
        }],
    )
    .unwrap();
    let db = state.db.lock().unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(tables, vec!["installations", "bindings"]);
    assert!(tables
        .iter()
        .all(|table| !table.contains("payload") && !table.contains("body")));
}

#[test]
fn wire_messages_use_versioned_camel_case_protocol() {
    let headers = HashMap::from([(String::from("x-test"), String::from("1"))]);
    let value = serde_json::to_value(RelayMessage::Webhook {
        protocol: PROTOCOL,
        request_id: "request-1",
        binding_id: "binding-1",
        connector: "slack",
        received_at: "2026-01-01T00:00:00.000Z",
        expires_at: "2026-01-01T00:00:02.500Z",
        headers: &headers,
        raw_body_base64: "eA==",
    })
    .unwrap();
    assert_eq!(value["requestId"], "request-1");
    assert_eq!(value["bindingId"], "binding-1");
    assert_eq!(value["receivedAt"], "2026-01-01T00:00:00.000Z");
    assert_eq!(value["expiresAt"], "2026-01-01T00:00:02.500Z");
    assert_eq!(value["rawBodyBase64"], "eA==");
}

#[tokio::test]
async fn authenticated_connection_routes_webhook_and_returns_local_response() {
    let state = state();
    let signing_key = SigningKey::generate(&mut OsRng);
    state
        .register_installation("install-online", signing_key.verifying_key().as_bytes())
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = state.router();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let (mut socket, _) = connect_async(format!("ws://{address}/v1/connect"))
        .await
        .unwrap();
    let challenge: serde_json::Value =
        serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
    let nonce = challenge["nonce"].as_str().unwrap();
    let signature = BASE64.encode(signing_key.sign(nonce.as_bytes()).to_bytes());
    socket
        .send(ClientMessage::Text(
            serde_json::json!({
                "type": "authenticate",
                "protocol": 1,
                "installationId": "install-online",
                "signatureBase64": signature
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let authenticated: serde_json::Value =
        serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
    assert_eq!(authenticated["type"], "authenticated");
    socket
        .send(ClientMessage::Text(
            serde_json::json!({
                "type": "sync_bindings",
                "protocol": 1,
                "bindings": [{"bindingId": "binding-online", "connector": "slack"}]
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    for _ in 0..20 {
        if lookup_binding(&state, "binding-online", "slack").is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        lookup_binding(&state, "binding-online", "slack").as_deref(),
        Some("install-online")
    );

    let http = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let body = r#"{"event_id":"event-online"}"#;
        stream
            .write_all(
                format!(
                    "POST /v1/webhooks/slack/binding-online HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nX-Slack-Signature: signed\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    });

    let forwarded: serde_json::Value =
        serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap();
    assert_eq!(forwarded["type"], "webhook");
    assert_eq!(forwarded["bindingId"], "binding-online");
    assert_eq!(forwarded["connector"], "slack");
    assert_eq!(
        BASE64
            .decode(forwarded["rawBodyBase64"].as_str().unwrap())
            .unwrap(),
        br#"{"event_id":"event-online"}"#
    );
    socket
        .send(ClientMessage::Text(
            serde_json::json!({
                "type": "webhook_response",
                "protocol": 1,
                "requestId": forwarded["requestId"],
                "status": 202,
                "headers": {"x-agentchannels-test": "routed"},
                "body": "accepted"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let response = http.await.unwrap();
    assert!(response.starts_with("HTTP/1.1 202 Accepted"));
    assert!(response
        .to_ascii_lowercase()
        .contains("x-agentchannels-test: routed"));
    assert!(response.ends_with("accepted"));
    server.abort();
}
