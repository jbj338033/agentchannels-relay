use super::*;
use axum::body::Body;
use ed25519_dalek::{Signer, SigningKey};
use http::{Request, StatusCode};
use std::fs;
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

#[test]
fn registration_is_idempotent_for_the_same_key_and_conflicts_for_a_new_key() {
    let state = state();
    let original = SigningKey::generate(&mut OsRng);
    let replacement = SigningKey::generate(&mut OsRng);
    assert!(state
        .register_installation("install-idempotent", original.verifying_key().as_bytes())
        .is_ok());
    assert!(state
        .register_installation("install-idempotent", original.verifying_key().as_bytes())
        .is_ok());
    assert!(matches!(
        state.register_installation("install-idempotent", replacement.verifying_key().as_bytes()),
        Err(RelayError::AlreadyRegistered)
    ));
}

#[test]
fn enrollment_token_rotation_preserves_ed25519_reconnect_identity() {
    let root = std::env::temp_dir().join(format!(
        "agentchannels-relay-token-rotation-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).unwrap();
    let database = root.join("relay.db");
    let signing_key = SigningKey::generate(&mut OsRng);
    {
        let config = RelayConfig::new(
            database.clone(),
            EnrollmentPolicy::Token(b"old-token".to_vec()),
        );
        let state = AppState::open(config).unwrap();
        state
            .register_installation("install-rotation", signing_key.verifying_key().as_bytes())
            .unwrap();
    }
    let config = RelayConfig::new(database, EnrollmentPolicy::Token(b"new-token".to_vec()));
    let state = AppState::open(config).unwrap();
    let nonce = b"rotation-challenge";
    let signature = BASE64.encode(signing_key.sign(nonce).to_bytes());
    assert!(verify_auth(&state, "install-rotation", nonce, &signature));
    drop(state);
    let _ = fs::remove_dir_all(root);
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
fn routes_any_well_formed_connector_and_rejects_malformed_ones() {
    // The Relay does not interpret events, so it has no reason to know which
    // providers exist. It constrains the shape of the route segment instead.
    let state = state();
    let key = SigningKey::generate(&mut OsRng);
    state
        .register_installation("install", key.verifying_key().as_bytes())
        .unwrap();
    replace_bindings(
        &state,
        "install",
        vec![
            Binding {
                binding_id: "binding-discord".into(),
                connector: "discord".into(),
            },
            Binding {
                binding_id: "binding-bad".into(),
                connector: "Not/A Connector".into(),
            },
        ],
    )
    .unwrap();

    assert_eq!(
        lookup_binding(&state, "binding-discord", "discord").as_deref(),
        Some("install")
    );
    assert_eq!(
        lookup_binding(&state, "binding-bad", "Not/A Connector"),
        None
    );

    for value in ["slack", "linear", "discord", "ms-teams", "my_tool2"] {
        assert!(is_connector_id(value), "{value} should be routable");
    }
    for value in ["", "Slack", "1slack", "sl ack", "sl/ack", &"a".repeat(33)] {
        assert!(!is_connector_id(value), "{value:?} should be rejected");
    }
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
    // Ordered by creation, which a table rebuild changes; the set is the property.
    let mut tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    tables.sort();
    assert_eq!(
        tables,
        vec!["bindings", "installations", "schema_migrations"]
    );
    assert!(tables
        .iter()
        .all(|table| !table.contains("payload") && !table.contains("body")));
}

#[tokio::test]
async fn protected_enrollment_has_identical_unauthorized_response() {
    let mut config = RelayConfig::in_memory();
    config.enrollment_policy = EnrollmentPolicy::Token(b"correct-token".to_vec());
    let state = AppState::open(config).unwrap();
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/installations")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"installationId":"protected","publicKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}).to_string(),
            ))
            .unwrap()
    };
    let missing = state.router().oneshot(request()).await.unwrap();
    let invalid = state
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/installations")
                .header("content-type", "application/json")
                .header("authorization", "Bearer wrong-token")
                .body(Body::from(
                    serde_json::json!({"installationId":"protected","publicKeyBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        axum::body::to_bytes(missing.into_body(), usize::MAX)
            .await
            .unwrap(),
        axum::body::to_bytes(invalid.into_body(), usize::MAX)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn explicit_open_enrollment_accepts_a_valid_key() {
    let state = state();
    let key = SigningKey::generate(&mut OsRng);
    let response = state
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/installations")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "installationId": "open-install",
                        "publicKeyBase64": BASE64.encode(key.verifying_key().as_bytes())
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn legacy_schema_migration_creates_backup_and_preserves_data() {
    let root =
        std::env::temp_dir().join(format!("agentchannels-relay-migration-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let database = root.join("relay.db");
    {
        let db = rusqlite::Connection::open(&database).unwrap();
        db.execute_batch("CREATE TABLE installations (installation_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, created_at TEXT NOT NULL); CREATE TABLE bindings (binding_id TEXT PRIMARY KEY, connector TEXT NOT NULL, installation_id TEXT NOT NULL, updated_at TEXT NOT NULL); INSERT INTO installations VALUES ('keep', x'0000000000000000000000000000000000000000000000000000000000000000', '2026-01-01T00:00:00.000Z'); INSERT INTO bindings VALUES ('binding-keep', 'slack', 'keep', '2026-01-01T00:00:00.000Z');") .unwrap();
    }
    let state = AppState::open(RelayConfig::new(database.clone(), EnrollmentPolicy::Open)).unwrap();
    assert_eq!(state.schema_version().unwrap(), SCHEMA_VERSION);
    {
        let db = state.db.lock().unwrap();
        assert_eq!(
            db.query_row(
                "SELECT public_key FROM installations WHERE installation_id = 'keep'",
                [],
                |row| row.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
            vec![0u8; 32]
        );
        assert_eq!(
            db.query_row(
                "SELECT installation_id FROM bindings WHERE binding_id = 'binding-keep'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
            "keep"
        );
    }
    let backups = fs::read_dir(root.join("backups"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(backups.len(), 1);
    let name = backups[0].file_name().to_string_lossy().to_string();
    assert!(name.contains("agentchannels-relay-v1.0.0-schema-1-"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(root.join("backups"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(backups[0].path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn migration_refuses_when_backup_destination_cannot_be_created() {
    let root = std::env::temp_dir().join(format!(
        "agentchannels-relay-backup-failure-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&root).unwrap();
    let database = root.join("relay.db");
    {
        let db = rusqlite::Connection::open(&database).unwrap();
        db.execute_batch("CREATE TABLE installations (installation_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, created_at TEXT NOT NULL); CREATE TABLE bindings (binding_id TEXT PRIMARY KEY, connector TEXT NOT NULL, installation_id TEXT NOT NULL, updated_at TEXT NOT NULL); INSERT INTO installations VALUES ('keep', x'0000000000000000000000000000000000000000000000000000000000000000', '2026-01-01T00:00:00.000Z');").unwrap();
    }
    fs::write(root.join("backups"), b"not a directory").unwrap();
    assert!(matches!(
        AppState::open(RelayConfig::new(database.clone(), EnrollmentPolicy::Open)),
        Err(RelayError::BackupFailed)
    ));
    let unchanged = rusqlite::Connection::open(&database).unwrap();
    assert!(!has_column(&unchanged, "installations", "enrolled_at"));
    assert_eq!(
        unchanged
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i32>(0))
            .unwrap(),
        0
    );
    drop(unchanged);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn newer_schema_is_refused_without_mutation() {
    let root = std::env::temp_dir().join(format!("agentchannels-relay-newer-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let database = root.join("relay.db");
    {
        let db = rusqlite::Connection::open(&database).unwrap();
        db.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
    }
    let expected = fs::read(&database).unwrap();
    assert!(matches!(
        AppState::open(RelayConfig::new(database.clone(), EnrollmentPolicy::Open)),
        Err(RelayError::NewerSchema)
    ));
    assert_eq!(fs::read(&database).unwrap(), expected);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn conformance_fixture_declares_protocol_one_and_explicit_rejection() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../protocol/v1/messages.json")).unwrap();
    assert_eq!(fixture["protocol"], PROTOCOL);
    assert_eq!(fixture["rejected"][0]["errorCode"], "unsupported_protocol");
}

#[test]
fn enrollment_policy_rejects_invalid_combinations_and_empty_tokens() {
    assert!(EnrollmentPolicy::from_values(None, None, None).is_err());
    assert!(EnrollmentPolicy::from_values(Some(b"token".to_vec()), None, Some("true")).is_err());
    assert!(EnrollmentPolicy::from_values(None, Some(b"token".to_vec()), Some("true")).is_err());
    assert!(EnrollmentPolicy::from_values(Some(Vec::new()), None, None).is_err());
    assert!(EnrollmentPolicy::from_values(None, Some(Vec::new()), None).is_err());
    assert!(EnrollmentPolicy::from_values(None, None, Some("false")).is_err());
    assert!(matches!(
        EnrollmentPolicy::from_values(None, Some(b"token\n".to_vec()), None),
        Ok(EnrollmentPolicy::Token(token)) if token == b"token"
    ));
}

#[test]
fn open_enrollment_prunes_inactive_records_and_enforces_capacity() {
    let state = state();
    {
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO installations (installation_id, public_key, created_at, enrolled_at, last_connected_at) VALUES ('inactive', ?1, '2000-01-01T00:00:00.000Z', '2000-01-01T00:00:00.000Z', NULL)",
            [vec![0u8; 32]],
        )
        .unwrap();
    }
    let key = SigningKey::generate(&mut OsRng);
    state
        .register_installation("fresh", key.verifying_key().as_bytes())
        .unwrap();
    let db = state.db.lock().unwrap();
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM installations WHERE installation_id = 'inactive'",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    drop(db);

    let db = state.db.lock().unwrap();
    let tx = db.unchecked_transaction().unwrap();
    for index in 0..OPEN_ENROLLMENT_MAX_INSTALLATIONS {
        tx.execute(
            "INSERT INTO installations (installation_id, public_key, created_at, enrolled_at, last_connected_at) VALUES (?1, ?2, ?3, ?3, NULL)",
            rusqlite::params![format!("capacity-{index}"), vec![1u8; 32], now()],
        ).unwrap();
    }
    tx.commit().unwrap();
    drop(db);
    let key = SigningKey::generate(&mut OsRng);
    assert!(matches!(
        state.register_installation("over-capacity", key.verifying_key().as_bytes()),
        Err(RelayError::EnrollmentCapacity)
    ));
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
