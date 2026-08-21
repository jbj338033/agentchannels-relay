//! Transport-only AgentChannels relay.
//!
//! The relay stores installation identity and binding routing metadata. Event bodies
//! live only in request/connection memory and are never written to the database.

use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use rusqlite::{backup::Backup, params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    time::{timeout, Duration},
};
use uuid::Uuid;

pub const PROTOCOL: u8 = 1;
const SCHEMA_VERSION: i32 = 3;

/// The Relay routes by connector but never interprets one.
///
/// It does not verify provider signatures or read event bodies, so it has no use
/// for the set of connector names in existence. Constraining the shape rather than
/// the value keeps `/v1/webhooks/{connector}/{binding}` a safe route segment while
/// letting the local installation add a provider without a Relay release.
fn is_connector_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}
const COMPONENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const OPEN_ENROLLMENT_MAX_INSTALLATIONS: i64 = 10_000;
const OPEN_ENROLLMENT_INACTIVE_DAYS: i64 = 90;

#[derive(Clone, Debug)]
pub enum EnrollmentPolicy {
    Token(Vec<u8>),
    Open,
}

impl EnrollmentPolicy {
    pub fn from_env() -> Result<Self, String> {
        let direct = std::env::var_os("AGENTCHANNELS_RELAY_ENROLLMENT_TOKEN");
        let file = std::env::var_os("AGENTCHANNELS_RELAY_ENROLLMENT_TOKEN_FILE");
        let open = std::env::var("AGENTCHANNELS_RELAY_ALLOW_OPEN_ENROLLMENT").ok();
        if let Some(value) = open.as_deref() {
            if value != "true" {
                return Err(
                    "AGENTCHANNELS_RELAY_ALLOW_OPEN_ENROLLMENT must be true when set".into(),
                );
            }
        }
        let configured = usize::from(direct.is_some())
            + usize::from(file.is_some())
            + usize::from(open.as_deref() == Some("true"));
        if configured != 1 {
            return Err("exactly one enrollment policy must be configured".into());
        }
        if let Some(token) = direct {
            let token = token.to_string_lossy().as_bytes().to_vec();
            return Self::from_values(Some(token), None, None);
        }
        if let Some(path) = file {
            let token = std::fs::read(path).map_err(|_| "enrollment token file is unreadable")?;
            return Self::from_values(None, Some(token), None);
        }
        Self::from_values(None, None, Some("true"))
    }

    fn from_values(
        direct: Option<Vec<u8>>,
        file_token: Option<Vec<u8>>,
        open: Option<&str>,
    ) -> Result<Self, String> {
        if let Some(value) = open {
            if value != "true" {
                return Err(
                    "AGENTCHANNELS_RELAY_ALLOW_OPEN_ENROLLMENT must be true when set".into(),
                );
            }
        }
        let configured = usize::from(direct.is_some())
            + usize::from(file_token.is_some())
            + usize::from(open == Some("true"));
        if configured != 1 {
            return Err("exactly one enrollment policy must be configured".into());
        }
        if let Some(token) = direct {
            if token.is_empty() {
                return Err("enrollment token is empty".into());
            }
            return Ok(Self::Token(token));
        }
        if let Some(token) = file_token {
            let token = trim_token(token);
            if token.is_empty() {
                return Err("enrollment token file is empty".into());
            }
            return Ok(Self::Token(token));
        }
        Ok(Self::Open)
    }
}

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub database_path: PathBuf,
    pub response_timeout: Duration,
    pub auth_timeout: Duration,
    pub enrollment_policy: EnrollmentPolicy,
}

impl RelayConfig {
    pub fn new(database_path: PathBuf, enrollment_policy: EnrollmentPolicy) -> Self {
        Self {
            database_path,
            response_timeout: Duration::from_millis(2_500),
            auth_timeout: Duration::from_secs(10),
            enrollment_policy,
        }
    }
    pub fn in_memory() -> Self {
        Self::new(PathBuf::from(":memory:"), EnrollmentPolicy::Open)
    }
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("invalid installation public key")]
    InvalidPublicKey,
    #[error("installation is already registered with a different key")]
    AlreadyRegistered,
    #[error("database schema is newer than this binary supports")]
    NewerSchema,
    #[error("database migration backup failed")]
    BackupFailed,
    #[error("database migration {0} is missing")]
    MissingMigration(i32),
    #[error("open enrollment installation capacity reached")]
    EnrollmentCapacity,
}

#[derive(Clone)]
pub struct AppState {
    db: Arc<Mutex<Connection>>,
    connections: Arc<RwLock<HashMap<String, Arc<ConnectionHandle>>>>,
    config: RelayConfig,
}

impl AppState {
    pub fn open(config: RelayConfig) -> Result<Self, RelayError> {
        let connection = if config.database_path.as_os_str() == ":memory:" {
            Connection::open_in_memory()?
        } else {
            if let Some(parent) = config
                .database_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::create_dir_all(parent)
                    .map_err(|_| rusqlite::Error::InvalidPath(config.database_path.clone()))?;
            }
            Connection::open(&config.database_path)?
        };
        initialize_database(&connection, &config)?;
        Ok(Self {
            db: Arc::new(Mutex::new(connection)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }

    pub fn router(&self) -> Router {
        router(self.clone())
    }

    /// Registers a key without exposing the database connection to callers.
    pub fn register_installation(
        &self,
        installation_id: &str,
        public_key: &[u8; 32],
    ) -> Result<(), RelayError> {
        let db = self.db.lock().expect("database mutex poisoned");
        let existing: Option<Vec<u8>> = db
            .query_row(
                "SELECT public_key FROM installations WHERE installation_id = ?1",
                params![installation_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing != public_key {
                return Err(RelayError::AlreadyRegistered);
            }
            return Ok(());
        }
        if matches!(self.config.enrollment_policy, EnrollmentPolicy::Open) {
            prune_inactive_installations(&db)?;
            let count: i64 =
                db.query_row("SELECT COUNT(*) FROM installations", [], |row| row.get(0))?;
            if count >= OPEN_ENROLLMENT_MAX_INSTALLATIONS {
                return Err(RelayError::EnrollmentCapacity);
            }
        }
        db.execute(
            "INSERT INTO installations (installation_id, public_key, created_at, enrolled_at, last_connected_at) VALUES (?1, ?2, ?3, ?3, NULL)",
            params![installation_id, public_key.as_slice(), now()],
        )?;
        Ok(())
    }

    pub fn enrollment_authorized(&self, headers: &HeaderMap) -> bool {
        let EnrollmentPolicy::Token(expected) = &self.config.enrollment_policy else {
            return true;
        };
        let presented = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::as_bytes)
            .unwrap_or_default();
        constant_time_token_eq(expected, presented)
    }

    pub fn schema_version(&self) -> Result<i32, RelayError> {
        let db = self.db.lock().expect("database mutex poisoned");
        Ok(db.query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/installations", post(register_installation))
        .route("/v1/connect", get(connect))
        .route("/v1/webhooks/{connector}/{binding}", post(webhook))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallationRequest {
    installation_id: String,
    public_key_base64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallationResponse {
    installation_id: String,
}

async fn register_installation(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !state.enrollment_authorized(&headers) {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let Ok(input) = serde_json::from_slice::<InstallationRequest>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid installation request").into_response();
    };
    if input.installation_id.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "installationId is required").into_response();
    }
    let Ok(bytes) = BASE64.decode(input.public_key_base64.as_bytes()) else {
        return (StatusCode::BAD_REQUEST, "publicKeyBase64 is invalid").into_response();
    };
    let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return (
            StatusCode::BAD_REQUEST,
            "publicKeyBase64 must contain an Ed25519 public key",
        )
            .into_response();
    };
    if VerifyingKey::from_bytes(&key).is_err() {
        return (StatusCode::BAD_REQUEST, "public key is invalid").into_response();
    }
    match state.register_installation(&input.installation_id, &key) {
        Ok(()) => Json(InstallationResponse {
            installation_id: input.installation_id,
        })
        .into_response(),
        Err(RelayError::AlreadyRegistered) => StatusCode::CONFLICT.into_response(),
        Err(RelayError::EnrollmentCapacity) => StatusCode::TOO_MANY_REQUESTS.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
enum LocalMessage {
    #[serde(rename = "authenticate")]
    Authenticate {
        protocol: u8,
        installation_id: String,
        signature_base64: String,
    },
    #[serde(rename = "sync_bindings")]
    SyncBindings {
        protocol: u8,
        bindings: Vec<Binding>,
    },
    #[serde(rename = "webhook_response")]
    WebhookResponse {
        protocol: u8,
        request_id: String,
        status: u16,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default)]
        body: String,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Binding {
    binding_id: String,
    connector: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
enum RelayMessage<'a> {
    #[serde(rename = "challenge")]
    Challenge { protocol: u8, nonce: &'a str },
    #[serde(rename = "authenticated")]
    Authenticated { protocol: u8 },
    #[serde(rename = "webhook")]
    Webhook {
        protocol: u8,
        request_id: &'a str,
        binding_id: &'a str,
        connector: &'a str,
        received_at: &'a str,
        expires_at: &'a str,
        headers: &'a HashMap<String, String>,
        raw_body_base64: &'a str,
    },
    #[serde(rename = "error")]
    Error {
        protocol: u8,
        code: &'a str,
        message: &'a str,
    },
}

async fn connect(upgrade: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| handle_connection(socket, state))
}

async fn handle_connection(mut socket: WebSocket, state: AppState) {
    let mut nonce_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = BASE64.encode(nonce_bytes);
    if send_json(
        &mut socket,
        &RelayMessage::Challenge {
            protocol: PROTOCOL,
            nonce: &nonce,
        },
    )
    .await
    .is_err()
    {
        return;
    }
    let first = timeout(state.config.auth_timeout, socket.recv()).await;
    let text = match first.ok().flatten() {
        Some(Ok(Message::Text(text))) => text,
        Some(Ok(Message::Binary(_))) => {
            send_error(
                &mut socket,
                "invalid_message",
                "authenticate must be JSON text",
            )
            .await;
            return;
        }
        _ => return,
    };
    let Ok(first_message) = serde_json::from_str::<LocalMessage>(&text) else {
        let _ = send_json(
            &mut socket,
            &RelayMessage::Error {
                protocol: PROTOCOL,
                code: "invalid_message",
                message: "authenticate is required",
            },
        )
        .await;
        return;
    };
    let LocalMessage::Authenticate {
        protocol,
        installation_id,
        signature_base64,
    } = first_message
    else {
        send_error(&mut socket, "invalid_message", "authenticate is required").await;
        return;
    };
    if protocol != PROTOCOL {
        send_error(
            &mut socket,
            "unsupported_protocol",
            &format!("protocol {protocol} is not supported"),
        )
        .await;
        return;
    }
    if !verify_auth(
        &state,
        &installation_id,
        nonce.as_bytes(),
        &signature_base64,
    ) {
        send_error(
            &mut socket,
            "unauthenticated",
            "invalid installation authentication",
        )
        .await;
        return;
    }
    update_last_connected(&state, &installation_id);
    let _ = send_json(
        &mut socket,
        &RelayMessage::Authenticated { protocol: PROTOCOL },
    )
    .await;
    let (mut sender, mut receiver) = socket.split();
    let (out_tx, mut out_rx) = mpsc::channel::<String>(32);
    let handle = Arc::new(ConnectionHandle {
        sender: out_tx,
        pending: Mutex::new(HashMap::new()),
    });
    {
        let mut connections = state.connections.write().await;
        if let Some(previous) = connections.insert(installation_id.clone(), handle.clone()) {
            previous.close();
        }
    }
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            if sender.send(Message::Text(message.into())).await.is_err() {
                break;
            }
        }
    });
    while let Some(Ok(message)) = receiver.next().await {
        let text = match message {
            Message::Text(text) => text,
            Message::Binary(_) => {
                send_error_on_channel(
                    &handle,
                    "invalid_message",
                    "relay messages must be JSON text",
                );
                continue;
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => continue,
        };
        match serde_json::from_str::<LocalMessage>(&text) {
            Ok(LocalMessage::SyncBindings { protocol, bindings }) if protocol == PROTOCOL => {
                match replace_bindings(&state, &installation_id, bindings) {
                    Ok(()) => {}
                    Err(_) => {
                        let message = serde_json::to_string(&RelayMessage::Error {
                            protocol: PROTOCOL,
                            code: "binding_conflict",
                            message: "one or more Binding IDs belong to another installation",
                        })
                        .expect("relay errors serialize");
                        let _ = handle.sender.try_send(message);
                    }
                }
            }
            Ok(LocalMessage::WebhookResponse {
                protocol,
                request_id,
                status,
                headers,
                body,
            }) if protocol == PROTOCOL => {
                if let Some(tx) = handle
                    .pending
                    .lock()
                    .expect("pending mutex poisoned")
                    .remove(&request_id)
                {
                    let _ = tx.send(WebhookResponse {
                        status,
                        headers,
                        body,
                    });
                }
            }
            Ok(LocalMessage::SyncBindings { protocol, .. })
            | Ok(LocalMessage::WebhookResponse { protocol, .. }) => {
                send_error_on_channel(
                    &handle,
                    "unsupported_protocol",
                    &format!("protocol {protocol} is not supported"),
                );
            }
            Ok(LocalMessage::Authenticate { .. }) => {
                send_error_on_channel(
                    &handle,
                    "invalid_message",
                    "authenticate is only valid once",
                );
            }
            Err(_) => {
                send_error_on_channel(&handle, "invalid_message", "unsupported relay message");
            }
        }
    }
    handle.close();
    writer.abort();
    let mut connections = state.connections.write().await;
    if connections
        .get(&installation_id)
        .is_some_and(|current| Arc::ptr_eq(current, &handle))
    {
        connections.remove(&installation_id);
    }
}

fn verify_auth(
    state: &AppState,
    installation_id: &str,
    nonce: &[u8],
    signature_base64: &str,
) -> bool {
    let Ok(signature) = BASE64
        .decode(signature_base64.as_bytes())
        .and_then(|bytes| {
            Signature::try_from(bytes.as_slice()).map_err(|_| base64::DecodeError::InvalidLength(0))
        })
    else {
        return false;
    };
    let db = state.db.lock().expect("database mutex poisoned");
    let Ok(key) = db
        .query_row(
            "SELECT public_key FROM installations WHERE installation_id = ?1",
            params![installation_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
    else {
        return false;
    };
    let Some(key) = key else {
        return false;
    };
    let Ok(key_bytes) = <[u8; 32]>::try_from(key.as_slice()) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    key.verify_strict(nonce, &signature).is_ok()
}

async fn send_json<T: Serialize>(socket: &mut WebSocket, value: &T) -> Result<(), axum::Error> {
    socket
        .send(Message::Text(
            serde_json::to_string(value)
                .expect("relay messages serialize")
                .into(),
        ))
        .await
}

struct ConnectionHandle {
    sender: mpsc::Sender<String>,
    pending: Mutex<HashMap<String, oneshot::Sender<WebhookResponse>>>,
}
impl ConnectionHandle {
    fn close(&self) {
        for (_, tx) in self.pending.lock().expect("pending mutex poisoned").drain() {
            drop(tx);
        }
    }
}

async fn send_error(socket: &mut WebSocket, code: &str, message: &str) {
    let _ = send_json(
        socket,
        &RelayMessage::Error {
            protocol: PROTOCOL,
            code,
            message,
        },
    )
    .await;
}

fn send_error_on_channel(handle: &ConnectionHandle, code: &str, message: &str) {
    let serialized = serde_json::to_string(&RelayMessage::Error {
        protocol: PROTOCOL,
        code,
        message,
    })
    .expect("relay errors serialize");
    let _ = handle.sender.try_send(serialized);
}

#[derive(Debug)]
struct WebhookResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

enum Delivery {
    Response(WebhookResponse),
    Offline,
}
impl ConnectionHandle {
    async fn deliver(&self, message: String, request_id: String, limit: Duration) -> Delivery {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending mutex poisoned")
            .insert(request_id.clone(), tx);
        if !matches!(timeout(limit, self.sender.send(message)).await, Ok(Ok(()))) {
            self.pending
                .lock()
                .expect("pending mutex poisoned")
                .remove(&request_id);
            return Delivery::Offline;
        }
        match timeout(limit, rx).await {
            Ok(Ok(response)) => Delivery::Response(response),
            _ => {
                self.pending
                    .lock()
                    .expect("pending mutex poisoned")
                    .remove(&request_id);
                Delivery::Offline
            }
        }
    }
}

async fn webhook(
    State(state): State<AppState>,
    Path((connector, binding_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_connector_id(&connector) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(installation_id) = lookup_binding(&state, &binding_id, &connector) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(connection) = state
        .connections
        .read()
        .await
        .get(&installation_id)
        .cloned()
    else {
        return StatusCode::OK.into_response();
    };
    let request_id = Uuid::new_v4().to_string();
    let request_headers = headers_to_map(&headers);
    let encoded_body = BASE64.encode(&body);
    let received = Utc::now();
    let received_at = format_time(received);
    let expires_at = format_time(
        received
            + chrono::Duration::from_std(state.config.response_timeout)
                .expect("response timeout fits chrono duration"),
    );
    let message = serde_json::to_string(&RelayMessage::Webhook {
        protocol: PROTOCOL,
        request_id: &request_id,
        binding_id: &binding_id,
        connector: &connector,
        received_at: &received_at,
        expires_at: &expires_at,
        headers: &request_headers,
        raw_body_base64: &encoded_body,
    })
    .expect("relay messages serialize");
    match connection
        .deliver(message, request_id, state.config.response_timeout)
        .await
    {
        Delivery::Response(result) => response_from_local(result),
        Delivery::Offline => StatusCode::OK.into_response(),
    }
}

fn response_from_local(result: WebhookResponse) -> Response {
    let status = StatusCode::from_u16(result.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response = Response::new(result.body.into());
    *response.status_mut() = status;
    for (name, value) in result.headers {
        if let (Ok(name), Ok(value)) = (
            name.parse::<http::header::HeaderName>(),
            HeaderValue::from_str(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

fn headers_to_map(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

fn lookup_binding(state: &AppState, binding_id: &str, connector: &str) -> Option<String> {
    let db = state.db.lock().ok()?;
    db.query_row(
        "SELECT installation_id FROM bindings WHERE binding_id = ?1 AND connector = ?2",
        params![binding_id, connector],
        |row| row.get(0),
    )
    .optional()
    .ok()
    .flatten()
}

fn replace_bindings(
    state: &AppState,
    installation_id: &str,
    bindings: Vec<Binding>,
) -> Result<(), rusqlite::Error> {
    let mut db = state.db.lock().expect("database mutex poisoned");
    let tx = db.transaction()?;
    tx.execute(
        "DELETE FROM bindings WHERE installation_id = ?1",
        params![installation_id],
    )?;
    for binding in bindings {
        if is_connector_id(&binding.connector) {
            tx.execute("INSERT INTO bindings (binding_id, connector, installation_id, updated_at) VALUES (?1, ?2, ?3, ?4)", params![binding.binding_id, binding.connector, installation_id, now()])?;
        }
    }
    tx.commit()
}

fn initialize_database(db: &Connection, config: &RelayConfig) -> Result<(), RelayError> {
    db.execute_batch("PRAGMA foreign_keys = ON;")?;
    let declared: i32 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if declared > SCHEMA_VERSION {
        return Err(RelayError::NewerSchema);
    }
    let has_installations = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='installations')",
        [],
        |row| row.get::<_, i32>(0),
    )? != 0;
    let source = if declared == 0 && has_installations {
        1
    } else {
        declared
    };
    if source < SCHEMA_VERSION {
        if config.database_path.as_os_str() != ":memory:" {
            create_backup(db, config, source)?;
        }
        for target in (source + 1)..=SCHEMA_VERSION {
            let tx = db.unchecked_transaction()?;
            match target {
                1 => tx.execute_batch(
                    "CREATE TABLE installations (installation_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, created_at TEXT NOT NULL); CREATE TABLE bindings (binding_id TEXT PRIMARY KEY, connector TEXT NOT NULL CHECK (connector IN ('linear','slack')), installation_id TEXT NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE, updated_at TEXT NOT NULL); CREATE INDEX bindings_installation_idx ON bindings(installation_id);",
                )?,
                2 => {
                    if !has_column(&tx, "installations", "enrolled_at") {
                        tx.execute_batch(
                            "ALTER TABLE installations ADD COLUMN enrolled_at TEXT; ALTER TABLE installations ADD COLUMN last_connected_at TEXT; UPDATE installations SET enrolled_at = created_at WHERE enrolled_at IS NULL;",
                        )?;
                    }
                }
                // Drop the connector allowlist. SQLite cannot remove a CHECK in
                // place, so the table is rebuilt with the constraint omitted.
                3 => tx.execute_batch(
                    "CREATE TABLE bindings_next (binding_id TEXT PRIMARY KEY, connector TEXT NOT NULL, installation_id TEXT NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE, updated_at TEXT NOT NULL); INSERT INTO bindings_next SELECT binding_id, connector, installation_id, updated_at FROM bindings; DROP TABLE bindings; ALTER TABLE bindings_next RENAME TO bindings; CREATE INDEX bindings_installation_idx ON bindings(installation_id);",
                )?,
                _ => return Err(RelayError::MissingMigration(target)),
            }
            record_migration(&tx, target)?;
            tx.pragma_update(None, "user_version", target)?;
            tx.commit()?;
        }
    } else if !has_table(db, "schema_migrations")? {
        if config.database_path.as_os_str() != ":memory:" {
            create_backup(db, config, source)?;
        }
        let tx = db.unchecked_transaction()?;
        tx.execute_batch("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);")?;
        if source >= 1 {
            record_migration(&tx, 1)?;
        }
        if source >= 2 {
            record_migration(&tx, 2)?;
        }
        if source >= 3 {
            record_migration(&tx, 3)?;
        }
        tx.commit()?;
    }
    Ok(())
}

fn create_backup(db: &Connection, config: &RelayConfig, source: i32) -> Result<(), RelayError> {
    let database_parent = config
        .database_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let backup_dir = database_parent.join("backups");
    std::fs::create_dir_all(&backup_dir).map_err(|_| RelayError::BackupFailed)?;
    set_operator_only_directory(&backup_dir)?;
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    let path = backup_dir.join(format!(
        "agentchannels-relay-v{COMPONENT_VERSION}-schema-{source}-{timestamp}.sqlite3"
    ));
    let mut backup_file = std::fs::OpenOptions::new();
    backup_file.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        backup_file.mode(0o600);
    }
    drop(
        backup_file
            .open(&path)
            .map_err(|_| RelayError::BackupFailed)?,
    );
    let mut destination = Connection::open(&path).map_err(|_| RelayError::BackupFailed)?;
    let backup = Backup::new(db, &mut destination).map_err(|_| RelayError::BackupFailed)?;
    backup
        .run_to_completion(128, std::time::Duration::from_millis(1), None)
        .map_err(|_| RelayError::BackupFailed)?;
    drop(backup);
    set_operator_only_file(&path)?;
    Ok(())
}

fn set_operator_only_directory(path: &std::path::Path) -> Result<(), RelayError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| RelayError::BackupFailed)?;
    }
    Ok(())
}

fn set_operator_only_file(path: &std::path::Path) -> Result<(), RelayError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| RelayError::BackupFailed)?;
    }
    Ok(())
}

fn record_migration(tx: &rusqlite::Transaction<'_>, version: i32) -> Result<(), rusqlite::Error> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);",
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
        params![version, now()],
    )?;
    Ok(())
}

fn has_table(db: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        params![name],
        |row| row.get::<_, i32>(0),
    )? != 0)
}

fn has_column(db: &Connection, table: &str, column: &str) -> bool {
    let sql = format!("PRAGMA table_info({table})");
    let Ok(mut statement) = db.prepare(&sql) else {
        return false;
    };
    let found = {
        let Ok(columns) = statement.query_map([], |row| row.get::<_, String>(1)) else {
            return false;
        };
        columns.flatten().any(|name| name == column)
    };
    found
}

fn prune_inactive_installations(db: &Connection) -> Result<(), rusqlite::Error> {
    let cutoff = Utc::now() - chrono::Duration::days(OPEN_ENROLLMENT_INACTIVE_DAYS);
    db.execute(
        "DELETE FROM installations WHERE COALESCE(last_connected_at, enrolled_at, created_at) < ?1",
        params![format_time(cutoff)],
    )?;
    Ok(())
}

fn update_last_connected(state: &AppState, installation_id: &str) {
    if let Ok(db) = state.db.lock() {
        let _ = db.execute(
            "UPDATE installations SET last_connected_at = ?1 WHERE installation_id = ?2",
            params![now(), installation_id],
        );
    }
}

fn trim_token(mut token: Vec<u8>) -> Vec<u8> {
    while token.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        token.pop();
    }
    token
}

fn constant_time_token_eq(expected: &[u8], presented: &[u8]) -> bool {
    let width = expected.len().max(presented.len());
    let mut expected_padded = vec![0u8; width];
    let mut presented_padded = vec![0u8; width];
    expected_padded[..expected.len()].copy_from_slice(expected);
    presented_padded[..presented.len()].copy_from_slice(presented);
    let same_bytes = expected_padded.ct_eq(&presented_padded);
    let same_length = expected.len().ct_eq(&presented.len());
    (same_bytes & same_length).unwrap_u8() == 1
}

fn now() -> String {
    format_time(Utc::now())
}

fn format_time(value: chrono::DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests;
