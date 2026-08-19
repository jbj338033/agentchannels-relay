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
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tokio::{
    sync::{mpsc, oneshot, RwLock},
    time::{timeout, Duration},
};
use uuid::Uuid;

const PROTOCOL: u8 = 1;

#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub database_path: PathBuf,
    pub response_timeout: Duration,
    pub auth_timeout: Duration,
}

impl RelayConfig {
    pub fn new(database_path: PathBuf) -> Self {
        Self {
            database_path,
            response_timeout: Duration::from_millis(2_500),
            auth_timeout: Duration::from_secs(10),
        }
    }
    pub fn in_memory() -> Self {
        Self::new(PathBuf::from(":memory:"))
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
        initialize_database(&connection)?;
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
        db.execute(
            "INSERT INTO installations (installation_id, public_key, created_at) VALUES (?1, ?2, ?3)",
            params![installation_id, public_key.as_slice(), now()],
        )?;
        Ok(())
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
    Json(input): Json<InstallationRequest>,
) -> Response {
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
    let Some(Ok(Message::Text(text))) = first.ok().flatten() else {
        return;
    };
    let Ok(LocalMessage::Authenticate {
        protocol,
        installation_id,
        signature_base64,
    }) = serde_json::from_str(&text)
    else {
        let _ = send_json(
            &mut socket,
            &RelayMessage::Error {
                protocol: PROTOCOL,
                code: "unauthenticated",
                message: "authenticate is required",
            },
        )
        .await;
        return;
    };
    if protocol != PROTOCOL
        || !verify_auth(
            &state,
            &installation_id,
            nonce.as_bytes(),
            &signature_base64,
        )
    {
        let _ = send_json(
            &mut socket,
            &RelayMessage::Error {
                protocol: PROTOCOL,
                code: "unauthenticated",
                message: "invalid installation authentication",
            },
        )
        .await;
        return;
    }
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
        let Message::Text(text) = message else {
            continue;
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
            _ => {}
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
    if connector != "linear" && connector != "slack" {
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
        if binding.connector == "linear" || binding.connector == "slack" {
            tx.execute("INSERT INTO bindings (binding_id, connector, installation_id, updated_at) VALUES (?1, ?2, ?3, ?4)", params![binding.binding_id, binding.connector, installation_id, now()])?;
        }
    }
    tx.commit()
}

fn initialize_database(db: &Connection) -> Result<(), rusqlite::Error> {
    db.execute_batch("PRAGMA foreign_keys = ON; CREATE TABLE IF NOT EXISTS installations (installation_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, created_at TEXT NOT NULL); CREATE TABLE IF NOT EXISTS bindings (binding_id TEXT PRIMARY KEY, connector TEXT NOT NULL CHECK (connector IN ('linear','slack')), installation_id TEXT NOT NULL REFERENCES installations(installation_id) ON DELETE CASCADE, updated_at TEXT NOT NULL); CREATE INDEX IF NOT EXISTS bindings_installation_idx ON bindings(installation_id);")
}

fn now() -> String {
    format_time(Utc::now())
}

fn format_time(value: chrono::DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests;
