use agentchannels_relay::{router, AppState, EnrollmentPolicy, RelayConfig};
use std::{env, path::PathBuf};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_path = env::var_os("AGENTCHANNELS_RELAY_DATABASE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("agentchannels-relay.db"));
    let bind =
        env::var("AGENTCHANNELS_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let enrollment_policy = EnrollmentPolicy::from_env().map_err(std::io::Error::other)?;
    let config = RelayConfig::new(database_path, enrollment_policy);
    let state = AppState::open(config)?;
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("AgentChannels relay listening on {bind}");
    axum::serve(listener, router(state)).await?;
    Ok(())
}
