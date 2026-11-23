//! Keygate service row for one authenticated pod principal.
use crate::station::AnyError;
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use landd_core::{
    pod_ledger::{Action, PodLedger},
    Digest32,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(clap::Args)]
pub struct Service {
    #[arg(long)]
    database: PathBuf,
    #[arg(long)]
    lead: String,
    #[arg(long)]
    principal: String,
    #[arg(long)]
    credential_sha256: Digest32,
    #[arg(long)]
    listen: SocketAddr,
}
struct Pod {
    db: Mutex<PodLedger>,
    principal: String,
    credential: Digest32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    pod: String,
    task: String,
    lease_seconds: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Done {
    pod: String,
    task: String,
    fencing_token: String,
}

async fn apply(
    state: Arc<Pod>,
    headers: HeaderMap,
    pod: String,
    task: String,
    action: Action,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth =
        headers.get("authorization").and_then(|h| h.as_bytes().strip_prefix(b"Bearer ")).ok_or(StatusCode::UNAUTHORIZED)?;
    if Sha256::digest(auth)[..] != state.credential.as_bytes()[..] {
        return Err(StatusCode::UNAUTHORIZED);
    }
    tokio::task::spawn_blocking(move || {
        let mut ledger = state.db.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let now = crate::daemon::unix_now().try_into().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let row = ledger
            .apply(&state.principal, &pod, &task, now, action)
            .map_err(|_| StatusCode::CONFLICT)?
            .ok_or(StatusCode::CONFLICT)?;
        Ok(Json(serde_json::json!({"fencing_token":row.fencing_token.to_string()})))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
impl Service {
    pub fn run(self) -> Result<(), AnyError> {
        if !self.listen.ip().is_loopback() {
            return Err("pod-service requires a loopback listener".into());
        }
        let state = Arc::new(Pod {
            db: Mutex::new(PodLedger::open(&self.database, &self.lead)?),
            principal: self.principal,
            credential: self.credential_sha256,
        });
        tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
            let app = Router::new()
                .route(
                    "/pod/claim",
                    post(|State(s), h, Json(c): Json<Claim>| async move {
                        apply(s, h, c.pod, c.task, Action::Claim { lease_seconds: c.lease_seconds }).await
                    }),
                )
                .route(
                    "/pod/done",
                    post(|State(s), h, Json(d): Json<Done>| async move {
                        let fencing_token = d.fencing_token.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
                        apply(s, h, d.pod, d.task, Action::Done { fencing_token }).await
                    }),
                )
                .layer(DefaultBodyLimit::max(8192))
                .with_state(state);
            let listener = tokio::net::TcpListener::bind(self.listen).await?;
            println!("{}", listener.local_addr()?);
            axum::serve(listener, app).await?;
            Ok(())
        })
    }
}
