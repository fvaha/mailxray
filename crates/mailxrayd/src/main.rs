// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Vahid
//! mailxrayd — HTTP front end for mailxray-core.
//!
//!   POST /inspect?name=attachment.pdf   (body = raw attachment bytes)
//!   GET  /report/{blake3}               (cached report, for the webmail UI)
//!   GET  /health
//!
//! The daemon never fetches mail, never holds credentials and never renders.
//! It receives one attachment, returns one report, and caches it by content hash
//! so the same file is inspected once for every recipient.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;

struct App {
    policy: mailxray_core::Policy,
    store: PathBuf,
}

#[derive(Deserialize)]
struct InspectQuery {
    name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = std::env::var("MAILXRAY_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8377".into())
        .parse()?;
    let store = PathBuf::from(
        std::env::var("MAILXRAY_STORE").unwrap_or_else(|_| "/var/lib/mailxray".into()),
    );
    std::fs::create_dir_all(&store)?;

    let app = Arc::new(App {
        policy: mailxray_core::Policy::default(),
        store,
    });

    let router = Router::new()
        .route("/inspect", post(inspect))
        .route("/report/{hash}", get(report))
        .route("/health", get(health))
        // Attachments are capped at 50 MB; anything larger is a policy problem,
        // not something to parse.
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("mailxrayd listening on {addr}");
    axum::serve(listener, router).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "schema": 1,
    }))
}

async fn inspect(
    State(app): State<Arc<App>>,
    Query(q): Query<InspectQuery>,
    body: Bytes,
) -> impl IntoResponse {
    let report = mailxray_core::inspect(q.name.as_deref(), &body, &app.policy);
    let json = serde_json::to_vec(&report).unwrap_or_default();

    // Cache by content hash; a failed write must not fail the request.
    let path = app.store.join(format!("{}.json", report.hash));
    let tmp = app.store.join(format!(".{}.json.tmp", report.hash));
    if tokio::fs::write(&tmp, &json).await.is_ok() {
        let _ = tokio::fs::rename(&tmp, &path).await;
    }

    (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "application/json")], json)
}

async fn report(
    State(app): State<Arc<App>>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    // The hash is a path segment and untrusted: only hex survives.
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "bad hash").into_response();
    }
    match tokio::fs::read(app.store.join(format!("{hash}.json"))).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "no report").into_response(),
    }
}
