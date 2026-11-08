// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Vahid

//! mailxrayd — HTTP front end for mailxray-core.
//!
//!   POST /inspect?name=<filename>          body = attachment bytes → report
//!   POST /entry?path=<member>              body = archive bytes   → one member
//!   GET  /report/{blake3}                  cached report
//!   GET  /health
//!
//! The daemon never fetches mail, never holds credentials and never renders.
//! External tools (7-Zip for RAR/7z listing and extraction) run inside the tier
//! 1 sandbox; everything else is parsed in-process by memory-safe Rust.

mod listers;
mod sandbox;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use mailxray_core::detect;
use mailxray_core::{Details, FileClass, Reason, Verdict};
use serde::Deserialize;

/// Largest member returned for preview. A preview is a look, not a download.
const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;

struct App {
    policy: mailxray_core::Policy,
    store: PathBuf,
    runner: sandbox::Runner,
}

#[derive(Deserialize)]
struct InspectQuery {
    name: Option<String>,
}

#[derive(Deserialize)]
struct EntryQuery {
    path: String,
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

    let runner = sandbox::Runner::new();
    eprintln!(
        "mailxrayd listening on {addr} (sandbox: {:?}, store: {})",
        runner.mode,
        store.display()
    );

    let app = Arc::new(App {
        policy: mailxray_core::Policy::default(),
        store,
        runner,
    });

    let router = Router::new()
        .route("/inspect", post(inspect))
        .route("/entry", post(entry))
        .route("/report/{hash}", get(report))
        .route("/health", get(health))
        // Attachments are capped at 50 MB; anything larger is a policy problem,
        // not something to parse.
        .layer(DefaultBodyLimit::max(50 * 1024 * 1024))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn health(State(app): State<Arc<App>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "schema": 1,
        "sandbox": format!("{:?}", app.runner.mode),
    }))
}

async fn inspect(
    State(app): State<Arc<App>>,
    Query(q): Query<InspectQuery>,
    body: Bytes,
) -> Response {
    let mut report = mailxray_core::inspect(q.name.as_deref(), &body, &app.policy);

    // Containers the in-process parsers leave unlisted get a tier 1 pass.
    enrich(&app, &body, &mut report).await;

    let json = serde_json::to_vec(&report).unwrap_or_default();

    // Cache by content hash; a failed write must not fail the request.
    let path = app.store.join(format!("{}.json", report.hash));
    let tmp = app.store.join(format!(".{}.json.tmp", report.hash));
    if tokio::fs::write(&tmp, &json).await.is_ok() {
        let _ = tokio::fs::rename(&tmp, &path).await;
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
        .into_response()
}

/// List RAR/7z/bzip2/xz/zstd with 7-Zip when core recognised but could not open
/// them, and fold the result (including a blocked member) back into the report.
async fn enrich(app: &App, bytes: &[u8], report: &mut mailxray_core::Report) {
    let needs_listing = matches!(
        &report.details,
        Details::Archive(a) if !a.listed && a.format != "gzip" && a.format != "zip"
    );
    if !needs_listing {
        return;
    }

    let entries = match listers::list(&app.runner, bytes, &app.policy).await {
        Ok(entries) => entries,
        Err(e) => {
            report
                .reasons
                .push(Reason::suspicious("external-listing-failed", e));
            return;
        }
    };

    let blocked: Vec<String> = entries
        .iter()
        .filter(|e| e.verdict == Verdict::Blocked)
        .map(|e| e.name.clone())
        .collect();

    if let Details::Archive(a) = &mut report.details {
        a.entries = entries;
        a.listed = true;
    }
    // The listing succeeded, so the "could not look inside" reason is now false.
    report.reasons.retain(|r| r.code != "container-not-listed");

    if !blocked.is_empty() {
        report.verdict = Verdict::Blocked;
        report.reasons.push(Reason::blocked(
            "executable-inside",
            format!(
                "{} executable member(s): {}",
                blocked.len(),
                blocked
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
}

/// One member of an archive, so a wrapper can show it without handing the
/// original file to the client.
///
/// The caller sends the archive bytes it already has (the webmail has the blob
/// from its mail server), so the daemon keeps no archive store. Only inert
/// classes are returned — image, PDF, text, audio, video — decided by magic
/// bytes, never by the member's name.
async fn entry(State(app): State<Arc<App>>, Query(q): Query<EntryQuery>, body: Bytes) -> Response {
    if let Err(msg) = validate_member_path(&q.path) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    let archive_format = detect::detect(&body).as_str().to_string();
    let extracted = match listers::extract(
        &app.runner,
        &body,
        &archive_format,
        &q.path,
        MAX_ENTRY_BYTES,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(e) => return (StatusCode::UNPROCESSABLE_ENTITY, e).into_response(),
    };

    let class = detect::detect_with_name(Some(&q.path), &extracted);
    if !is_previewable(class) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("member type {} is not previewable", class.as_str()),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type(class, &extracted)),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_DISPOSITION, "inline"),
        ],
        extracted,
    )
        .into_response()
}

fn validate_member_path(path: &str) -> Result<(), &'static str> {
    if path.is_empty() || path.len() > 1024 {
        return Err("bad member path");
    }
    if path.starts_with('/') || path.starts_with('-') || path.contains("..") {
        return Err("bad member path");
    }
    if path.chars().any(|c| c == '\0' || c == '\\') {
        return Err("bad member path");
    }
    Ok(())
}

fn is_previewable(class: FileClass) -> bool {
    matches!(
        class,
        FileClass::Image | FileClass::Pdf | FileClass::Text | FileClass::Audio | FileClass::Video
    )
}

/// A concrete content type, sniffed from the bytes: `image/*` is not something a
/// browser will display.
fn content_type(class: FileClass, bytes: &[u8]) -> &'static str {
    match class {
        FileClass::Pdf => "application/pdf",
        FileClass::Text => "text/plain; charset=utf-8",
        FileClass::Image => {
            if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                "image/png"
            } else if bytes.starts_with(b"\xff\xd8\xff") {
                "image/jpeg"
            } else if bytes.starts_with(b"GIF8") {
                "image/gif"
            } else if bytes.starts_with(b"RIFF") && bytes.len() > 12 && &bytes[8..12] == b"WEBP" {
                "image/webp"
            } else {
                "application/octet-stream"
            }
        }
        FileClass::Audio => "audio/mpeg",
        FileClass::Video => "video/mp4",
        _ => "application/octet-stream",
    }
}

async fn report(State(app): State<Arc<App>>, Path(hash): Path<String>) -> impl IntoResponse {
    // The hash is a path segment and untrusted: only hex survives.
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return (StatusCode::BAD_REQUEST, "bad hash").into_response();
    }
    match tokio::fs::read(app.store.join(format!("{hash}.json"))).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "no report").into_response(),
    }
}
