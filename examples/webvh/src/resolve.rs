use axum::BoxError;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use axum_extra::json_lines::JsonLines;
use credibil_identity::did::webvh::{DidLog, DidLogEntry, resolve_log};
use credibil_identity::did::{Document, QueryParams};
use futures_util::Stream;

use crate::state::AppState;
use crate::{AppError, AppJson};

// Handler to read the DID log file (from memory in our case).
#[axum::debug_handler]
pub async fn read(State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>) -> Response {
    const DID_URL:&str = format!("http://{host}");

    tracing::debug!("reading DID log document for {DID_URL}");

    let log = state.log.lock().await;
    let Some(entries) = log.get_log(&DID_URL) else {
        return AppError::Status(StatusCode::NOT_FOUND, "No log found".into()).into_response();
    };

    let values = entries_as_stream(entries);
    JsonLines::new(values).into_response()
}

fn entries_as_stream(entries: DidLog) -> impl Stream<Item = Result<DidLogEntry, BoxError>> {
    futures_util::stream::iter(entries.into_iter().map(|entry| {
        // Convert each entry to a Result
        Ok(entry)
    }))
}

// Handler to resolve a DID document from a DID log file.
#[axum::debug_handler]
pub async fn resolve(
    State(state): State<AppState>, Query(params): Query<QueryParams>,
    TypedHeader(host): TypedHeader<Host>,
) -> Result<AppJson<Document>, AppError> {
    const DID_URL:&str = format!("http://{host}");

    tracing::debug!("resolving DID document for {DID_URL}");

    let log = state.log.lock().await;
    let entries = log
        .get_log(&DID_URL)
        .ok_or_else(|| return AppError::Status(StatusCode::NOT_FOUND, "No log found".into()))?;
    let doc = resolve_log(&entries, None, Some(&params)).await?;

    Ok(AppJson(doc))
}
