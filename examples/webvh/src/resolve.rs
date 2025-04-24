use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response}, BoxError,
};
use axum_extra::{TypedHeader, headers::Host, json_lines::JsonLines};
use credibil_identity::did::{webvh::{resolve_log, DidLog, DidLogEntry}, Document, QueryParams};
use futures_util::Stream;

use crate::{AppError, AppJson};
use crate::state::AppState;

// Handler to read the DID log file (from memory in our case).
#[axum::debug_handler]
pub async fn read(State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>) -> Response {
    let domain_and_path = format!("http://{host}");

    tracing::debug!("reading DID log document for {domain_and_path}");

    let log = state.log.lock().await;
    let Some(entries) = log.get_log(&domain_and_path) else {
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
    let domain_and_path = format!("http://{host}");

    tracing::debug!("resolving DID document for {domain_and_path}");

    let log = state.log.lock().await;
    let entries = log
        .get_log(&domain_and_path)
        .ok_or_else(|| return AppError::Status(StatusCode::NOT_FOUND, "No log found".into()))?;
    let doc = resolve_log(&entries, None, Some(&params)).await?;

    Ok(AppJson(doc))
}
