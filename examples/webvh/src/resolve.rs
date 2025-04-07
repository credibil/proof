use axum::{
    extract::State,
    http::StatusCode,
};
use axum_extra::{TypedHeader, headers::Host};
use credibil_did::webvh::DidLog;

use super::{AppError, AppJson};
use crate::state::AppState;

// Handler to read the DID log file (from memory in our case).
#[axum::debug_handler]
pub async fn read(
    State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
) -> Result<AppJson<DidLog>, AppError> {
    let domain_and_path = format!("http://{host}");

    tracing::debug!("reading DID log document for {domain_and_path}");

    let log = state.log.lock().await;
    let entries = log
        .get_log(&domain_and_path)
        .ok_or_else(|| return AppError::Status(StatusCode::NOT_FOUND, "No log found".into()))?;

    Ok(AppJson(entries))
}

// Handler to resolve a DID document from a DID log file.
// #[axum::debug_handler]
// pub async fn resolve(
//     State(state): State<AppState>, Query(params): Query<QueryParams>,
//     TypedHeader(host): TypedHeader<Host>,
// ) -> Result<AppJson<DidLog>, AppError> {
//     let domain_and_path = format!("http://{host}");

//     tracing::debug!("resolving DID document for {domain_and_path}");

//     let log = state.log.lock().await;
//     let entries = log
//         .get_log(&domain_and_path)
//         .ok_or_else(|| return AppError::Status(StatusCode::NOT_FOUND, "No log found".into()))?;


//     Ok(AppJson(did))
// }
