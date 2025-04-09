//! Deactivate operation

use axum::{extract::State, http::StatusCode};
use axum_extra::{TypedHeader, headers::Host};
use credibil_did::webvh::{DeactivateBuilder, DeactivateResult};

use crate::{AppError, AppJson, state::AppState};

// Handler to deactivate a DID document
#[axum::debug_handler]
pub async fn deactivate(
    State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
) -> Result<AppJson<DeactivateResult>, AppError> {
    let domain_and_path = format!("http://{host}");

    tracing::debug!("deactivating DID log document for {domain_and_path}");

    let mut keyring = state.keyring.lock().await;

    // Rotate keys
    keyring.rotate()?;
    let update_multi = keyring.multibase("signing")?;
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();
    let next_multi = keyring.next_multibase("signing")?;
    let next_keys = vec![next_multi.clone()];
    let next_keys: Vec<&str> = next_keys.iter().map(|s| s.as_str()).collect();

    // Resolve the latest DID document from the log and start building the
    // deactivation.
    let mut log = state.log.lock().await;
    let Some(did_log) = log.get_log(&domain_and_path) else {
        return Err(AppError::Status(
            StatusCode::NOT_FOUND,
            "No existing log found to deactivate. Use create to get started.".into(),
        ));
    };

    let result = DeactivateBuilder::from(&did_log)?
        .rotate_keys(&update_keys, &next_keys)?
        .signer(&*keyring)
        .build()
        .await?;

    // Store the log in app state
    log.add_log(&domain_and_path, result.log.clone())?;

    Ok(AppJson(result))
}
