//! Create operation

use axum::Json;
use axum::extract::State;
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_identity::did::webvh::{CreateBuilder, CreateResult, default_did};
use credibil_identity::did::{DocumentBuilder, KeyId, MethodType, VerificationMethodBuilder};
use credibil_jose::PublicKeyJwk;
use serde::{Deserialize, Serialize};

use super::{AppError, AppJson};
use crate::state::AppState;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateRequest;

// Handler to create a new DID log document
#[axum::debug_handler]
pub async fn create(
    State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
    Json(_req): Json<CreateRequest>,
) -> Result<AppJson<CreateResult>, AppError> {
    let did_url = format!("http://{host}");

    tracing::debug!("creating DID log document for {did_url}");

    let vault = state.vault;
    let signer = Keyring::generate(&vault, "wvhd", "signing", Curve::Ed25519).await?;
    let verifying_key = signer.verifying_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&verifying_key)?;
    let update_multi = jwk.to_multibase()?;

    let id_entry = Keyring::generate(&vault, "wvhd", "id", Curve::Ed25519).await?;
    let verifying_key = id_entry.verifying_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&verifying_key)?;
    let id_multi = jwk.to_multibase()?;

    let did = default_did(&did_url)?;

    let next_key = signer.next_key().await?;
    let jwk = PublicKeyJwk::from_bytes(&next_key)?;
    let next_multi = jwk.to_multibase()?;

    let vm = VerificationMethodBuilder::new(update_multi.clone())
        .did(&did)
        .key_id(KeyId::Authorization(id_multi))
        .method_type(MethodType::Multikey)
        .build()?;

    tracing::debug!("keys established");

    // Could add other verification methods and service endpoints to the
    // `CreateRequest` and build them here.
    let doc = DocumentBuilder::new(did).verification_method(vm).build()?;

    let result = CreateBuilder::new()
        .document(doc)?
        .update_keys(vec![update_multi])?
        .next_key(&next_multi)
        .signer(&signer)
        .build()
        .await?;

    // Store the log in app state
    let mut log = state.log.lock().await;
    log.add_log(&did_url, result.log.clone())?;

    Ok(AppJson(result))
}
