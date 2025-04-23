//! Create operation

use axum::Json;
use axum::extract::State;
use axum_extra::{TypedHeader, headers::Host};
use credibil_identity::{
    DocumentBuilder, KeyPurpose, MethodType, PublicKeyFormat, VerificationMethod,
    VerificationMethodBuilder, VmKeyId,
    core::Kind,
    webvh::{CreateBuilder, CreateResult, default_did},
};
use serde::{Deserialize, Serialize};

use super::{AppError, AppJson};
use crate::state::AppState;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateRequest {}

// Handler to create a new DID log document
#[axum::debug_handler]
pub async fn create(
    State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
    Json(_req): Json<CreateRequest>,
) -> Result<AppJson<CreateResult>, AppError> {
    let domain_and_path = format!("http://{host}");

    tracing::debug!("creating DID log document for {domain_and_path}");

    let mut keyring = state.keyring.lock().await;

    let update_multi = keyring.multibase("signing")?;
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();
    let id_multi = keyring.multibase("id")?;
    let did = default_did(&domain_and_path)?;
    let next_key = keyring.next_multibase("signing")?;

    let vm = VerificationMethodBuilder::new(&PublicKeyFormat::PublicKeyMultibase {
        public_key_multibase: update_multi,
    })
    .key_id(&did, VmKeyId::Authorization(id_multi))?
    .method_type(&MethodType::Ed25519VerificationKey2020)?
    .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());

    tracing::debug!("keys established");

    // Could add other verification methods and service endpoints to the
    // `CreateRequest` and build them here.

    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)?
        .build();

    let result = CreateBuilder::new()
        .document(&doc)?
        .update_keys(&update_keys)?
        .next_key(&next_key)
        .signer(&*keyring)
        .build()
        .await?;

    // Store the log in app state
    let mut log = state.log.lock().await;
    log.add_log(&domain_and_path, result.log.clone())?;

    Ok(AppJson(result))
}
