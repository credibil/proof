use axum::Json;
use axum::extract::State;
use axum_extra::{TypedHeader, headers::Host};
use credibil_did::{
    Create, DocumentBuilder, KeyPurpose, MethodType, VerificationMethod, VerificationMethodBuilder,
    VmKeyId,
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

    let update_jwk = state.keyring.jwk("signing")?;
    let update_multi = update_jwk.to_multibase()?;
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let id_jwk = state.keyring.jwk("id")?;

    let did = default_did(&domain_and_path)?;

    let vm = VerificationMethodBuilder::new(&update_jwk)
        .key_id(&did, VmKeyId::Authorization(id_jwk))?
        .method_type(&MethodType::Ed25519VerificationKey2020)?
        .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    state.keyring.set_verification_method(vm.id)?;

    // Could add other verification methods and service endpoints to the
    // `CreateRequest` and build them here.

    let doc = DocumentBuilder::<Create>::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)?
        .build();

    let result = CreateBuilder::new(&update_keys, &doc)?.build(&state.keyring).await?;

    Ok(AppJson(result))
}
