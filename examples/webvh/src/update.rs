//! Update operation

use axum::{http::StatusCode, Json};
use axum::extract::State;
use axum_extra::{TypedHeader, headers::Host};
use credibil_did::core::Kind;
use credibil_did::webvh::UpdateBuilder;
use credibil_did::{DocumentBuilder, MethodType, VerificationMethod, VerificationMethodBuilder, VmKeyId};
use credibil_did::{webvh::{resolve_log, UpdateResult}, KeyPurpose};
use serde::{Deserialize, Serialize};

use super::{AppError, AppJson};
use crate::state::AppState;

// Example options to influence the update process.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateRequest {
    // Add a verification method to the document with the specified purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add: Option<KeyPurpose>,

    // Flag to rotate keys (true) or not (false).
    pub rotate_keys: bool,
}

// Handler to create a new DID log document
#[axum::debug_handler]
pub async fn update(State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
Json(req): Json<UpdateRequest>,) -> Result<AppJson<UpdateResult>, AppError> {
    let domain_and_path = format!("http://{host}");

    tracing::debug!("updating DID log document for {domain_and_path}");

    let mut keyring = state.keyring.lock().await;
    // Rotate keys
    if req.rotate_keys {
        keyring.rotate()?;
    }
    let update_jwk = keyring.jwk("signing")?;
    let update_multi = keyring.multibase("signing")?;
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();
    let next_multi = keyring.next_multibase("signing")?;
    let next_keys = vec![next_multi.clone()];
    let next_keys: Vec<&str> = next_keys.iter().map(|s| s.as_str()).collect();

    // Get a new ID key for the new verification method.
    let id_jwk = keyring.replace("id")?;

    // Resolve the latest DID document from the log and start building the
    // update.
    let mut log = state.log.lock().await;
    let Some(did_log) = log.get_log(&domain_and_path) else {
        return Err(AppError::Status(StatusCode::NOT_FOUND, "No existing log found to update. Use create to get started.".into()));
    };
    let current_doc = resolve_log(&did_log, None, None).await?;
    let mut db = DocumentBuilder::from(&current_doc);

    // Create a new verification method.
    let vm = VerificationMethodBuilder::new(&update_jwk)
        .key_id(&current_doc.id, VmKeyId::Authorization(id_jwk))?
        .method_type(&MethodType::Ed25519VerificationKey2020)?
        .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    db = db.add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)?;

    // Add a reference-based verification method if requested.
    if let Some(purpose) = req.add {
        match purpose {
            KeyPurpose::VerificationMethod => {
                // Do nothing. We have already added a general verification
                // method.
            },
            _ => {
                let ref_vm = Kind::<VerificationMethod>::String(vm.id.clone());
                db = db.add_verification_method(&ref_vm, &purpose)?;
            }
        }
    }

    // Create an update log entry.
    let doc = db.build();
    let mut ub = UpdateBuilder::new(&did_log, None, &doc).await?;
    if req.rotate_keys {
        ub = ub.rotate_keys(&update_keys, &next_keys)?;
    }
    let result = ub.signer(&*keyring).build().await?;

    // Store the log in app state
    log.add_log(&domain_and_path, result.log.clone())?;

    Ok(AppJson(result))
}
