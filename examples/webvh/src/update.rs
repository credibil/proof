//! Update operation

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum_extra::TypedHeader;
use axum_extra::headers::Host;
use credibil_identity::core::Kind;
use credibil_identity::did::webvh::{UpdateBuilder, UpdateResult, resolve_log};
use credibil_identity::did::{
    DocumentBuilder, KeyPurpose, MethodType, PublicKeyFormat, VerificationMethod,
    VerificationMethodBuilder, VmKeyId,
};
use serde::{Deserialize, Serialize};

use super::{AppError, AppJson};
use crate::state::AppState;

// Example options to influence the update process.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpdateRequest {
    // Add a verification method to the document with the specified purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub add: Option<KeyPurpose>,
}

// Handler to create a new DID log document
#[axum::debug_handler]
pub async fn update(
    State(state): State<AppState>, TypedHeader(host): TypedHeader<Host>,
    Json(req): Json<UpdateRequest>,
) -> Result<AppJson<UpdateResult>, AppError> {
    let domain_and_path = format!("http://{host}");

    tracing::debug!("updating DID log document for {domain_and_path}, with request: {req:?}");

    let mut keyring = state.keyring.lock().await;

    // Rotate keys
    keyring.rotate().await?;
    let update_multi = keyring.multibase("signing").await?;
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();
    let next_multi = keyring.next_multibase("signing").await?;
    let next_keys = vec![next_multi.clone()];
    let next_keys: Vec<&str> = next_keys.iter().map(|s| s.as_str()).collect();

    // Get a new ID key for the new verification method.
    keyring.replace("id").await?;
    let id_multi = keyring.multibase("id").await?;

    // Resolve the latest DID document from the log and start building the
    // update.
    let mut log = state.log.lock().await;
    let Some(did_log) = log.get_log(&domain_and_path) else {
        return Err(AppError::Status(
            StatusCode::NOT_FOUND,
            "No existing log found to update. Use create to get started.".into(),
        ));
    };
    let current_doc = resolve_log(&did_log, None, None).await?;
    let mut db = DocumentBuilder::from(&current_doc);

    // Create a new verification method.
    let vm = VerificationMethodBuilder::new(&PublicKeyFormat::PublicKeyMultibase {
        public_key_multibase: update_multi,
    })
    .key_id(&current_doc.id, VmKeyId::Authorization(id_multi))?
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
            }
            _ => {
                let ref_vm = Kind::<VerificationMethod>::String(vm.id.clone());
                db = db.add_verification_method(&ref_vm, &purpose)?;
            }
        }
    }

    // Create an update log entry.
    let doc = db.build();
    let result = UpdateBuilder::from(&did_log, None)
        .await?
        .document(&doc)?
        .rotate_keys(&update_keys, &next_keys)?
        .signer(&*keyring)
        .build()
        .await?;

    // Store the log in app state
    log.add_log(&domain_and_path, result.log.clone())?;

    Ok(AppJson(result))
}
