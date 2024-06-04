use std::sync::Arc;

use anyhow::bail;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get, get_service, patch, post};
use axum::{Json, Router};
use serde::Deserialize;
use tower_http::services::ServeDir;
use vercre_did::test_utils::TestKeyRingSigner;
use vercre_did::{DidDocument, Patch, Registrar, Service, WebRegistrar};

// Application entry point.
#[tokio::main]
async fn main() {
    let domain = "localhost%3A3000";
    let controller = format!("did:web:{}", domain);
    let state = Arc::new(AppState {
        registrar: WebRegistrar::new(domain, TestKeyRingSigner::new(), Some(controller.clone())),
    });

    let app = Router::new()
        .route("/", get(info))
        .route("/", post(create))
        .route("/", patch(update))
        .route("/", delete(deactivate))
        .nest_service("/.well-known", get_service(ServeDir::new("./.well-known")))
        .with_state(state);

    println!("Listening on http://localhost:3000");
    let listener = tokio::net::TcpListener::bind(&"0.0.0.0:3000").await.expect("failed to bind");
    axum::serve(listener, app).await.expect("failed to run server");
}

// Keep a Registrar instance in state.
struct AppState {
    registrar: WebRegistrar<TestKeyRingSigner>,
}

// Root route handler. Simple disclaimer.
async fn info() -> &'static str {
    "Sample DID Web implementation only. Not suitable for production use."
}

// Request body for create. Path should be a URL-compliant path relative to the .well-known
// directory.
#[derive(Default, Deserialize)]
struct CreateRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    services: Vec<Service>,
}

// Create a DID document.
//
// ## Usage:
//
// ```
// curl --location 'http://localhost:3000' \
// --header 'Content-Type: application/json' \
// --data '{
//     "path": "/test",
//     "services": [
//         {
//             "id": "did:example:123#vcs",
//             "type": "VerifiableCredentialService",
//             "serviceEndpoint": "http://localhost:3000/vc/"
//         }
//     ]
// }
// '
// ```
//
// ## Result
//
// ```
// curl --location 'http://localhost:3000/.well-known/test/did.json'
// ```
async fn create(
    State(state): State<Arc<AppState>>, Json(req): Json<CreateRequest>,
) -> (StatusCode, Json<DidDocument>) {
    let domain = "localhost%3A3000";
    let controller = format!("did:web:{}", domain);

    let mut doc = state.registrar.create(Some(&req.services)).await.unwrap();

    let mut id = controller.clone();
    if let Some(path) = req.path.clone() {
        if !path.starts_with('/') {
            id.push_str(":");
        }
        id.push_str(&path.replace('/', ":"));
    }
    doc.id = id;

    // Store the DID document in the file system for direct serving.
    match put_doc(&doc) {
        Ok(_) => (StatusCode::CREATED, Json(doc)),
        Err(e) => {
            println!("Failed to write DID document to file: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(DidDocument::default()));
        }
    }
}

// Request body for update. The DID should be resolvable on this registry.
#[derive(Debug, Default, Deserialize)]
struct UpdateRequest {
    did: String,
    patches: Vec<Patch>,
}

// Update a DID document.
//
// ## Usage:
//
// ```
// curl --location --request PATCH 'http://localhost:3000' \
// --header 'Content-Type: application/json' \
// --data '{
//     "did": "did:web:localhost%3A3000:test",
//     "patches": [
//         {
//             "action": "add-public-keys",
//             "publicKeys": [
//                 {
//                     "verificationMethod": {
//                         "id": "key2",
//                         "type": "EcdsaSecp256k1VerificationKey2019",
//                         "publicKeyJwk": {
//                             "kty": "EC",
//                             "crv": "secp256k1",
//                             "x": "QJZEHYfuTyjhIywIPKW_VLj9KQHUjLYCZJXJaNo2JQ4",
//                             "y": "p_j1EtkaHqnuporRvK1Y0iyQ3orNmj5EzFVErdkGOFg"
//                         }
//                     },
//                     "purposes": ["authentication", "keyAgreement"]
//                 }
//             ]
//         }
//     ]
// }
// '
// ```
async fn update(
    State(state): State<Arc<AppState>>, Json(req): Json<UpdateRequest>,
) -> (StatusCode, Json<DidDocument>) {
    // Use the DID to load the document from the file system.
    let doc = match get_doc(&req.did) {
        Ok(d) => d,
        Err(e) => {
            println!("Failed to load DID document: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(DidDocument::default()));
        }
    };

    let new_doc = match state.registrar.update(&doc, &req.patches).await {
        Ok(d) => d,
        Err(e) => {
            println!("Failed to update DID document: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(DidDocument::default()));
        }
    };

    // Store the DID document in the file system for direct serving.
    match put_doc(&new_doc) {
        Ok(_) => (StatusCode::CREATED, Json(new_doc)),
        Err(e) => {
            println!("Failed to write DID document to file: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(DidDocument::default()));
        }
    }
}

// Request body for deactivate. The DID should be resolvable on this registry.
#[derive(Debug, Default, Deserialize)]
struct DeactivateRequest {
    did: String,
}

// Deactivate (remove) a DID document.
//
// ## Usage:
//
// ```
// curl --location --request DELETE 'http://localhost:3000/' \
// --header 'Content-Type: application/json' \
// --data '{
//     "did": "did:web:localhost%3A3000:test"
// }
// '
// ```
async fn deactivate(
    State(_state): State<Arc<AppState>>, Json(req): Json<DeactivateRequest>,
) -> (StatusCode, ()) {
    match delete_doc(&req.did) {
        Ok(_) => (StatusCode::NO_CONTENT, ()),
        Err(e) => {
            println!("Failed to delete DID document: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, ());
        }
    }
}

// Load a DID document from the file system.
fn get_doc(did: &str) -> anyhow::Result<DidDocument> {
    let path = did_to_path(did)?;
    let doc = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&doc)?)
}

// Store the DID document in the file system for direct serving.
fn put_doc(doc: &DidDocument) -> anyhow::Result<()> {
    let path = did_to_path(&doc.id)?;
    let parent = path.trim_end_matches("/did.json");
    std::fs::create_dir_all(parent)?;
    std::fs::write(path, serde_json::to_string_pretty(&doc).expect("failed to serialize"))?;
    Ok(())
}

// Delete the DID document from the file system.
fn delete_doc(did: &str) -> anyhow::Result<()> {
    let path = did_to_path(did)?;
    std::fs::remove_file(path)?;
    Ok(())
}

// Convert a DID to a path.
fn did_to_path(did: &str) -> anyhow::Result<String> {
    if !did.starts_with("did:web:") {
        bail!("invalidDid");
    }
    if !did.contains("localhost%3A3000") {
        bail!("invalidDid");
    }

    let mut path = "./.well-known".to_string();
    let has_path = did.matches(':').count() > 2;
    if has_path {
        path += &did.trim_start_matches("did:web:localhost%3A3000").to_string().replace(':', "/");
    }
    path += "/did.json";
    Ok(path)
}
