//! Tests for the creation of a new `did:web` document.

use credibil_ecc::{Curve, Keyring, Signer};
use credibil_identity::did::{
    DocumentBuilder, KeyId, MethodType, ServiceBuilder, VerificationMethodBuilder, web,
};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Test the happy path of creating a new `did:web` document. Should just work
// without errors.
#[tokio::test]
async fn create_success() {
    const DID_URL: &str = "https://credibil.io/issuers/example";
    let did = web::default_did(DID_URL).expect("should create DID");
    assert_eq!(did, "did:web:credibil.io:issuers:example");

    let signer =
        Keyring::generate(&Vault, "wc", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");

    let vm = VerificationMethodBuilder::new(jwk)
        .did(&did)
        .key_id(KeyId::Index("key-0".to_string()))
        .method_type(MethodType::JsonWebKey2020)
        .build()
        .expect("should build");
    let service = ServiceBuilder::new(format!("{did}#whois"))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois")
        .build();
    let doc = DocumentBuilder::new(did)
        .verification_method(vm)
        .add_service(service)
        .build()
        .expect("should build document");

    let json = serde_json::to_string_pretty(&doc).expect("should serialize");
    print!("{json}");
}
