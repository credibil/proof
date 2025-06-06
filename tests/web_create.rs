//! Tests for the creation of a new `did:web` document.

use credibil_ecc::{Curve, Keyring, Signer};
use credibil_identity::core::Kind;
use credibil_identity::did::{
    DocumentBuilder, KeyPurpose, MethodType, ServiceBuilder, VerificationMethodBuilder, VmKeyId,
    web,
};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Test the happy path of creating a new `did:web` document. Should just work
// without errors.
#[tokio::test]
async fn create_success() {
    let domain_and_path = "https://credibil.io/issuers/example";
    let did = web::default_did(domain_and_path).expect("should get default DID");
    assert_eq!(did, "did:web:credibil.io:issuers:example");

    let signer =
        Keyring::generate(&Vault, "wc", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");

    let vm = VerificationMethodBuilder::new(jwk)
        .key_id(&did, VmKeyId::Index("key".to_string(), 0))
        .expect("should apply key ID")
        .method_type(&MethodType::JsonWebKey2020)
        .expect("should apply method type")
        .build();
    let service = ServiceBuilder::new(format!("{did}#whois"))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois".to_string())
        .build();
    let doc = DocumentBuilder::new(did)
        .add_verification_method(Kind::Object(vm), &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(service)
        .build();

    let json_doc = serde_json::to_string_pretty(&doc).expect("should serialize document");
    print!("{json_doc}");
}
