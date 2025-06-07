//! Tests being able to dereference a resource from a `did:web` document.

use std::str::FromStr;

use credibil_ecc::{Curve, Keyring, Signer};
use credibil_identity::did::{
    DocumentBuilder, KeyFormat, KeyId, MethodType, Resource, ServiceBuilder, Url,
    VerificationMethodBuilder, document_resource, web,
};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Create a new `did:web` document and dereference a resource from it.
#[tokio::test]
async fn create_then_deref() {
    let domain_and_path = "https://credibil.io/issuers/example";
    let did = web::default_did(domain_and_path).expect("should get default DID");
    assert_eq!(did, "did:web:credibil.io:issuers:example");

    let signer =
        Keyring::generate(&Vault, "wd", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");

    let vm = VerificationMethodBuilder::new(jwk.clone())
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
        .verification_method(vm.clone())
        .add_service(service)
        .build()
        .expect("should build document");
    let url = Url::from_str(&vm.id).expect("should parse DID");

    let deref_vm = document_resource(&url, &doc).expect("should dereference VM");
    let Resource::VerificationMethod(deref_vm) = deref_vm else {
        panic!("should be a verification method");
    };

    let KeyFormat::Jwk { public_key_jwk } = deref_vm.key else {
        panic!("should be a JWK");
    };
    assert_eq!(public_key_jwk.x, jwk.x);
}
