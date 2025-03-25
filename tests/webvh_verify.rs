//! Tests to verify log entries.

use credibil_did::{
    KeyPurpose,
    core::{Kind, OneMany},
    document::{MethodType, Service, VerificationMethod},
    operation::document::{Create, DocumentBuilder, VerificationMethodBuilder, VmKeyId},
    webvh::{
        SCID_PLACEHOLDER, Witness, WitnessWeight, create::CreateBuilder, url::default_did,
        verify::verify_proofs,
    },
};
use kms::new_keyring;
use serde_json::Value;

// Create a minimal document and then verify the proof. Should verify without
// errors.
#[tokio::test]
async fn simple_proof() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let signer = new_keyring();
    let auth_jwk = signer.verifying_key_jwk().await.expect("should get JWK key");
    let update_multi = signer.verifying_key_multibase().await.expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm_jwk = signer.verifying_key_jwk().await.expect("should get JWK key");
    let vm = VerificationMethodBuilder::new(&vm_jwk)
        .key_id(&did, VmKeyId::Authorization(auth_jwk))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    let doc = DocumentBuilder::<Create>::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .build();

    let result = CreateBuilder::new(&update_keys, &doc)
        .expect("should create builder")
        .build(&signer)
        .await
        .expect("should build document");

    verify_proofs(&result.log[0], &signer).await.expect("should verify proof");
}

// Create a document with more options and then verify the proof. Should verify
// without errors.
#[tokio::test]
async fn complex_proof() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let signer = new_keyring();
    let auth_jwk = signer.verifying_key_jwk().await.expect("should get JWK key");
    let update_multi = signer.verifying_key_multibase().await.expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm_jwk = new_keyring().verifying_key_jwk().await.expect("should get JWK key");
    let vm = VerificationMethodBuilder::new(&vm_jwk)
        .key_id(&did, VmKeyId::Authorization(auth_jwk))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    let service = Service {
        id: format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER),
        type_: "LinkedVerifiablePresentation".to_string(),
        service_endpoint: OneMany::<Kind<Value>>::One(Kind::String(
            "https://example.com/.well-known/whois".to_string(),
        )),
    };
    let doc = DocumentBuilder::<Create>::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_multi =
        new_keyring().verifying_key_multibase().await.expect("should get multibase key");

    let witness_keyring1 = new_keyring();
    let witness1 = WitnessWeight {
        id: witness_keyring1.did().to_string(),
        weight: 50,
    };
    let witness_keyring2 = new_keyring();
    let witness2 = WitnessWeight {
        id: witness_keyring2.did().to_string(),
        weight: 40,
    };

    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![witness1, witness2],
    };

    let result = CreateBuilder::new(&update_keys, &doc)
        .expect("should create builder")
        .next_key(&next_multi)
        .portable(false)
        .witness(&witnesses)
        .expect("witness information should be applied")
        .ttl(60)
        .build(&signer)
        .await
        .expect("should build document");

    verify_proofs(&result.log[0], &signer).await.expect("should verify proof");
}
