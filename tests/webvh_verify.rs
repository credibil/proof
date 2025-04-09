//! Tests to verify log entries.

use credibil_did::{
    KeyPurpose,
    core::{Kind, OneMany},
    document::{
        DocumentBuilder, MethodType, Service, VerificationMethod, VerificationMethodBuilder,
        VmKeyId,
    },
    webvh::{CreateBuilder, SCID_PLACEHOLDER, Witness, WitnessWeight, default_did, verify_proofs},
};
use credibil_infosec::Signer;
use kms::Keyring;
use serde_json::Value;

// Create a minimal document and then verify the proof. Should verify without
// errors.
#[tokio::test]
async fn simple_proof() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = Keyring::new();
    let update_jwk = signer.jwk("signing").expect("should get signing key");
    let update_multi = signer.multibase("signing").expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let id_jwk = signer.jwk("id").expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(&update_jwk)
        .key_id(&did, VmKeyId::Authorization(id_jwk))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();
    signer.set_verification_method("signing").expect("should set verification method");
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .build();

    let result = CreateBuilder::new()
        .document(&doc)
        .expect("should apply document")
        .update_keys(&update_keys)
        .expect("should apply update keys")
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    println!("result log[0]: {:?}", result.log[0]);
    verify_proofs(&result.log[0]).await.expect("should verify proof");
}

// Create a document with more options and then verify the proof. Should verify
// without errors.
#[tokio::test]
async fn complex_proof() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = Keyring::new();
    let update_jwk = signer.jwk("signing").expect("should get signing key");
    let update_multi = signer.multibase("signing").expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let id_jwk = signer.jwk("id").expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(&update_jwk)
        .key_id(&did, VmKeyId::Authorization(id_jwk))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    signer.set_verification_method("signing").expect("should set verification method");
    let service = Service {
        id: format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER),
        type_: "LinkedVerifiablePresentation".to_string(),
        service_endpoint: OneMany::<Kind<Value>>::One(Kind::String(
            "https://example.com/.well-known/whois".to_string(),
        )),
    };
    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_multi = signer.next_multibase("signing").expect("should get next key");

    let mut witness_keyring1 = Keyring::new();
    witness_keyring1.set_verification_method("signing").expect("should set verification method");
    let mut witness_keyring2 = Keyring::new();
    witness_keyring2.set_verification_method("signing").expect("should set verification method");
    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![
            WitnessWeight {
                id: witness_keyring1
                    .verification_method()
                    .await
                    .expect("should get verifying key as did:key"),
                weight: 50,
            },
            WitnessWeight {
                id: witness_keyring2
                    .verification_method()
                    .await
                    .expect("should get verifying key as did:key"),
                weight: 40,
            },
        ],
    };

    let result = CreateBuilder::new()
        .document(&doc)
        .expect("should apply document")
        .update_keys(&update_keys)
        .expect("should apply update keys")
        .next_key(&next_multi)
        .portable(false)
        .witness(&witnesses)
        .expect("witness information should be applied")
        .ttl(60)
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    verify_proofs(&result.log[0]).await.expect("should verify proof");
}
