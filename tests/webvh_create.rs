//! Tests for the creation of a new `did:webvh` document and associated log
//! entry.

use credibil_did::{
    KeyPurpose, PublicKeyFormat, SignerExt, ServiceBuilder,
    core::Kind,
    document::{
        DocumentBuilder, MethodType, VerificationMethod, VerificationMethodBuilder, VmKeyId,
    },
    webvh::{CreateBuilder, Witness, WitnessWeight, default_did},
};
use credibil_infosec::jose::jws::Key;
use kms::Keyring;

use credibil_did::webvh::SCID_PLACEHOLDER;

// Test the happy path of creating a new `did:webvh` document and associated log
// entry. Should just work without errors.
#[tokio::test]
async fn create_success() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let mut signer = Keyring::new();
    let update_multi = signer.multibase("signing").expect("should get multibase key");
    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let id_multi = signer.multibase("id").expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(&PublicKeyFormat::PublicKeyMultibase {
        public_key_multibase: update_multi,
    })
    .key_id(&did, VmKeyId::Authorization(id_multi))
    .expect("should apply key ID")
    .method_type(&MethodType::Ed25519VerificationKey2020)
    .expect("should apply method type")
    .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());

    let service = ServiceBuilder::new(&format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER))
        .service_type(&"LinkedVerifiablePresentation")
        .endpoint_str(&"https://example.com/.well-known/whois")
        .build();

    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_multi = signer.next_multibase("signing").expect("should get next key");

    let witness_keyring1 = Keyring::new();
    let Key::KeyId(key_id1) =
        witness_keyring1.verification_method().await.expect("should get key id for witness1")
    else {
        panic!("should get key id");
    };
    let witness_keyring2 = Keyring::new();
    let Key::KeyId(key_id2) =
        witness_keyring2.verification_method().await.expect("should get key id for witness2")
    else {
        panic!("should get key id");
    };
    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![
            WitnessWeight {
                id: key_id1,
                weight: 50,
            },
            WitnessWeight {
                id: key_id2,
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

    let log_entry = serde_json::to_string(&result.log[0]).expect("should serialize log entry");
    println!("{log_entry}");
}
