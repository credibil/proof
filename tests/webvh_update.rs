//! Tests for the update of an existing `did:webvh` document and associated log
//! entry.

use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_identity::core::Kind;
use credibil_identity::did::webvh::{
    CreateBuilder, SCID_PLACEHOLDER, UpdateBuilder, Witness, WitnessWeight, default_did,
};
use credibil_identity::did::{
    DocumentBuilder, KeyFormat, KeyPurpose, MethodType, ServiceBuilder, VerificationMethod,
    VerificationMethodBuilder, VmKeyId,
};
use credibil_identity::{Signature, VerifyBy};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Test the happy path of creating then updating a `did:webvh` document and log
// entries. Should just work without errors.
#[tokio::test]
async fn update_success() {
    // --- Create --------------------------------------------------------------

    let domain_and_path = "https://credibil.io/issuers/example";

    let signer =
        Keyring::generate(&Vault, "wu", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let update_keys = vec![update_multi.clone()];
    let update_keys: Vec<&str> = update_keys.iter().map(|s| s.as_str()).collect();

    let id_entry =
        Keyring::generate(&Vault, "wu", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(&KeyFormat::Multibase {
        public_key_multibase: update_multi,
    })
    .key_id(&did, VmKeyId::Authorization(id_multi))
    .expect("should apply key ID")
    .method_type(&MethodType::Ed25519VerificationKey2020)
    .expect("should apply method type")
    .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());

    let service = ServiceBuilder::new(&format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER))
        .service_type("LinkedVerifiablePresentation")
        .endpoint_str("https://example.com/.well-known/whois")
        .build();

    let doc = DocumentBuilder::new(&did)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_service(&service)
        .build();

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let next_multi = jwk.to_multibase().expect("should get multibase");

    let witness_1 =
        Keyring::generate(&Vault, "w1", "signing", Curve::Ed25519).await.expect("should generate");
    let VerifyBy::KeyId(key_id1) =
        witness_1.verification_method().await.expect("should get key id")
    else {
        panic!("should get key id");
    };
    let witness_2 =
        Keyring::generate(&Vault, "w2", "signing", Curve::Ed25519).await.expect("should generate");
    let VerifyBy::KeyId(key_id2) =
        witness_2.verification_method().await.expect("should get key id for witness2")
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

    let create_result = CreateBuilder::new()
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

    // --- Update --------------------------------------------------------------

    let doc = create_result.document.clone();

    // Rotate the signing key.
    let signer = Keyring::rotate(&Vault, signer).await.expect("should rotate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let new_update_multi = jwk.to_multibase().expect("should get multibase");

    let new_update_keys = vec![new_update_multi.clone()];
    let new_update_keys: Vec<&str> = new_update_keys.iter().map(|s| s.as_str()).collect();

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let new_next_multi = jwk.to_multibase().expect("should get multibase");

    let new_next_keys = vec![new_next_multi.clone()];
    let new_next_keys: Vec<&str> = new_next_keys.iter().map(|s| s.as_str()).collect();

    let id_entry =
        Keyring::generate(&Vault, "utd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethodBuilder::new(&KeyFormat::Multibase {
        public_key_multibase: new_update_multi,
    })
    .key_id(&did, VmKeyId::Authorization(id_multi))
    .expect("should apply key ID")
    .method_type(&MethodType::Ed25519VerificationKey2020)
    .expect("should apply method type")
    .build();
    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());

    // Add a reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let vm = vm_list.first().expect("should get first verification method");
    let auth_vm = Kind::<VerificationMethod>::String(vm.id.clone());

    // Construct a new document from the existing one.
    let doc = DocumentBuilder::from(&doc)
        .add_verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .add_verification_method(&auth_vm, &KeyPurpose::Authentication)
        .expect("should add verification method")
        .build();

    // Create an update log entry and skip witness verification.
    let result = UpdateBuilder::from(create_result.log.as_slice(), None)
        .await
        .expect("should create builder")
        .document(&doc)
        .expect("should apply document")
        .rotate_keys(&new_update_keys, &new_next_keys)
        .expect("should rotate keys on builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    let logs = serde_json::to_string(&result.log).expect("should serialize log entries");
    println!("{logs}");
}
