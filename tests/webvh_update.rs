//! Tests for the update of an existing `did:webvh` document and associated log
//! entry.

use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_identity::did::webvh::{
    CreateBuilder, SCID_PLACEHOLDER, UpdateBuilder, Witness, WitnessWeight, default_did,
};
use credibil_identity::did::{
    DocumentBuilder, MethodType, ServiceBuilder, VerificationMethodBuilder, VmKeyId,
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

    let id_entry =
        Keyring::generate(&Vault, "wu", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let did = default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(update_multi.clone())
        .key_id(&did, VmKeyId::Authorization(id_multi))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();

    let service = ServiceBuilder::new(format!("did:webvh:{SCID_PLACEHOLDER}:example.com#whois"))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois".to_string())
        .build();

    let doc =
        DocumentBuilder::new(&did).verification_method(vm.clone()).add_service(service).build();

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
        .document(doc)
        .expect("should apply document")
        .update_keys(vec![update_multi])
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

    let next_key = signer.next_key().await.expect("should get next key");
    let jwk = PublicKeyJwk::from_bytes(&next_key).expect("should convert");
    let new_next_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "utd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let vm = VerificationMethodBuilder::new(new_update_multi.clone())
        .key_id(did, VmKeyId::Authorization(id_multi))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();

    // Add a reference-based verification method as a for-instance.
    let vm_list = doc.verification_method.clone().expect("should get verification methods");
    let auth_vm = vm_list.first().expect("should get first verification method");

    // Construct a new document from the existing one.
    let doc = DocumentBuilder::from(doc)
        .verification_method(vm.clone())
        .authentication(auth_vm.id.clone())
        .build();

    // Create an update log entry and skip witness verification.
    let result = UpdateBuilder::from(create_result.log.as_slice(), None)
        .await
        .expect("should create builder")
        .document(&doc)
        .expect("should apply document")
        .rotate_keys(vec![new_update_multi], &vec![new_next_multi])
        .expect("should rotate keys on builder")
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    let logs = serde_json::to_string(&result.log).expect("should serialize log entries");
    println!("{logs}");
}
