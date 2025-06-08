//! Tests to verify log entries.

use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_identity::did::webvh::{
    self, CreateBuilder, SCID_PLACEHOLDER, Witness, WitnessWeight,
};
use credibil_identity::did::{DocumentBuilder, KeyId, ServiceBuilder, VerificationMethodBuilder};
use credibil_identity::{Signature, VerifyBy};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Create a minimal document and then verify the proof. Should verify without
// errors.
#[tokio::test]
async fn simple_proof() {
    const DID_URL: &str = "https://credibil.io/issuers/example";

    let signer =
        Keyring::generate(&Vault, "utd", "signing", Curve::Ed25519).await.expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wvhd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let did = webvh::default_did(DID_URL).expect("should create DID");
    let vm =
        VerificationMethodBuilder::new(update_multi.clone()).key_id(KeyId::Authorization(id_multi));

    let doc =
        DocumentBuilder::new(did).verification_method(vm).build().expect("should build document");

    let result = CreateBuilder::new()
        .document(doc)
        .expect("should apply document")
        .update_keys(vec![update_multi])
        .expect("should apply update keys")
        .signer(&signer)
        .build()
        .await
        .expect("should build document");

    println!("result log[0]: {:?}", result.log[0]);
    webvh::verify_proofs(&result.log[0]).await.expect("should verify proof");
}

// Create a document with more options and then verify the proof. Should verify
// without errors.
#[tokio::test]
async fn complex_proof() {
    const DID_URL: &str = "https://credibil.io/issuers/example";

    let signer = Keyring::generate(&Vault, "wvhd", "signing", Curve::Ed25519)
        .await
        .expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wvhd", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let did = webvh::default_did(DID_URL).expect("should create DID");

    let vm =
        VerificationMethodBuilder::new(update_multi.clone()).key_id(KeyId::Authorization(id_multi));
    let service = ServiceBuilder::new(format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois")
        .build();
    let doc = DocumentBuilder::new(did)
        .verification_method(vm)
        .add_service(service)
        .build()
        .expect("should build document");

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

    let result = CreateBuilder::new()
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

    webvh::verify_proofs(&result.log[0]).await.expect("should verify proof");
}
