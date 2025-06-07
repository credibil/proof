//! Tests for the creation of a new `did:webvh` document and associated log
//! signer.

use credibil_ecc::{Curve, Keyring, NextKey, Signer};
use credibil_identity::did::webvh::{
    self, CreateBuilder, SCID_PLACEHOLDER, Witness, WitnessWeight,
};
use credibil_identity::did::{
    DocumentBuilder, KeyId, MethodType, ServiceBuilder, VerificationMethodBuilder,
};
use credibil_identity::{Signature, VerifyBy};
use credibil_jose::PublicKeyJwk;
use test_utils::Vault;

// Test the happy path of creating a new `did:webvh` document and associated log
// entry. Should just work without errors.
#[tokio::test]
async fn create_success() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let signer = Keyring::generate(&Vault, "wvhc", "signing", Curve::Ed25519)
        .await
        .expect("should generate");
    let verifying_key = signer.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let update_multi = jwk.to_multibase().expect("should get multibase");

    let id_entry =
        Keyring::generate(&Vault, "wvhc", "id", Curve::Ed25519).await.expect("should generate");
    let verifying_key = id_entry.verifying_key().await.expect("should get key");
    let jwk = PublicKeyJwk::from_bytes(&verifying_key).expect("should convert");
    let id_multi = jwk.to_multibase().expect("should get key");

    let did = webvh::default_did(domain_and_path).expect("should get default DID");

    let vm = VerificationMethodBuilder::new(update_multi.clone())
        .did(&did)
        .key_id(KeyId::Authorization(id_multi))
        .method_type(MethodType::Ed25519VerificationKey2020)
        .build()
        .expect("should build");
    let svc = ServiceBuilder::new(format!("did:webvh:{SCID_PLACEHOLDER}:example.com#whois"))
        .service_type("LinkedVerifiablePresentation")
        .endpoint("https://example.com/.well-known/whois")
        .build();
    let doc = DocumentBuilder::new(did)
        .verification_method(vm)
        .add_service(svc)
        .build()
        .expect("should build document");

    let json = serde_json::to_string_pretty(&doc).expect("should serialize");
    print!("{json}");

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

    let log_entry = serde_json::to_string(&result.log[0]).expect("should serialize log signer");
    println!("{log_entry}");
}
