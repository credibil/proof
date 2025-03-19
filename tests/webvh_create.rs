//! Tests for the creation of a new `did:webvh` document and associated
//! log entry.

use credibil_did::{
    KeyPurpose,
    core::{Kind, OneMany},
    document::{MethodType, Service, VerificationMethod},
    operation::document::{VerificationMethodBuilder, VmKeyId},
    webvh::{
        Witness, WitnessWeight,
        create::{
            CreateBuilder, WithUpdateKeys, WithUrl, WithoutUpdateKeys, WithoutUrl,
            WithoutVerificationMethods,
        },
    },
};
use multibase::Base;
use serde_json::Value;
use sha2::Digest;
use test_signer::new_keyring;

use credibil_did::webvh::SCID_PLACEHOLDER;

// Test the happy path of creating a new, minimal `did:webvh` document and
// associated log entry.
#[tokio::test]
async fn create_success() {
    let domain_and_path = "https://credibil.io/issuers/example";

    let update_multi =
        new_keyring().verifying_key_multibase().await.expect("should get multibase key");

    let signer = new_keyring();
    let auth_jwk = signer.verifying_key_jwk().await.expect("should get JWK key");

    let doc_builder: CreateBuilder<WithUrl, WithUpdateKeys, WithoutVerificationMethods> =
        CreateBuilder::<WithoutUrl, WithoutUpdateKeys, WithoutVerificationMethods>::new()
            .url(domain_and_path)
            .expect("should apply URL")
            .update_keys(vec![update_multi])
            .expect("should apply update keys");

    let vm_jwk = new_keyring().verifying_key_jwk().await.expect("should get JWK key");
    let vm = VerificationMethodBuilder::new(&vm_jwk)
        .key_id(doc_builder.did(), VmKeyId::Authorization(auth_jwk))
        .expect("should apply key ID")
        .method_type(&MethodType::Ed25519VerificationKey2020)
        .expect("should apply method type")
        .build();

    let vm_kind = Kind::<VerificationMethod>::Object(vm.clone());
    let doc_builder = doc_builder
        .verification_method(&vm_kind, &KeyPurpose::VerificationMethod)
        .expect("should apply verification method")
        .portable(false);

    let next_multi =
        new_keyring().verifying_key_multibase().await.expect("should get multibase key");
    let next_digest = sha2::Sha256::digest(next_multi.as_bytes());
    let next_hash = multibase::encode(Base::Base58Btc, next_digest.as_slice());

    let doc_builder = doc_builder.next_key_hash(next_hash);

    let witnesses = Witness {
        threshold: 60,
        witnesses: vec![
            WitnessWeight {
                id: new_keyring().did().to_string(),
                weight: 50,
            },
            WitnessWeight {
                id: new_keyring().did().to_string(),
                weight: 40,
            },
        ],
    };
    let doc_builder =
        doc_builder.witness(&witnesses).expect("witness information should be applied").ttl(60);

    let service = Service {
        id: format!("did:webvh:{}:example.com#whois", SCID_PLACEHOLDER),
        type_: "LinkedVerifiablePresentation".to_string(),
        service_endpoint: OneMany::<Kind<Value>>::One(Kind::String(
            "https://example.com/.well-known/whois".to_string(),
        )),
    };

    let doc_builder = doc_builder.service(&service);
    
    let result = doc_builder.build(&signer).await.expect("should build document");
    let log_entry = serde_json::to_string(&result.log[0]).expect("should serialize log entry");
    println!("{log_entry}");
}
