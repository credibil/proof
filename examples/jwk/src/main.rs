#![allow(missing_docs)]

use did_core::{Registrar, Signer};
use did_jwk::Registrar as JwkRegistrar;
use keyring::{EphemeralKeyRing, EphemeralSigner, Secp256k1KeyPair};

#[tokio::main]
async fn main() {
    let keyring = EphemeralKeyRing::<Secp256k1KeyPair>::new();
    let registrar = JwkRegistrar::new(&keyring);
    let did_doc = registrar.create(None).await.expect("Failed to create DID");
    println!("Created DID: {}", did_doc.id);
    println!("DID Document: {:#?}", did_doc);

    let signer = EphemeralSigner::new(keyring);
    let msg = b"Hello, world!";
    let signature = signer.try_sign(msg, None).await.expect("Failed to sign message");
    let signed = std::str::from_utf8(&signature.0).unwrap();
    println!("Signed message: {signed}");
}
