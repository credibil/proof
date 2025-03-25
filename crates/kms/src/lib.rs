//! # Key management and basic provider implementations for testing.

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_did::{CreateOptions, DidOperator, DidResolver, Document, KeyPurpose, key::DidKey};
use credibil_infosec::{
    Algorithm, Curve, KeyType, PublicKey, PublicKeyJwk, Receiver, SecretKey, SharedSecret, Signer,
};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, Signer as _, SigningKey, VerifyingKey};
use multibase::Base;
use rand::rngs::OsRng;
use sha2::Digest;

pub const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
// const X25519_CODEC: [u8; 2] = [0xec, 0x01];

#[derive(Default, Clone, Debug)]
pub struct Keyring {
    did: String,
    did_key: String,
    secret_key: String,
    verifying_key: VerifyingKey,
    vm_secret_key: String,
}

pub fn new_keyring() -> Keyring {
    let signing_key = SigningKey::generate(&mut OsRng);

    // verifying key (Ed25519)
    let verifying_key = signing_key.verifying_key();
    let mut multi_bytes = ED25519_CODEC.to_vec();
    multi_bytes.extend_from_slice(&verifying_key.to_bytes());
    let verifying_multi = multibase::encode(Base::Base58Btc, &multi_bytes);

    // authorization key (Ed25519) - used for generating a verification method.
    let vm_signing_key = SigningKey::generate(&mut OsRng);

    Keyring {
        did: format!("did:key:{verifying_multi}"),
        did_key: format!("did:key:{verifying_multi}#{verifying_multi}"),
        secret_key: Base64UrlUnpadded::encode_string(signing_key.as_bytes()),
        verifying_key,
        vm_secret_key: Base64UrlUnpadded::encode_string(vm_signing_key.as_bytes()),
    }
}

impl Keyring {
    pub fn did(&self) -> String {
        self.did.clone()
    }

    pub fn did_key(&self) -> String {
        self.did_key.clone()
    }

    pub async fn verifying_key_jwk(&self) -> anyhow::Result<PublicKeyJwk> {
        let key = self.verifying_key().await?;
        PublicKeyJwk::from_bytes(&key)
    }

    pub async fn verifying_key_multibase(&self) -> anyhow::Result<String> {
        let key = self.verifying_key_jwk().await?;
        key.to_multibase()
    }

    // Generate an authorization key for use in creating a verification method
    // identifier. 
    pub fn auth_key_jwk(&self) -> anyhow::Result<PublicKeyJwk> {
        let auth_key = SigningKey::generate(&mut OsRng);
        let key = auth_key.verifying_key().as_bytes().to_vec();
        PublicKeyJwk::from_bytes(&key)
    }

    // Get a predicable public key to use in a verificatio method.
    pub fn vm_key_jwk(&self) -> anyhow::Result<PublicKeyJwk> {
        let key = Base64UrlUnpadded::decode_vec(&self.vm_secret_key)?;
        PublicKeyJwk::from_bytes(&key)
    }
}

impl Signer for Keyring {
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let secret_key: ed25519_dalek::SecretKey =
            decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }

    async fn verifying_key(&self) -> anyhow::Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let secret_key: ed25519_dalek::SecretKey =
            decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.verifying_key().as_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    async fn verification_method(&self) -> anyhow::Result<String> {
        let verify_key = self.did.strip_prefix("did:key:").unwrap_or_default();
        Ok(format!("{}#{}", self.did, verify_key))
    }
}

impl Receiver for Keyring {
    fn key_id(&self) -> String {
        self.did.clone()
    }

    async fn shared_secret(&self, sender_public: PublicKey) -> anyhow::Result<SharedSecret> {
        // EdDSA signing key
        let decoded = Base64UrlUnpadded::decode_vec(&self.secret_key)?;
        let bytes: [u8; PUBLIC_KEY_LENGTH] =
            decoded.try_into().map_err(|_| anyhow!("invalid secret key"))?;
        let signing_key = SigningKey::from_bytes(&bytes);

        // *** derive X25519 secret for Diffie-Hellman from Ed25519 secret ***
        let hash = sha2::Sha512::digest(signing_key.as_bytes());
        let mut hashed = [0u8; PUBLIC_KEY_LENGTH];
        hashed.copy_from_slice(&hash[..PUBLIC_KEY_LENGTH]);
        let secret_key = x25519_dalek::StaticSecret::from(hashed);

        let secret_key = SecretKey::from(secret_key.to_bytes());
        secret_key.shared_secret(sender_public)
    }
}

// TODO: Expand to support did:web and did:webvh methods
impl DidResolver for Keyring {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        if !url.starts_with("did:key:") {
            return Err(anyhow!("unsupported DID method"));
        }
        DidKey::create(self, CreateOptions::default()).map_err(|e| anyhow!(e))
    }
}

// TODO: Expand to support did:web and did:webvh methods
impl DidOperator for Keyring {
    fn verification(&self, purpose: KeyPurpose) -> Option<PublicKeyJwk> {
        match purpose {
            KeyPurpose::VerificationMethod => Some(PublicKeyJwk {
                kty: KeyType::Okp,
                crv: Curve::Ed25519,
                x: Base64UrlUnpadded::encode_string(self.verifying_key.as_bytes()),
                ..PublicKeyJwk::default()
            }),
            _ => panic!("unsupported purpose"),
        }
    }
}
