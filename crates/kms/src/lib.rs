//! Key management

use credibil_identity::{Key, Signature, did};
use credibil_jose::PublicKeyJwk;
use credibil_se::{Algorithm, Curve, Signer};
use test_kms::Keyring as BaseKeyring;

#[derive(Clone)]
pub struct Keyring {
    // Stored keys
    keys: BaseKeyring,
}

impl Keyring {
    // Create a new keyring and add a signing key.
    #[must_use]
    pub async fn new(owner: impl ToString) -> anyhow::Result<Self> {
        let mut keys = BaseKeyring::new(owner).await?;
        keys.add(&Curve::Ed25519, "signing").await?;
        Ok(Self { keys })
    }

    // Add a newly generated key to the keyring and corresponding next key.
    pub async fn add_key(&mut self, id: impl ToString) -> anyhow::Result<()> {
        self.keys.add(&Curve::Ed25519, id).await
    }

    // Replace a key in the keyring with a new one.
    pub async fn replace(&mut self, id: impl ToString) -> anyhow::Result<()> {
        self.keys.replace(id).await
    }

    // Rotate keys
    pub async fn rotate(&mut self) -> anyhow::Result<()> {
        self.keys.rotate_all().await
    }

    // Get a public JWK for a verifying key in the keyring.
    //
    // This will always return a result if it can. If the key is not found, one
    // will be generated with the specified ID.
    pub async fn jwk(&mut self, id: impl ToString + Clone) -> anyhow::Result<PublicKeyJwk> {
        let vk = match self.keys.verifying_key(&id.to_string()).await {
            Ok(vk) => vk,
            Err(_) => {
                self.add_key(id.clone()).await?;
                self.keys.verifying_key(&id.to_string()).await?
            }
        };
        Ok(PublicKeyJwk::from_bytes(&vk)?)
    }

    // Get a public multibase key for a key in the keyring.
    pub async fn multibase(&mut self, id: impl ToString + Clone) -> anyhow::Result<String> {
        let key = self.jwk(id).await?;
        Ok(key.to_multibase()?)
    }

    // Get a public JWK for a next key in the keyring.
    //
    // This will fail with an error if the key is not found or any encoding
    // errors occur.
    pub async fn next_jwk(&self, id: impl ToString + Clone) -> anyhow::Result<PublicKeyJwk> {
        let vk = self.keys.next_verifying_key(id).await?;
        Ok(PublicKeyJwk::from_bytes(&vk)?)
    }

    // Get a public multibase key for a next key in the keyring.
    //
    // Will fail with an error if the key is not found or any encoding errors
    // occur.
    pub async fn next_multibase(&self, id: impl ToString + Clone) -> anyhow::Result<String> {
        let key = self.next_jwk(id).await?;
        Ok(key.to_multibase()?)
    }
}

impl Signer for Keyring {
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.keys.sign("signing", msg).await
    }

    async fn verifying_key(&self) -> anyhow::Result<Vec<u8>> {
        self.keys.verifying_key("signing").await
    }

    async fn algorithm(&self) -> anyhow::Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl Signature for Keyring {
    async fn verification_method(&self) -> anyhow::Result<Key> {
        let vk = self.keys.verifying_key("signing").await?;
        let jwk = PublicKeyJwk::from_bytes(&vk)?;
        let vm = did::key::did_from_jwk(&jwk)?;
        Ok(Key::KeyId(vm))
    }
}
