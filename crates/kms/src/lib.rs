//! Key management

use std::sync::LazyLock;

use anyhow::Result;
use credibil_ecc::{Algorithm, Curve, Entry, Keyring, Signer, Vault};
use credibil_identity::{Signature, VerifyBy, did};
use credibil_jose::PublicKeyJwk;
use dashmap::DashMap;

static STORE: LazyLock<DashMap<String, Vec<u8>>> = LazyLock::new(DashMap::new);

#[derive(Clone)]
pub struct KeyringExt {
    owner: String,
}

impl KeyringExt {
    // Create a new keyring and add a signing key.
    #[must_use]
    pub async fn new(owner: &str) -> Result<Self> {
        Keyring::generate(&Store, owner, "signing", Curve::Ed25519).await?;
        Ok(Self {
            owner: owner.to_string(),
        })
    }

    // Add a newly generated key to the keyring and corresponding next key.
    pub async fn add_key(&mut self, key_id: &str) -> Result<()> {
        Keyring::generate(&Store, &self.owner, key_id, Curve::Ed25519).await.map(|_| ())
    }

    // Replace a key in the keyring with a new one.
    pub async fn replace(&mut self, key_id: &str) -> Result<()> {
        Keyring::rotate(&Store, &self.owner, key_id).await.map(|_| ())
    }

    // Rotate keys
    pub async fn rotate(&mut self) -> Result<()> {
        let entries = Store.get_all(&self.owner, "VAULT").await?;
        for (_, bytes) in entries {
            let e = Entry::from_bytes(&bytes)?;
            Keyring::rotate(&Store, &self.owner, e.key_id()).await?;
        }
        Ok(())
    }

    // Get a public JWK for a verifying key in the keyring.
    //
    // This will always return a result if it can. If the key is not found, one
    // will be generated with the specified ID.
    pub async fn jwk(&mut self, key_id: &str) -> Result<PublicKeyJwk> {
        let entry = match Keyring::entry(&Store, &self.owner, key_id).await {
            Ok(entry) => entry,
            Err(_) => {
                self.add_key(key_id).await?;
                Keyring::entry(&Store, &self.owner, key_id).await?
            }
        };
        let verifying_key = entry.verifying_key().await?;
        PublicKeyJwk::from_bytes(&verifying_key)
    }

    // Get a public multibase key for a key in the keyring.
    pub async fn multibase(&mut self, key_id: &str) -> Result<String> {
        self.jwk(key_id).await?.to_multibase()
    }

    // Get a public JWK for a next key in the keyring.
    //
    // This will fail with an error if the key is not found or any encoding
    // errors occur.
    pub async fn next_jwk(&self, key_id: &str) -> Result<PublicKeyJwk> {
        let entry = Keyring::entry(&Store, &self.owner, key_id).await?;
        let verifying_key = entry.next_key().await?;
        PublicKeyJwk::from_bytes(verifying_key.as_slice())
    }

    // Get a public multibase key for a next key in the keyring.
    //
    // Will fail with an error if the key is not found or any encoding errors
    // occur.
    pub async fn next_multibase(&self, key_id: &str) -> Result<String> {
        let key = self.next_jwk(key_id).await?;
        Ok(key.to_multibase()?)
    }
}

impl Signer for KeyringExt {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let entry = Keyring::entry(&Store, &self.owner, "signing").await?;
        entry.try_sign(msg).await
    }

    async fn verifying_key(&self) -> Result<Vec<u8>> {
        let entry = Keyring::entry(&Store, &self.owner, "signing").await?;
        entry.verifying_key().await
    }

    async fn algorithm(&self) -> Result<Algorithm> {
        Ok(Algorithm::EdDSA)
    }
}

impl Signature for KeyringExt {
    async fn verification_method(&self) -> Result<VerifyBy> {
        let entry = Keyring::entry(&Store, &self.owner, "signing").await?;
        let vk = entry.verifying_key().await?;
        let jwk = PublicKeyJwk::from_bytes(&vk)?;
        let vm = did::key::did_from_jwk(&jwk)?;
        Ok(VerifyBy::KeyId(vm))
    }
}

#[derive(Clone, Debug)]
struct Store;

impl Vault for Store {
    async fn put(&self, owner: &str, partition: &str, key: &str, data: &[u8]) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.insert(key, data.to_vec());
        Ok(())
    }

    async fn get(&self, owner: &str, partition: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let key = format!("{owner}-{partition}-{key}");
        let Some(bytes) = STORE.get(&key) else {
            return Ok(None);
        };
        Ok(Some(bytes.to_vec()))
    }

    async fn delete(&self, owner: &str, partition: &str, key: &str) -> Result<()> {
        let key = format!("{owner}-{partition}-{key}");
        STORE.remove(&key);
        Ok(())
    }

    async fn get_all(&self, owner: &str, partition: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let all = STORE
            .iter()
            .filter(move |r| r.key().starts_with(&format!("{owner}-{partition}-")))
            .map(|r| (r.key().to_string(), r.value().clone()))
            .collect::<Vec<_>>();
        Ok(all)
    }
}
