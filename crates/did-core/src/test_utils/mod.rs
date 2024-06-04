//! Keyring and signer implementations that can be used for testing.

use crate::keys::keyring::KeyRing;
use crate::keys::signer::Signer;
use crate::keys::{Algorithm, Jwk, KeyOperation};
use crate::Result;

pub mod keyring;
pub mod signer;

/// Combined keyring and signer for testing.
#[derive(Default)]
pub struct TestKeyRingSigner {
    /// Test keyring.
    pub keyring: keyring::Test,
    /// Test signer.
    pub signer: signer::Test,
}

/// Construction implementation.
impl TestKeyRingSigner {
    /// Create a new keyring and signer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keyring: keyring::Test {},
            signer: signer::Test {},
        }
    }
}

#[allow(async_fn_in_trait)]
impl KeyRing for TestKeyRingSigner {
    async fn active_key(&self, op: &KeyOperation) -> Result<Jwk> {
        self.keyring.active_key(op).await
    }

    async fn next_key(&self, op: &KeyOperation) -> Result<Jwk> {
        self.keyring.next_key(op).await
    }
}

#[allow(async_fn_in_trait)]
impl Signer for TestKeyRingSigner {
    fn supported_algorithms(&self) -> Vec<Algorithm> {
        self.signer.supported_algorithms()
    }

    async fn try_sign_op(
        &self, msg: &[u8], op: &KeyOperation, alg: Option<Algorithm>,
    ) -> Result<(Vec<u8>, Option<String>)> {
        self.signer.try_sign_op(msg, op, alg).await
    }

    async fn verify(&self, data: &[u8], signature: &[u8], vm: Option<&str>) -> Result<()> {
        self.signer.verify(data, signature, vm).await
    }
}
