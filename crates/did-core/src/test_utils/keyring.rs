//! Keyring implementation for use in tests.

use crate::keys::keyring::KeyRing;
use crate::keys::{Jwk, KeyOperation};
use crate::Result;

/// Test keyring implementation. Uses a few hardcoded keys.
#[derive(Default)]
pub struct Test {}

#[allow(async_fn_in_trait)]
impl KeyRing for Test {
    async fn active_key(&self, op: &KeyOperation) -> Result<Jwk> {
        match op {
            KeyOperation::Update =>
            // jwkEs256k2Public
            {
                Ok(Jwk {
                    kty: "EC".to_string(),
                    crv: Some("secp256k1".to_string()),
                    x: Some("QJZEHYfuTyjhIywIPKW_VLj9KQHUjLYCZJXJaNo2JQ4".to_string()),
                    y: Some("p_j1EtkaHqnuporRvK1Y0iyQ3orNmj5EzFVErdkGOFg".to_string()),
                    ..Default::default()
                })
            }
            _ =>
            // jwkEs256k1Public
            {
                Ok(Jwk {
                    kty: "EC".to_string(),
                    crv: Some("secp256k1".to_string()),
                    x: Some("XFl4fd9n4qp2Gcc2_oqqUsI3uT63o3Jt0f54DiNOijw".to_string()),
                    y: Some("IH_q19UKDu_jkIwtehWU7NiaXk7CaGoD-XRcuuqcgQ0".to_string()),
                    ..Default::default()
                })
            }
        }
    }

    async fn next_key(&self, op: &KeyOperation) -> Result<Jwk> {
        match op {
            KeyOperation::Update =>
            // jwkEs256k3Public
            {
                Ok(Jwk {
                    kty: "EC".to_string(),
                    crv: Some("secp256k1".to_string()),
                    x: Some("BoCXWUX2swC6ERZXyKcfhAdv1Qjvb6Yf4jJqp2cfRgQ".to_string()),
                    y: Some("5KZPs8N0i1bIa_XhbB8BzR8pCi4yUv1AulLfrq4lJnU".to_string()),
                    ..Default::default()
                })
            }
            _ =>
            // jwkEs256k2Public
            {
                Ok(Jwk {
                    kty: "EC".to_string(),
                    crv: Some("secp256k1".to_string()),
                    x: Some("QJZEHYfuTyjhIywIPKW_VLj9KQHUjLYCZJXJaNo2JQ4".to_string()),
                    y: Some("p_j1EtkaHqnuporRvK1Y0iyQ3orNmj5EzFVErdkGOFg".to_string()),
                    ..Default::default()
                })
            }
        }
    }

    async fn commit(&self) -> Result<()> {
        Ok(())
    }
}
