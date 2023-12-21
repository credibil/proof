use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{serde::ts_seconds_option, DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// Key types supported by the Credibil framework that are also supported by Azure Key Vault.
#[derive(Debug, Deserialize, Serialize)]
pub enum JwkType {
    /// Elliptic Curve
    EC,
}

/// Key operations supported by the Credibil framework that are also supported by Azure Key Vault.
#[derive(Debug, Serialize)]
pub enum JwkOperation {
    /// Sign
    #[serde(rename = "sign")]
    Sign,
    /// Verify
    #[serde(rename = "verify")]
    Verify,
}

/// Elliptic curve names supported by the Credibil framework that are also supported by Azure Key
/// Vault.
#[derive(Debug, Serialize)]
pub enum JwkCurve {
    /// secp256k1
    #[serde(rename = "P-256K")]
    Secp256k1,
}

/// Key bundle is the main data type transferred to and from the Azure Key Vault API.
#[derive(Debug, Deserialize)]
pub struct KeyBundle {
    pub attributes: KeyAttributes,
    pub key: JsonWebKey,
    pub managed: Option<bool>,
    pub tags: Option<Map<String, Value>>,
}

/// A deleted key bundle consists of a key bundle and its deletion information.
#[derive(Debug, Deserialize)]
pub struct Deleted {
    #[serde(flatten)]
    pub key_bundle: KeyBundle,
    #[serde(rename = "recoveryId")]
    pub recovery_id: Option<String>,
    #[serde(
        rename = "deletedDate",
        with = "ts_seconds_option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub date: Option<DateTime<Utc>>,
    #[serde(
        rename = "scheduledPurgeDate",
        with = "ts_seconds_option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub scheduled_purge_date: Option<DateTime<Utc>>,
}

/// The attributes of a key managed by the key vault service.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAttributes {
    /// Creation time in UTC.
    #[serde(
        with = "ts_seconds_option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub created: Option<DateTime<Utc>>,
    /// Determines whether the object is enabled.
    pub enabled: Option<bool>,
    /// Expiry date in UTC.
    #[serde(
        rename = "exp",
        with = "ts_seconds_option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub expires: Option<DateTime<Utc>>,
    /// Not before date in UTC.
    #[serde(
        rename = "nbf",
        with = "ts_seconds_option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub not_before: Option<DateTime<Utc>>,
    /// softDelete data retention days. Value should be >=7 and <=90 when softDelete enabled, otherwise 0.
    pub recoverable_days: Option<u8>,
    /// Reflects the deletion recovery level currently in effect for keys in the current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged user; otherwise, only the system can purge the key, at the end of the retention interval.
    pub recovery_level: Option<String>,
    /// Last updated time in UTC.
    #[serde(
        with = "ts_seconds_option",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub updated: Option<DateTime<Utc>>,
}

/// See <http://tools.ietf.org/html/draft-ietf-jose-json-web-key-18>
#[derive(Debug, Deserialize, Serialize)]
pub struct JsonWebKey {
    /// Elliptic curve name. For valid values, see [`JwkCurve`].
    #[serde(rename = "crv")]
    pub curve_name: Option<String>,
    /// RSA private exponent, or the D component of an EC private key.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub d: Option<Vec<u8>>,
    /// RSA private key parameter.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub dp: Option<Vec<u8>>,
    /// RSA private key parameter.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub dq: Option<Vec<u8>>,
    /// RSA public exponent.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub e: Option<Vec<u8>>,
    /// Symmetric key.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub k: Option<Vec<u8>>,
    /// HSM Token, used with 'Bring Your Own Key'.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    #[serde(rename = "key_hsm")]
    pub t: Option<Vec<u8>>,
    /// Supported key operations.
    pub key_ops: Option<Vec<String>>,
    /// Key identifier.
    #[serde(rename = "kid")]
    pub id: Option<String>,
    /// JsonWebKey Key Type (kty), as defined in <https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40>.
    #[serde(rename = "kty")]
    pub key_type: String,
    /// RSA modulus.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub n: Option<Vec<u8>>,
    /// RSA secret prime.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub p: Option<Vec<u8>>,
    /// RSA secret prime, with p < q.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub q: Option<Vec<u8>>,
    /// RSA private key parameter.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub qi: Option<Vec<u8>>,
    /// X component of an EC public key.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub x: Option<Vec<u8>>,
    /// Y component of an EC public key.
    #[serde(
        serialize_with = "ser_base64_opt",
        deserialize_with = "deser_base64_opt"
    )]
    #[serde(default)]
    pub y: Option<Vec<u8>>,
}

/// List of versions for a key.
#[derive(Debug, Deserialize)]
pub struct KeyList {
    pub value: Vec<KeyListItem>,
    #[serde(rename = "nextLink")]
    pub next_link: Option<String>,
}

/// List item for a list of versions for a key.
#[derive(Debug, Deserialize)]
pub struct KeyListItem {
    pub kid: String,
    pub attributes: KeyAttributes,
    pub managed: Option<bool>,
    pub tags: Option<Map<String, Value>>,
}

#[allow(dead_code)]
fn ser_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let base_64 = Base64UrlUnpadded::encode_string(bytes);
    serializer.serialize_str(&base_64)
}

fn ser_base64_opt<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(bytes) = bytes {
        let base_64 = Base64UrlUnpadded::encode_string(bytes);
        serializer.serialize_str(&base_64)
    } else {
        serializer.serialize_none()
    }
}

#[allow(dead_code)]
fn deser_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    let res = Base64UrlUnpadded::decode_vec(s.as_str()).map_err(serde::de::Error::custom)?;
    Ok(res)
}

fn deser_base64_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    let res = match s {
        Some(s) => {
            Some(Base64UrlUnpadded::decode_vec(s.as_str()).map_err(serde::de::Error::custom)?)
        }
        None => None,
    };
    Ok(res)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn deserialize_key_bundle() {
        let serialized = json!({
            "key": {
                "kid": "https://kv-credibil-vc.vault.azure.net/keys/vc-sign-unlikely-test/4399d1c799db41f6b2cf9920c7d72f14",
                "kty": "EC",
                "key_ops": [
                    "sign",
                    "verify"
                ],
                "crv": "P-256K",
                "x": "jGxSWtojklh8gDrjKaYokMW8b0ZG4gFN4hl_oiKjvfQ",
                "y": "zHbSkGNdH0RLQj6IqLYddqKryRKkPXEGaqlX6Tq2IqI"
            },
            "attributes": {
                "enabled": false,
                "created": 1697601096,
                "updated": 1697601096,
                "recoveryLevel": "Recoverable+Purgeable",
                "recoverableDays": 90
            }
        });
        let deserialized: KeyBundle =
            serde_json::from_value(serialized).expect("failed to deserialize key bundle");
        assert_eq!(deserialized.attributes.enabled, Some(false));
    }

    #[test]
    fn deserialize_deleted_key_bundle() {
        let serialized = json!({
            "recoveryId": "https://kv-credibil-vc.vault.azure.net/deletedkeys/vc-sign-unlikely-test",
            "deletedDate": 1697669021,
            "scheduledPurgeDate": 1705445021,
            "key": {
                "kid": "https://kv-credibil-vc.vault.azure.net/keys/vc-sign-unlikely-test/4399d1c799db41f6b2cf9920c7d72f14",
                "kty": "EC",
                "key_ops": [
                    "sign",
                    "verify"
                ],
                "crv": "P-256K",
                "x": "jGxSWtojklh8gDrjKaYokMW8b0ZG4gFN4hl_oiKjvfQ",
                "y": "zHbSkGNdH0RLQj6IqLYddqKryRKkPXEGaqlX6Tq2IqI"
            },
            "attributes": {
                "enabled": false,
                "created": 1697601096,
                "updated": 1697601096,
                "recoveryLevel": "Recoverable+Purgeable",
                "recoverableDays": 90
            }
        });
        let deserialized: Deleted =
            serde_json::from_value(serialized).expect("failed to deserialize deleted key bundle");
        assert!(deserialized.date.is_some());
        assert_eq!(deserialized.key_bundle.key.key_type, "EC");
    }
}
