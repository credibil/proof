use std::fmt::Display;

use argon2::Argon2;
use base64ct::{Base64, Encoding};
use chrono::{Duration, Utc};
use olpc_cjson::CanonicalFormatter;
use reqwest::{Response, Url};
use serde::{Deserialize, Serialize};

use vercre_didcore::{
    error::Err,
    hash::{hash_data, rand_hex},
    tracerr, DidDocument, KeyRing, OperationType, Patch, PatchAction, PatchDocument, Resolution,
    Result, Service, Signer, VerificationMethod,
};

use crate::registrar::check_delta;

/// Request provides a data structure for making DID operation requests.
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct Request {
    /// The type of DID operation requested.
    #[serde(rename = "type")]
    pub type_: OperationType,
    /// Suffix data appended to a DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suffix_data: Option<SuffixData>,
    /// Optional additional suffix
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_suffix: Option<String>,
    /// Reveal value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reveal_value: Option<String>,
    /// Delta information for updating a DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Delta>,
    /// Signed data that can be attached to a DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_data: Option<String>,
}

/// Data to be appended as a DID suffix
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SuffixData {
    pub delta_hash: String,
    pub recovery_commitment: String,
}

/// DID content is the set of public keys and services that are to be contained in a DID document.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DidContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_keys: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<Service>>,
}

/// DID change information.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Delta {
    pub update_commitment: String,
    pub patches: Vec<Patch>,
}

/// Long segment of a long DID
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LongSegment {
    pub suffix_data: SuffixData,
    pub delta: Delta,
}

/// ION Operation submitted to an ION node to update the public ledger
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IonOperation {
    #[serde(rename = "type")]
    pub type_: String,
    pub suffix_data: SuffixData,
    pub did_suffix: String,
    pub reveal_value: String,
    pub delta: Delta,
    pub signed_data: String,
}

// Proof of work
struct ProofOfWork {
    pub challenge_nonce: String,
    pub answer_nonce: String,
}

// Challenge Response
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeResponse {
    pub challenge_nonce: String,
    pub largest_allowed_hash: String,
    pub valid_duration_in_minutes: i32,
}

// Error Response. Allow dead code because we can't control the struct coming from the API but
// don't use all the fields.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorResponseDetail>,
}

// Error details in the error response. Allow dead code because we can't control the struct coming
// from the API but don't need all the fields.
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ErrorResponseDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

impl Display for ErrorResponseDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        serde_json::to_string(self).map_err(|_| std::fmt::Error)?.fmt(f)
    }
}

/// Registrar that implements the ION DID method.
pub struct IonRegistrar<K>
where
    K: KeyRing + Signer,
{
    challenge_url: String,
    solution_url: String,
    pub(crate) resolution_url: String,
    /// Reusable HTTP client
    http_client: reqwest::Client,
    /// Set to control whether the registrar will anchor the DID on the ledger.
    pub(crate) anchor: bool,
    /// Key ring for managing keys and signing.
    pub(crate) keyring: K,
    /// Bitcoin network to use for anchoring.
    network: Option<String>,
    /// Controller of the verification methods.
    pub(crate) controller: Option<String>,
}

/// Configuration and internal implementation for the ION registrar.
impl<K> IonRegistrar<K>
where
    K: KeyRing + Signer,
{
    /// Constructor.
    pub fn new(
        challenge_url: &str,
        solution_url: &str,
        resolution_url: &str,
        keyring: K,
        anchor: bool,
        network: Option<String>,
        controller: Option<String>,
    ) -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::ACCEPT,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("failed to create HTTP client.");
        Self {
            challenge_url: challenge_url.to_string(),
            solution_url: solution_url.to_string(),
            resolution_url: resolution_url.to_string(),
            http_client,
            keyring,
            anchor,
            network,
            controller,
        }
    }

    // Submit a request to the ION server.
    pub(crate) async fn submit(&self, req: &Request) -> Result<()> {
        // Generate proof of work
        let pow = self.proof_of_work(req).await?;

        // Submit request
        let url = Url::parse(&self.solution_url)?;
        let mut headers = reqwest::header::HeaderMap::new();

        headers.insert(
            "Challenge-Nonce",
            match reqwest::header::HeaderValue::from_str(&pow.challenge_nonce) {
                Ok(v) => v,
                Err(e) => tracerr!(
                    Err::InvalidFormat,
                    "failed to set challenge nonce header: {}",
                    e
                ),
            },
        );
        headers.insert(
            "Answer-Nonce",
            match reqwest::header::HeaderValue::from_str(&pow.answer_nonce) {
                Ok(v) => v,
                Err(e) => tracerr!(
                    Err::InvalidFormat,
                    "failed to set answer nonce header: {}",
                    e
                ),
            },
        );
        let res = match self.http_client.post(url).headers(headers).json(req).send().await {
            Ok(v) => v,
            Err(e) => tracerr!(Err::RequestError, "failed to submit request: {}", e),
        };

        unpack_response::<()>(res).await
    }

    // Generate a proof-of-work for the anchor request. Uses Argon2 to generate a nonce that
    // satisfies the challenge criteria. A hash of the anchor request is generated that is smaller
    // than or equal to the largest allowed hash.
    async fn proof_of_work(&self, req: &Request) -> Result<ProofOfWork> {
        let url = Url::parse(&self.challenge_url)?;
        let res = match self.http_client.get(url).send().await {
            Ok(v) => v,
            Err(e) => tracerr!(Err::RequestError, "failed to get challenge: {}", e),
        };
        let challenge = unpack_response::<ChallengeResponse>(res).await?;

        let data_bytes = serde_json::to_vec(req)?;
        let expires = Utc::now() + Duration::minutes(challenge.valid_duration_in_minutes as i64);
        let pow = loop {
            let nonce = rand_hex(500).as_bytes().to_vec();
            let mut pwd = nonce.clone();
            pwd.extend_from_slice(&data_bytes);
            let salt = challenge.challenge_nonce.as_bytes().to_vec();
            let mut key = [0u8; 32];
            match Argon2::default().hash_password_into(&pwd, &salt, &mut key) {
                Ok(_) => {}
                Err(e) => tracerr!(Err::SerializationError, "failed to hash password: {}", e),
            };

            // Check we're not out of time
            if Utc::now() > expires {
                tracerr!(
                    Err::Expired,
                    "challenge expired before proof of work nonce was found."
                );
            }

            // Exit loop if hash is not too large.
            let hash = String::from_utf8(key.to_vec())?;
            if hash.cmp(&challenge.largest_allowed_hash) != std::cmp::Ordering::Greater {
                let answer_nonce = String::from_utf8(nonce)?;
                break ProofOfWork {
                    challenge_nonce: challenge.challenge_nonce.clone(),
                    answer_nonce,
                };
            }
        };

        Ok(pow)
    }

    // Call the DID resolution endpoint and return the DID document if possible.
    pub(crate) async fn resolve_did(&self, did: &str) -> Result<Resolution> {
        let mut url = Url::parse(&self.resolution_url)?;
        if self.resolution_url.ends_with('/') {
            url.join(did)?;
        } else {
            url.set_path(did);
        }
        let res = match self.http_client.get(url).send().await {
            Ok(res) => res,
            Err(e) => tracerr!(
                Err::RequestError,
                "failed to call DID resolution endpoint: {}",
                e
            ),
        };

        unpack_response::<Resolution>(res).await
    }

    // Construct a create request for the given DID document. Used by other DID operations that
    // need to provide a new DID.
    pub(crate) fn create_request(
        &self,
        recovery_commitment: &str,
        update_commitment: &str,
        doc: &DidDocument,
    ) -> Result<Request> {
        let delta = Delta {
            patches: vec![Patch {
                action: PatchAction::Replace,
                document: Some(PatchDocument::from(doc)),
                ..Default::default()
            }],
            update_commitment: update_commitment.to_string(),
        };
        check_delta(&delta)?;
        let delta_hash = hash_data(&delta)?;

        Ok(Request {
            type_: OperationType::Create,
            suffix_data: Some(SuffixData {
                delta_hash,
                recovery_commitment: recovery_commitment.to_string(),
            }),
            delta: Some(delta),
            ..Default::default()
        })
    }

    /// Convert a DID request into a short-form DID.
    pub(crate) fn short_did(&self, req: &Request) -> Result<String> {
        let long = self.long_did(req)?;
        let (short, _) = long.rsplit_once(':').unwrap_or((&long, ""));
        Ok(short.to_string())
    }

    /// Convert a DID request into a long-form DID.
    pub(crate) fn long_did(&self, req: &Request) -> Result<String> {
        if req.type_ != OperationType::Create {
            tracerr!(
                Err::InvalidInput,
                "DID construction requires a create request"
            );
        }

        let suffix = hash_data(&req.suffix_data)?;
        let short_did = match &self.network {
            Some(network) if network == "mainnet" => format!("did:ion:{}", suffix),
            Some(network) => format!("did:ion:{}:{}", network, suffix),
            None => format!("did:ion:{}", suffix),
        };

        let long_segment = LongSegment {
            suffix_data: req.suffix_data.clone().unwrap_or_default(),
            delta: req.delta.clone().unwrap_or_default(),
        };
        let mut buf = Vec::new();
        let mut se_long_segment =
            serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
        long_segment.serialize(&mut se_long_segment)?;
        let enc_long_segment = Base64::encode_string(&buf);

        Ok(format!("{}:{}", short_did, &enc_long_segment))
    }
}

// Helper to unpack any response from the API.
async fn unpack_response<T>(res: Response) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    if res.status().is_success() {
        match res.json::<T>().await {
            Ok(obj) => Ok(obj),
            Err(e) => tracerr!(
                Err::DeserializationError,
                "failed to deserialize successful response: {}",
                e
            ),
        }
    } else {
        match res.json::<ErrorResponse>().await {
            Ok(e) => match e.error {
                Some(e) => tracerr!(Err::ApiError, "{}", e),
                None => tracerr!(Err::ApiError, "error response but no detail provided"),
            },
            Err(e) => tracerr!(
                Err::DeserializationError,
                "failed to deserialize error response: {}",
                e
            ),
        }
    }
}
