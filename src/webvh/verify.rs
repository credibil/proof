//! Verification and validation functions for `did:webvh` log entries and
//! information referenced in the log parameters.

use crate::{
    document::VerificationMethod,
    operation::resolve::{dereference, Resource},
    DidResolver,
};

use super::{DidLogEntry, Witness};

use anyhow::bail;
use sha2::Digest;

/// Verify the proofs in a log entry.
///
/// Requires a DID resolver to fetch a DID document and find the verification
/// method referenced in the proof.
///
/// # Errors
/// Will return an error if any of the proofs on the log entry are invalid.
pub async fn verify_proofs(
    log_entry: &DidLogEntry, resolver: &impl DidResolver,
) -> anyhow::Result<()> {
    if log_entry.proof.is_empty() {
        bail!("log entry has no proof");
    }

    let mut unsigned_entry = log_entry.clone();
    unsigned_entry.proof = Vec::new();
    let unsigned_data = serde_json_canonicalizer::to_string(&unsigned_entry)?;
    let unsigned_hash = sha2::Sha256::digest(unsigned_data.as_bytes());

    for proof in &log_entry.proof {
        let Some(proof_value) = &proof.proof_value else {
            bail!("proof value is missing");
        };
        if proof.type_ != "DataIntegrityProof" {
            bail!("unsupported proof type {} - must be 'DataIntegrityProof'", proof.type_);
        }
        if proof.proof_purpose != "authentication" && proof.proof_purpose != "assertionMethod" {
            bail!(
                "unsupported proof purpose {} - must be 'authentication' or 'assertionMethod",
                proof.proof_purpose
            );
        }
        if proof.cryptosuite != Some("eddsa-jcs-2022".to_string()) {
            bail!(
                "unsupported cryptosuite {} - must be 'eddsa-jcs-2022'",
                proof.cryptosuite.as_deref().unwrap_or("")
            );
        }
        let verification_method = authorized_key(
            &proof.verification_method,
            log_entry,
            resolver,
        )
        .await?;

        // Verify the signature.
        let mut config = proof.clone();
        config.proof_value = None;
        let config_data = serde_json_canonicalizer::to_string(&config)?;
        let config_hash = sha2::Sha256::digest(config_data.as_bytes());
        let payload = [config_hash.as_slice(), unsigned_hash.as_slice()].concat();
        let (base, signature) = multibase::decode(proof_value)?;
        if base != multibase::Base::Base58Btc {
            bail!("unsupported multibase encoding");
        }
        let key = verification_method.key.jwk()?;
        key.verify_bytes(&payload, &signature)?;
    }
    Ok(())
}

/// Check if a key is contained in a log entry's update keys (authorized to
/// carry out DID operations).
/// 
/// # Errors
/// Will fail if the key is not authorized to update the log entry or if finding
/// the verification method by dereferencing the URL fails.
pub async fn authorized_key(
    url: &str, log_entry: &DidLogEntry, resolver: &impl DidResolver,
) -> anyhow::Result<VerificationMethod> {
    let deref = dereference(url, None, resolver.clone()).await?;
    let Some(cs) = deref.content_stream else {
        bail!("could not dereference verification method");
    };
    match cs {
        Resource::VerificationMethod(vm) => {
            if !log_entry.parameters.update_keys.contains(&vm.id) {
                bail!("verification method is not authorized to update the log entry");
            }
            Ok(vm)
        }
        _ => bail!("dereferenced content stream is not a verification method"),
    }
}

/// Validate a set of witness entries.
///
/// Note: This function just validates the witness entries in the log parameters
/// meet structural requiremnents. It does not verify the proofs supplied by
/// the witnesses.
///
/// # Errors
///
/// Will fail if the witness threshold is zero, the witness list is empty,
/// the contribution (weight) of a witness is zero, or the sum of
/// contributions would never reach the threshold.
pub fn validate_witness(witness: &Witness) -> anyhow::Result<()> {
    if witness.threshold == 0 {
        bail!("witness threshold must be greater than zero.");
    }
    if witness.witnesses.is_empty() {
        bail!("witness witness list must not be empty.");
    }
    let mut total_weight = 0;
    for w in &witness.witnesses {
        if !w.id.starts_with("did:key:") {
            bail!("witness id must be a 'did:key:'.");
        }
        if w.weight == 0 {
            bail!("witness weight must be greater than zero.");
        }
        total_weight += w.weight;
    }
    if total_weight < witness.threshold {
        bail!("total witness weight must be greater than or equal to the threshold.");
    }
    Ok(())
}
