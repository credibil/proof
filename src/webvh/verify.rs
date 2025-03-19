//! Verification and validation functions for `did:webvh` log entries and
//! information referenced in the log parameters.

use super::{DidLogEntry, Witness};

use anyhow::bail;

/// Verify the proofs in a log entry.
/// 
/// Requires a DID resolver to fetch a DID document and find the verification
/// method referenced in the proof.
///
/// # Errors
/// Will return an error if any of the proofs on the log entry are invalid.
pub fn verify_proofs(log_entry: &DidLogEntry) -> anyhow::Result<()> {
    if log_entry.proof.is_empty() {
        bail!("log entry has no proof");
    }
    for proof in &log_entry.proof {
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
            bail!("unsupported cryptosuite {} - must be 'eddsa-jcs-2022'", proof.cryptosuite.as_deref().unwrap_or(""));
        }
        if proof.verification_method.starts_with("did:key:") {
            if !is_key_authorized(&proof.verification_method, &log_entry.parameters.update_keys) {
                bail!("verification method is not authorized to update the log entry");
            }
        } else if proof.verification_method.starts_with("did:webvh:") {
            if let Some(witness) = &log_entry.parameters.witness {
                if !is_witness_authorized(&proof.verification_method, witness) {
                    bail!("verification method is not from an authorized witness");
                }
            } else {
                bail!("log entry has no witness information to verify proof");
            }
        } else {
            bail!("proof verification method is not a 'did:key:' or 'did:webvh:'");
        }
    }
    Ok(())
}

// Check if a key is authorized to sign a log entry.
fn is_key_authorized(verification_method: &str, update_keys: &[String]) -> bool {
    if !verification_method.starts_with("did:key:") {
        return false;
    }
    let parts = verification_method.split('#').collect::<Vec<_>>();
    update_keys.iter().any(|k| k == parts[0])
}

// Check if a witness is authorized to sign a log entry.
fn is_witness_authorized(verification_method: &str, witness: &Witness) -> bool {
    if !verification_method.starts_with("did:webvh:") {
        return false;
    }
    let parts = verification_method.split('#').collect::<Vec<_>>();
    witness.witnesses.iter().any(|w| w.id == parts[0])
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
