//! # Endpoint
//!
//! `Endpoint` provides the entry point for DWN messages. Messages are routed
//! to the appropriate handler for processing, returning a reply that can be
//! serialized to a JSON object.

mod document;

use std::fmt::Debug;

use anyhow::Error;
pub use credibil_core::api::{Body, Handler, Headers, Request, Response};
use tracing::instrument;

pub use self::document::{DocumentRequest, DocumentResponse};
use crate::provider::Provider;

/// Result type for Token Status endpoints.
pub type Result<T, E = Error> = anyhow::Result<T, E>;

/// Handle incoming requests.
///
/// # Errors
///
/// This method can fail for a number of reasons related to the imcoming
/// message's viability. Expected failues include invalid authorization,
/// insufficient permissions, and invalid message content.
///
/// Implementers should look to the Error type and description for more
/// information on the reason for failure.
#[instrument(level = "debug", skip(provider))]
pub async fn handle<B, H, P, U>(
    issuer: &str, request: impl Into<Request<B, H>> + Debug, provider: &P,
) -> Result<Response<U>>
where
    B: Body,
    H: Headers,
    P: Provider,
    Request<B, H>: Handler<U, P, Error = Error>,
{
    let request: Request<B, H> = request.into();
    Ok(request.handle(issuer, provider).await?.into())
}
