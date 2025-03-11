//! Operation endpoint module.

pub mod create;
pub mod resolve;

use std::fmt::Debug;

use super::{Method, Result};

/// Handle incoming requests for DID operations.
/// 
/// # Errors
/// 
/// This method can fail on request validation or if client providers return
/// an error.
pub async fn handle<B, H, R>(
    method: impl Into<Method>, request: impl Into<Request<B, H>>,
) -> Result<R>
where
    B: Body,
    H: Headers,
    Request<B, H>: Handler<Response = R>,
{
    let req: Request<B, H> = request.into();
    req.handle(method).await
}

/// A request to process
#[derive(Clone, Debug)]
pub struct Request<B, H>
where
    B: Body,
    H: Headers,
{
    /// The request to process.
    pub body: B,

    /// Headers associated with the request.
    pub headers: H,
}

impl<B: Body> From<B> for Request<B, NoHeaders> {
    fn from(body: B) -> Self {
        Self {
            body,
            headers: NoHeaders,
        }
    }
}

/// Functions common to all requests.
/// 
/// The primary role of this trait is to provide a common interface for requests
/// so they can be handled by the universal [`handle`] function.
pub trait Handler: Clone + Debug + Send + Sync {
    /// The inner reply type specific to the request handler.
    type Response;

    /// Routes the request to the concrete handler.
    fn handle(self, method: impl Into<Method>) -> impl Future<Output = Result<Self::Response>> + Send;
}

/// The `Body` trait is used to restrict the types able to implement request
/// bodies. It is implemented by all `xxxRequest` types.
pub trait Body: Clone + Debug + Send + Sync {}

/// The `Headers` trait is used to restrict the types able to implement request
/// headers.
pub trait Headers: Clone + Debug + Send + Sync {}

/// A placeholder for requests without headers.
#[derive(Clone, Debug)]
pub struct NoHeaders;
impl Headers for NoHeaders {}
