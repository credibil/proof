//! Create operation for the `did:webvh` method.
//! 

use serde::{Deserialize, Serialize};

/// Output of a `create` operation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CreateResult {}