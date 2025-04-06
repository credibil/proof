//! # HTTP server example
//!
//! This example demonstrates a basic HTTP service implementation of the
//! `did:webvh` method using the `credibil-did` crate.

mod create;
mod keyring;
mod log;
mod state;

use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Router, extract::FromRequest};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use create::create;
use state::AppState;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::DEBUG).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");

    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router =
        Router::new().route("/create", post(create)).layer(cors).with_state(AppState::new());

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("should have addr"));
    axum::serve(listener, router).await.expect("server should run");
}

// Custom JSON extractor to enable overriding the rejection and create our own
/// error response.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct AppJson<T>(pub T);

impl<T> IntoResponse for AppJson<T>
where
    T: Serialize,
    axum::Json<T>: IntoResponse,
{
    fn into_response(self) -> axum::response::Response {
        axum::Json(self.0).into_response()
    }
}

/// Custom application errors.
pub enum AppError {
    /// The request body contained invalid JSON.
    InvalidJson(JsonRejection),

    /// Status code and message error.
    Status(StatusCode, String),

    /// Unspecified application error.
    Other(anyhow::Error),
}

/// Error response.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ErrorResponse {
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::InvalidJson(rejection) => (rejection.status(), rejection.body_text()),
            Self::Status(status, message) => {
                tracing::error!("status error: {status} {message}");
                (status, message)
            }
            Self::Other(error) => {
                tracing::error!("internal server error: {}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".into())
            }
        };
        (status, AppJson(ErrorResponse { message })).into_response()
    }
}

impl From<JsonRejection> for AppError {
    fn from(rejection: JsonRejection) -> Self {
        Self::InvalidJson(rejection)
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}

impl From<credibil_did::Error> for AppError {
    fn from(error: credibil_did::Error) -> Self {
        Self::Other(error.into())
    }
}
