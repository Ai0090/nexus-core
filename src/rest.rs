pub mod handlers;
pub mod helpers;
pub mod state;
pub mod types;

mod routes;

pub use routes::serve;
pub use state::{E2eeJobQueue, HttpRateLimit, RestState};
pub use types::*;

// Pure module hub: all endpoint logic lives in `rest/handlers/*`,
// shared utilities live in `rest/helpers.rs`, and state in `rest/state.rs`.
