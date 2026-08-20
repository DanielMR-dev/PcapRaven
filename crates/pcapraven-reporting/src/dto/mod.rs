//! Data Transfer Objects (DTOs) for report serialization.

pub mod analysis;
pub mod dns;
pub mod findings;
pub mod flows;
pub mod http;
pub mod tls;
pub mod validation;

pub use analysis::*;
pub use dns::*;
pub use findings::*;
pub use flows::*;
pub use http::*;
pub use tls::*;
pub use validation::*;
