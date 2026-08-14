//! Deterministic bidirectional flow reconstruction for PcapRaven.
//!
//! This crate reconstructs canonical bidirectional flow instances from normalized
//! domain packet facts. It enforces strict capture stream order, manages lifecycle
//! boundaries (timeouts, TCP reset, and SYN restarts), and emits compact
//! packet associations and minimal flow records without retaining packet data
//! or computing temporal metrics (deferred to Phase 5).

pub mod config;
pub mod error;
pub mod reconstructor;

pub use config::{
    FlowConfigError, FlowReconstructionConfig, FlowReconstructionConfigBuilder,
    MAX_ALLOWED_FLOW_INSTANCES, MAX_ALLOWED_TIMEOUT_SECONDS, MAX_ALLOWED_TRACKED_FLOWS,
};
pub use error::FlowError;
pub use reconstructor::{
    FlowDisposition, FlowExclusionReason, FlowReconstructionStep, FlowReconstructor, has_timed_out,
};
