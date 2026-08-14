//! Deterministic bidirectional flow reconstruction for PcapRaven.
//!
//! This crate reconstructs canonical bidirectional flow instances from normalized
//! domain packet facts. It enforces strict capture stream order, manages lifecycle
//! boundaries (timeouts, TCP reset, and SYN restarts), computes checked traffic
//! statistics, and calculates exact rational temporal metrics without retaining
//! packet payloads or interval vectors in memory.

pub mod config;
pub mod error;
pub mod metrics;
pub mod reconstructor;

pub use config::{
    FlowConfigError, FlowReconstructionConfig, FlowReconstructionConfigBuilder,
    MAX_ALLOWED_FLOW_INSTANCES, MAX_ALLOWED_TIMEOUT_SECONDS, MAX_ALLOWED_TRACKED_FLOWS,
};
pub use error::FlowError;
pub use metrics::{exact_duration_between, validate_timestamp_structure};
pub use reconstructor::{
    FlowDisposition, FlowExclusionReason, FlowReconstructionStep, FlowReconstructor, has_timed_out,
};
