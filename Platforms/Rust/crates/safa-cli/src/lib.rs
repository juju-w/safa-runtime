//! Minimal, non-shipping Agent-facing CLI shell for SAFA runtimes.
//!
//! This crate owns parsing and presentation only. It has no credential-store access, approval
//! authority, Broker implementation, or remote transport fallback.

mod arguments;
mod clock;
mod envelope;
mod runtime;

pub use clock::{Clock, SystemClock};
pub use runtime::{
    run, BrokerClient, BrokerStatus, RuntimeContext, UnavailableBrokerClient,
    EXIT_INVALID_INVOCATION, EXIT_RUNTIME_FAILURE, EXIT_SUCCESS, EXIT_UNEXPECTED,
};
