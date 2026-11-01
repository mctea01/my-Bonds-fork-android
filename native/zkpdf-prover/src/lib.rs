//! Offline witness execution for the frozen zkPDF v1 circuits.

mod acir;
mod assets;
mod field;
mod inflate;
mod lex;
mod prepare;
mod public;
mod verify;
pub use prepare::check;
mod types;
pub use types::*;
pub const NOIR_REVISION: &str = "1.0.0-beta.15+83245db91dcf63420ef4bcbbd85b98f397fee663";
pub const BB_REVISION: &str = "2.1.9+f2bed7ed073966bb2a2dcdd02a133d11bf2996d3";

/// Errors expose fixed codes only; upstream diagnostic payloads are discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "bb")]
mod backend;
#[cfg(feature = "bb")]
mod runtime;
#[cfg(feature = "bb")]
pub use runtime::{prove, prove_with_metrics, verify, SegmentMetrics};
mod opening;
pub use opening::verify_opening;
