//! GDHCN HCERT & SMART Health Link validator -- Rust port of gdhcn-helper.
//!
//! Port status and sequencing live in ../../docs/PORT-PLAN.md. Modules land in
//! the plan's step order; only what is implemented is declared here, so the
//! crate always reflects reality rather than aspiration.

mod error;
pub use error::Error;

// Step 2 -- decode pipeline.
pub mod base45;
