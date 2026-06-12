//! # models/
//!
//! Data types shared between the capture hot-path and the I/O threads.
//! Currently contains a single type (`RtpRecord`) — structured so that
//! adding further record types later requires only a new submodule here.

pub mod rtp_record;
pub use rtp_record::{RtpRecord, parse_rtp_record};
