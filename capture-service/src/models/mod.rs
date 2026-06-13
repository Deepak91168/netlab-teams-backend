//! # models/
//!
//! **SHARED common packet models.**
//!
//! Data types shared between the capture hot-path and every platform's I/O and
//! session threads.  Currently contains a single type ([`RtpRecord`]) plus its
//! pure parser.  `RtpRecord` describes a generic RTP/UDP/IP packet and is not
//! tied to any conferencing vendor, so it is shared rather than duplicated per
//! platform.  Adding further record types later requires only a new submodule.

pub mod rtp_record;
pub use rtp_record::{parse_rtp_record, RtpRecord};
