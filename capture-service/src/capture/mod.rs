//! # capture/
//!
//! **SHARED, platform-agnostic capture-side utilities.**
//!
//! This layer is the single packet-capture + parse pipeline that every
//! platform builds on top of:
//!
//! - [`frame`]    — Ethernet / VLAN / IPv4 / IPv6 / UDP parsing into
//!                  [`ParsedPacket`] (the generic half of the old
//!                  `quick_precheck`).
//! - [`protocol`] — RFC 7983 application-protocol demultiplexing
//!                  (RTP / RTCP / STUN / DTLS / QUIC).
//!
//! Nothing in this module knows about Microsoft Teams, Google Meet, Zoom or
//! any other vendor.  Vendor-specific decisions (which IP ranges belong to me,
//! which demuxed protocols do I keep) live in the platform modules.

pub mod frame;
pub mod protocol;

pub use frame::{parse_frame, ParsedPacket};
pub use protocol::{classify_protocol, Protocol};
