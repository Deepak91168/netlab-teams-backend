//! # platforms/google_meet/classify.rs
//!
//! **Google Meet-owned classification rule — SCAFFOLD.**
//!
//! Mirrors `platforms::teams::classify`: a packet would belong to Google Meet
//! iff its source *or* destination IP falls in a Google media range.  Until
//! [`super::ip_ranges`] is filled in, this returns `false` for every packet,
//! guaranteeing the Google Meet platform claims nothing and leaves the Teams
//! pipeline completely unaffected.

use super::ip_ranges::{is_google_ipv4, is_google_ipv6};
use crate::capture::ParsedPacket;

/// Hot-path check: is this parsed UDP packet Google Meet media?
///
/// SCAFFOLD: returns `false` until `ip_ranges` is implemented.
#[inline(always)]
pub fn is_google_meet(pkt: &ParsedPacket) -> bool {
    if pkt.is_ipv6 {
        is_google_ipv6(pkt.src_ip) || is_google_ipv6(pkt.dst_ip)
    } else {
        is_google_ipv4(pkt.src_ip) || is_google_ipv4(pkt.dst_ip)
    }
}
