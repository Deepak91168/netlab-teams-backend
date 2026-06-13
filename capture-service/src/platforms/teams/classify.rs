//! # platforms/teams/classify.rs
//!
//! **Teams-owned classification rule.**
//!
//! A packet belongs to Teams iff its source *or* destination IP falls in a
//! Microsoft Teams media range.  This is the per-platform replacement for the
//! IP gate that used to be baked into `quick_precheck`, and it is completely
//! isolated from any other platform's rules.

use super::ip_ranges::{is_microsoft_ipv4, is_microsoft_ipv6};
use crate::capture::ParsedPacket;

/// Hot-path check: is this parsed UDP packet Microsoft Teams media?
#[inline(always)]
pub fn is_teams(pkt: &ParsedPacket) -> bool {
    if pkt.is_ipv6 {
        is_microsoft_ipv6(pkt.src_ip) || is_microsoft_ipv6(pkt.dst_ip)
    } else {
        is_microsoft_ipv4(pkt.src_ip) || is_microsoft_ipv4(pkt.dst_ip)
    }
}
