//! # ip_ranges.rs
//!
//! **What this file does:**
//! - `is_microsoft_ipv4(ip)` — checks whether an IPv4 address falls inside
//!   Microsoft Teams' published UDP media ranges (MS O365 ID 11):
//!     - `52.112.0.0/14`  (52.112-115.x.x)
//!     - `52.122.0.0/15`  (52.122-123.x.x)
//! - `is_microsoft_ipv6(ip)` — same check for IPv6 prefixes documented by
//!   Microsoft for Teams media traffic
//! - `quick_precheck(data)` — the outermost gate on the capture hot-path:
//!   parses Ethernet (including 802.1Q / QinQ tags), extracts IP version,
//!   confirms the transport is UDP, and checks src/dst against the Teams IP
//!   ranges.  Returns `Some((is_ipv6, ip_start, udp_payload_offset))` for
//!   packets that pass, `None` for everything else.
//!
//! Only packets that pass `quick_precheck` are handed to `identify_protocol`.
//! This keeps the RFC 7983 demux off the critical path for the bulk of
//! non-Teams traffic.

// ─────────────────────────────────────────────────────────────────────────────
//  IP range checks
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `ip` belongs to a Microsoft Teams media IPv4 range.
/// Matches the MS O365 connectivity documentation, Optimize category (ID 11).
#[inline(always)]
pub fn is_microsoft_ipv4(ip: [u8; 4]) -> bool {
    match ip[0] {
        52 => matches!(ip[1],
            112..=115 |  // 52.112.0.0/14
            122..=123    // 52.122.0.0/15
        ),
        _ => false,
    }
}

/// Returns `true` if `ip` (16 bytes, big-endian) belongs to a Microsoft Teams
/// media IPv6 range.
#[inline(always)]
pub fn is_microsoft_ipv6(ip: &[u8]) -> bool {
    if ip.len() < 16 {
        return false;
    }

    // 2603:1010::/22 and sub-ranges used by Teams media
    if ip[0] == 0x26 && ip[1] == 0x03 && ip[2] == 0x10 {
        let b3 = ip[3];
        if b3 == 0x63 && (ip[4] & 0xFC) == 0x00 {
            return true;
        }
        if b3 == 0x27 && ip[4] == 0x00 && ip[5] == 0x00 {
            return true;
        }
        if b3 == 0x37 && ip[4] == 0x00 && ip[5] == 0x00 {
            return true;
        }
        if b3 == 0x47 && ip[4] == 0x00 && ip[5] == 0x00 {
            return true;
        }
        if b3 == 0x57 && ip[4] == 0x00 && ip[5] == 0x00 {
            return true;
        }
    }

    // 2620:1ec:6::/48 and 2620:1ec:40::/42
    if ip[0] == 0x26 && ip[1] == 0x20 && ip[2] == 0x01 && ip[3] == 0xec {
        if ip[4] == 0x00 && ip[5] == 0x06 {
            return true;
        }
        if ip[4] == 0x00 && (ip[5] & 0xC0) == 0x40 {
            return true;
        }
    }

    false
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fast pre-filter
// ─────────────────────────────────────────────────────────────────────────────

/// Gate every raw Ethernet frame through three checks before any heavier work:
/// 1. Ethertype is IPv4 (`0x0800`) or IPv6 (`0x86DD`), accounting for 802.1Q
///    (`0x8100`) and QinQ / 802.1ad (`0x88A8`) VLAN tags
/// 2. Transport protocol is UDP (proto 17 / next-header 17)
/// 3. Source **or** destination IP is in a Microsoft Teams media range
///
/// **Returns** `Some((is_ipv6, ip_start, udp_payload_offset))` on a match:
/// - `is_ipv6`           — `true` for IPv6, `false` for IPv4
/// - `ip_start`          — byte offset of the IP header inside `data`
/// - `udp_payload_offset`— byte offset of the first UDP payload byte
///
/// **Returns** `None` for all other packets (the vast majority of campus traffic).
#[inline(always)]
pub fn quick_precheck(data: &[u8]) -> Option<(bool, usize, usize)> {
    if data.len() < 14 {
        return None;
    }

    // ── Ethertype / VLAN unwrap ───────────────────────────────────────────
    let raw_et = u16::from_be_bytes([data[12], data[13]]);
    let (ethertype, ip_start) = match raw_et {
        // QinQ (802.1ad outer tag) — may carry an inner 802.1Q tag
        0x88a8 => {
            if data.len() < 22 {
                return None;
            }
            let inner_et = u16::from_be_bytes([data[16], data[17]]);
            if inner_et == 0x8100 {
                (u16::from_be_bytes([data[20], data[21]]), 22usize)
            } else {
                (inner_et, 18usize)
            }
        }
        // Single 802.1Q tag
        0x8100 => {
            if data.len() < 18 {
                return None;
            }
            (u16::from_be_bytes([data[16], data[17]]), 18usize)
        }
        // Untagged
        _ => (raw_et, 14usize),
    };

    let is_ipv4 = ethertype == 0x0800;
    let is_ipv6 = ethertype == 0x86DD;
    if !is_ipv4 && !is_ipv6 {
        return None;
    }

    // ── IPv4 path ─────────────────────────────────────────────────────────
    if is_ipv4 {
        if data.len() < ip_start + 20 {
            return None;
        }
        if data[ip_start + 9] != 17 {
            return None;
        } // not UDP

        let ihl = (data[ip_start] & 0x0F) as usize * 4;
        if ihl < 20 {
            return None;
        }

        let src_ip = [
            data[ip_start + 12],
            data[ip_start + 13],
            data[ip_start + 14],
            data[ip_start + 15],
        ];
        let dst_ip = [
            data[ip_start + 16],
            data[ip_start + 17],
            data[ip_start + 18],
            data[ip_start + 19],
        ];

        if is_microsoft_ipv4(src_ip) || is_microsoft_ipv4(dst_ip) {
            return Some((false, ip_start, ip_start + ihl + 8));
        }
        return None;
    }

    // ── IPv6 path ─────────────────────────────────────────────────────────
    if data.len() < ip_start + 40 {
        return None;
    }

    let src6 = &data[ip_start + 8..ip_start + 24];
    let dst6 = &data[ip_start + 24..ip_start + 40];
    if !is_microsoft_ipv6(src6) && !is_microsoft_ipv6(dst6) {
        return None;
    }

    // Walk extension headers until we find UDP (17) or give up
    let mut next_hdr = data[ip_start + 6];
    let mut offset = ip_start + 40;

    loop {
        match next_hdr {
            17 => return Some((true, ip_start, offset + 8)), // UDP found
            58 => return None,                               // ICMPv6 — skip
            // Hop-by-Hop (0), Destination (60), Routing (43)
            0 | 60 | 43 => {
                if data.len() < offset + 2 {
                    return None;
                }
                next_hdr = data[offset];
                offset += (data[offset + 1] as usize + 1) * 8;
            }
            // Fragment (44) — fixed 8-byte header
            44 => {
                if data.len() < offset + 8 {
                    return None;
                }
                next_hdr = data[offset];
                offset += 8;
            }
            // AH (51) — length in 4-byte words, offset by 2
            51 => {
                if data.len() < offset + 2 {
                    return None;
                }
                next_hdr = data[offset];
                offset += (data[offset + 1] as usize + 2) * 4;
            }
            _ => return None,
        }
        if offset > data.len() {
            return None;
        }
    }
}
