//! # platforms/teams/ip_ranges.rs
//!
//! **Teams-owned traffic classification data.**
//!
//! Byte-level membership tests for Microsoft Teams' published UDP media IP
//! ranges (MS O365 connectivity, Optimize category, ID 11).  These were the
//! Microsoft-specific half of the original `quick_precheck`; the generic
//! Ethernet/IP/UDP parsing now lives in the shared `capture::frame` module, so
//! only the vendor ranges remain here — fully owned by the Teams platform.

/// Returns `true` if `ip` belongs to a Microsoft Teams media IPv4 range.
///   - `52.112.0.0/14`  (52.112-115.x.x)
///   - `52.122.0.0/15`  (52.122-123.x.x)
#[inline(always)]
pub fn is_microsoft_ipv4(ip: &[u8]) -> bool {
    if ip.len() < 4 {
        return false;
    }
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
