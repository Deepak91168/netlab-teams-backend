//! # platforms/google_meet/ip_ranges.rs
//!
//! **Google Meet-owned traffic classification data — SCAFFOLD.**
//!
//! This is the Google Meet counterpart to `platforms::teams::ip_ranges`.  It is
//! intentionally left as a scaffold: every check currently returns `false`, so
//! the Google Meet platform classifies *nothing* and has zero effect on the
//! live Teams pipeline.
//!
//! ## TODO (Google Meet implementer)
//! Fill in Google's published media IP ranges and turn these into real
//! byte-level membership tests, exactly as `teams::ip_ranges` does.
//!
//! Google Meet media is served primarily from Google's `74.125.0.0/16` and
//! parts of `142.250.0.0/15`, `172.217.0.0/16`, `216.58.192.0/19`, and the
//! IPv6 `2607:f8b0::/32` block (see Google's published "Meet" / Workspace
//! media ranges for the authoritative, current list).  Match on the leading
//! bytes the same way the Teams ranges do, e.g.:
//!
//! ```ignore
//! // 74.125.0.0/16
//! if ip[0] == 74 && ip[1] == 125 { return true; }
//! ```

/// Returns `true` if `ip` (4 bytes) belongs to a Google Meet media IPv4 range.
///
/// SCAFFOLD: always `false` until the implementer fills in Google's ranges.
#[inline(always)]
pub fn is_google_ipv4(ip: &[u8]) -> bool {
    if ip.len() < 4 {
        return false;
    }

    // 74.125.250.0/24
    if ip[0] == 74 && ip[1] == 125 && ip[2] == 250 {
        return true;
    }

    // 74.125.247.128/32
    if ip[0] == 74 && ip[1] == 125 && ip[2] == 247 && ip[3] == 128 {
        return true;
    }

    // 142.250.82.0/24
    if ip[0] == 142 && ip[1] == 250 && ip[2] == 82 {
        return true;
    }

    false
}

/// Returns `true` if `ip` (16 bytes, big-endian) belongs to a Google Meet
/// media IPv6 range.
///
/// SCAFFOLD: always `false` until the implementer fills in Google's ranges.
#[inline(always)]
pub fn is_google_ipv6(ip: &[u8]) -> bool {
    if ip.len() < 16 {
        return false;
    }

    // 2001:4860:4864:5::/64
    if ip[0] == 0x20
        && ip[1] == 0x01
        && ip[2] == 0x48
        && ip[3] == 0x60
        && ip[4] == 0x48
        && ip[5] == 0x64
        && ip[6] == 0x00
        && ip[7] == 0x05
    {
        return true;
    }

    // 2001:4860:4864:6::/64
    if ip[0] == 0x20
        && ip[1] == 0x01
        && ip[2] == 0x48
        && ip[3] == 0x60
        && ip[4] == 0x48
        && ip[5] == 0x64
        && ip[6] == 0x00
        && ip[7] == 0x06
    {
        return true;
    }

    // 2001:4860:4864:4:8000::/128
    if ip
        == [
            0x20, 0x01, 0x48, 0x60,
            0x48, 0x64, 0x00, 0x04,
            0x80, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]
    {
        return true;
    }

    false
}