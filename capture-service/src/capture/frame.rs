//! # capture/frame.rs
//!
//! **What this file does (SHARED / platform-agnostic):**
//! Parses a raw Ethernet frame down to the UDP payload and exposes the result
//! as a [`ParsedPacket`].  This is the *generic* half of the original Teams
//! `quick_precheck`: it understands Ethernet, 802.1Q / QinQ VLAN tags, IPv4,
//! IPv6 (including the extension-header chain) and UDP — but it knows nothing
//! about any particular conferencing vendor.
//!
//! The per-vendor IP-range matching that used to live inside `quick_precheck`
//! now lives in each platform's classifier (e.g. `platforms::teams::classify`),
//! which inspects the zero-copy `src_ip` / `dst_ip` slices on the returned
//! [`ParsedPacket`].  This is what lets a single capture + parse pipeline feed
//! many isolated platforms.
//!
//! `parse_frame` performs **no heap allocation** — all IP fields are returned
//! as borrowed slices into the original frame.  String formatting of addresses
//! happens later and only for packets a platform decides to keep.

/// A parsed UDP-over-IP frame, ready for platform classification.
///
/// All slices borrow from the original frame buffer (`raw`); nothing is copied.
pub struct ParsedPacket<'a> {
    /// The full original Ethernet frame.
    pub raw: &'a [u8],
    /// `true` for IPv6, `false` for IPv4.
    pub is_ipv6: bool,
    /// Byte offset of the IP header within `raw`.
    pub ip_start: usize,
    /// Byte offset of the first UDP payload byte within `raw`.
    /// May equal `raw.len()` for a zero-length payload.
    pub udp_payload_offset: usize,
    /// Source IP address bytes (4 for IPv4, 16 for IPv6).
    pub src_ip: &'a [u8],
    /// Destination IP address bytes (4 for IPv4, 16 for IPv6).
    pub dst_ip: &'a [u8],
    /// The UDP payload (possibly empty if the frame was truncated).
    pub udp_payload: &'a [u8],
}

/// Parse a raw Ethernet frame into a [`ParsedPacket`].
///
/// Returns `None` for frames that are not UDP-over-IPv4/IPv6 (the protocol
/// the capture pipeline is built around).  This mirrors exactly the parsing
/// the original `quick_precheck` performed, minus the Microsoft IP-range gate
/// (now a per-platform concern).
#[inline(always)]
pub fn parse_frame(data: &[u8]) -> Option<ParsedPacket<'_>> {
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

        let udp_payload_offset = ip_start + ihl + 8;
        let udp_payload: &[u8] = if udp_payload_offset <= data.len() {
            &data[udp_payload_offset..]
        } else {
            &[]
        };

        return Some(ParsedPacket {
            raw: data,
            is_ipv6: false,
            ip_start,
            udp_payload_offset,
            src_ip: &data[ip_start + 12..ip_start + 16],
            dst_ip: &data[ip_start + 16..ip_start + 20],
            udp_payload,
        });
    }

    // ── IPv6 path ─────────────────────────────────────────────────────────
    if data.len() < ip_start + 40 {
        return None;
    }

    // Walk extension headers until we find UDP (17) or give up.
    let mut next_hdr = data[ip_start + 6];
    let mut offset = ip_start + 40;

    let udp_payload_offset = loop {
        match next_hdr {
            17 => break offset + 8, // UDP found
            58 => return None,      // ICMPv6 — skip
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
    };

    let udp_payload: &[u8] = if udp_payload_offset <= data.len() {
        &data[udp_payload_offset..]
    } else {
        &[]
    };

    Some(ParsedPacket {
        raw: data,
        is_ipv6: true,
        ip_start,
        udp_payload_offset,
        src_ip: &data[ip_start + 8..ip_start + 24],
        dst_ip: &data[ip_start + 24..ip_start + 40],
        udp_payload,
    })
}
