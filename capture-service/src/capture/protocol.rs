//! # capture/protocol.rs
//!
//! **What this file does (SHARED / platform-agnostic):**
//! RFC 7983 protocol demultiplexing — identifies the application-layer
//! protocol carried inside a UDP payload, using the same byte-level checks
//! and the same check ORDER as the original Teams reference implementation.
//!
//! The byte-level checks are *generic* (they describe the wire format of each
//! protocol, not any particular conferencing vendor), so they live in the
//! shared capture layer.  Each platform decides, in its own `handle_packet`,
//! *which* of these protocols it actually cares about.
//!
//! The order matters because some byte ranges overlap between protocols:
//!   1. STUN / TURN Channel Data  (checked first — most restrictive header)
//!   2. DTLS                      (content-type byte 20-23, versioned)
//!   3. QUIC                      (first byte 64-127 or 192-255)
//!   4. RTCP                      (version=2, PT 200-207)
//!   5. RTP                       (version=2, PT 0-127)
//!   6. UNKNOWN
//!
//! All functions are `#[inline(always)]` — they are called millions of times
//! per second from the capture hot-path and must not generate call overhead.

/// Application-layer protocol identified inside a UDP payload by RFC 7983
/// demultiplexing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Unknown,
    Rtp,
    Rtcp,
    Stun,
    Dtls,
    Quic,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Individual protocol checks
// ─────────────────────────────────────────────────────────────────────────────

/// RFC 5389 / RFC 8656: STUN and TURN Channel Data.
///
/// Two sub-cases:
/// 1. **Native STUN** — magic cookie `0x2112A442` at bytes 4-7, first 2 bits
///    of byte 0 must be `00`.
/// 2. **TURN Channel Data** — channel number in `0x4000..=0x7FFF`, declared
///    length field within ±3 bytes of actual remaining payload (padding).
#[inline(always)]
pub fn is_stun(payload: &[u8]) -> bool {
    if payload.len() < 4 {
        return false;
    }

    let b0 = payload[0];

    // Native STUN (RFC 5389)
    if payload.len() >= 20 && (b0 & 0xC0) == 0x00 {
        let magic = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        if magic == 0x2112A442 {
            return true;
        }
    }

    // TURN Channel Data (RFC 8656 / RFC 5766)
    let channel_num = u16::from_be_bytes([payload[0], payload[1]]);
    if (0x4000..=0x7FFF).contains(&channel_num) {
        let declared = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        let remaining = payload.len() - 4;
        // Allow 0-3 bytes of DTLS-style padding
        if remaining >= declared && remaining <= declared + 3 {
            return true;
        }
    }

    false
}

/// RFC 6347 / RFC 9147: DTLS.
///
/// Byte 0 is the TLS/DTLS content type (20-23).
/// Bytes 1-2 are the DTLS version: `0xFEFF` (1.0), `0xFEFD` (1.2),
/// or `0xFEFC` (1.3).
#[inline(always)]
pub fn is_dtls(payload: &[u8]) -> bool {
    if payload.len() < 3 {
        return false;
    }
    if !(20..=23).contains(&payload[0]) {
        return false;
    }
    let version = u16::from_be_bytes([payload[1], payload[2]]);
    matches!(version, 0xFEFF | 0xFEFD | 0xFEFC)
}

/// RFC 9000: QUIC (Long Header, Short Header, and Version Negotiation).
///
/// - **Long Header** : byte 0 in `192..=255` (top 2 bits `11`)
/// - **Short Header**: byte 0 in `64..=127`  (top 2 bits `01`)
/// - **Version Negotiation / GREASE**: top bit set, version field `0x00000000`
///   or matches GREASE mask `0x?a?a?a?a`
///
/// STUN is checked before QUIC so TURN Channel Data (0x4000-0x7FFF) is not
/// mis-identified as a QUIC Short Header.
#[inline(always)]
pub fn is_quic(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let b0 = payload[0];

    if (192..=255).contains(&b0) {
        return true;
    } // Long Header
    if (64..=127).contains(&b0) {
        return true;
    } // Short Header

    // Version Negotiation / GREASE
    if payload.len() >= 5 && (b0 & 0x80) == 0x80 {
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        if version == 0 || (version & 0x0f0f0f0f) == 0x0a0a0a0a {
            return true;
        }
    }

    false
}

/// RFC 3550: RTCP.
///
/// Version field (top 2 bits of byte 0) must be `2`.
/// Byte 1 (full byte, not masked) must be a valid RTCP PT: `200..=207`.
#[inline(always)]
pub fn is_rtcp(payload: &[u8]) -> bool {
    if payload.len() < 2 {
        return false;
    }
    let version = (payload[0] >> 6) & 0x03;
    version == 2 && (200..=207).contains(&payload[1])
}

/// RFC 3550: RTP.
///
/// Version field (top 2 bits of byte 0) must be `2`.
/// Minimum 12 bytes (fixed RTP header).
/// Payload type is the lower 7 bits of byte 1 — range 0-127 — but we do
/// NOT check PT here because RTCP was already eliminated by `is_rtcp`.
#[inline(always)]
pub fn is_rtp_payload(payload: &[u8]) -> bool {
    payload.len() >= 12 && (payload[0] >> 6) & 0x03 == 2
}

// ─────────────────────────────────────────────────────────────────────────────
//  Demultiplexer
// ─────────────────────────────────────────────────────────────────────────────

/// Identify the protocol of a UDP payload using RFC 7983 ordering.
#[inline(always)]
pub fn classify_protocol(payload: &[u8]) -> Protocol {
    if payload.is_empty() {
        return Protocol::Unknown;
    }
    if is_stun(payload) {
        return Protocol::Stun;
    }
    if is_dtls(payload) {
        return Protocol::Dtls;
    }
    if is_quic(payload) {
        return Protocol::Quic;
    }
    if is_rtcp(payload) {
        return Protocol::Rtcp;
    }
    if is_rtp_payload(payload) {
        return Protocol::Rtp;
    }
    Protocol::Unknown
}
