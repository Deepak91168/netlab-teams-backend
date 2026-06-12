//! # models/rtp_record.rs
//!
//! **What this file does:**
//! - `RtpRecord` — the structured representation of one captured RTP packet,
//!   derived from the raw Ethernet frame.  Fields mirror the CSV column order
//!   written by `records_thread`.
//! - `parse_rtp_record(data, is_ipv6, ip_start, udp_payload_offset, ts)` —
//!   extracts all RTP + IP + UDP header fields from the raw bytes.  Returns
//!   `None` if the frame is too short to contain a valid RTP fixed header
//!   (12 bytes).
//!
//! This module has no side-effects and no global state — it is pure parsing.

use serde::Serialize;
use std::time::Duration;

/// All fields captured from a single RTP/UDP/IP frame.
/// `Serialize` is derived so the struct can be turned into JSON or CSV rows
/// without extra code.
#[derive(Clone, Debug, Serialize)]
pub struct RtpRecord {
    pub arrival_epoch_ns: u64, // wall-clock at capture, nanoseconds since UNIX epoch
    pub src_ip: String,        // dotted-decimal IPv4 or colon-hex IPv6
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_proto: u8,       // always 17 (UDP) for records produced here
    pub ip_len: u16,        // total IP packet length (header + payload)
    pub udp_len: u16,       // UDP length field (header + payload)
    pub ssrc: u32,          // RTP synchronisation source identifier
    pub rtp_timestamp: u32, // RTP media clock timestamp
    pub seq_num: u16,       // RTP sequence number
    pub payload_type: u8,   // RTP PT (lower 7 bits of byte 1)
    pub marker: bool,       // RTP marker bit (top bit of byte 1)
}

/// Parse a raw Ethernet `data` slice into an `RtpRecord`.
///
/// Caller must have already verified via `quick_precheck` that:
/// - `ip_start` points at a valid IPv4 or IPv6 header
/// - `udp_payload_offset` points at the first byte after the 8-byte UDP header
///
/// Returns `None` if there are fewer than 12 bytes of RTP payload available.
pub fn parse_rtp_record(
    data: &[u8],
    is_ipv6: bool,
    ip_start: usize,
    udp_payload_offset: usize,
    ts: Duration,
) -> Option<RtpRecord> {
    // RTP fixed header is 12 bytes
    if udp_payload_offset + 12 > data.len() {
        return None;
    }

    // ── UDP header fields (8 bytes immediately before the payload) ────────
    let udp_hdr = udp_payload_offset - 8;
    let src_port = u16::from_be_bytes([data[udp_hdr], data[udp_hdr + 1]]);
    let dst_port = u16::from_be_bytes([data[udp_hdr + 2], data[udp_hdr + 3]]);
    let udp_len = u16::from_be_bytes([data[udp_hdr + 4], data[udp_hdr + 5]]);

    // ── IP address strings + total IP length ─────────────────────────────
    let (src_ip, dst_ip, ip_len) = if is_ipv6 {
        let src = std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&data[ip_start + 8..ip_start + 24]).unwrap(),
        )
        .to_string();
        let dst = std::net::Ipv6Addr::from(
            <[u8; 16]>::try_from(&data[ip_start + 24..ip_start + 40]).unwrap(),
        )
        .to_string();
        // IPv6 payload length does not include the 40-byte fixed header
        let payload_len = u16::from_be_bytes([data[ip_start + 4], data[ip_start + 5]]);
        (src, dst, payload_len + 40)
    } else {
        let src = std::net::Ipv4Addr::new(
            data[ip_start + 12],
            data[ip_start + 13],
            data[ip_start + 14],
            data[ip_start + 15],
        )
        .to_string();
        let dst = std::net::Ipv4Addr::new(
            data[ip_start + 16],
            data[ip_start + 17],
            data[ip_start + 18],
            data[ip_start + 19],
        )
        .to_string();
        let len = u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]);
        (src, dst, len)
    };

    // ── RTP fixed header (bytes 0-11 of UDP payload) ──────────────────────
    let rtp = &data[udp_payload_offset..];
    let payload_type = rtp[1] & 0x7F; // lower 7 bits
    let marker = (rtp[1] & 0x80) != 0; // top bit
    let seq_num = u16::from_be_bytes([rtp[2], rtp[3]]);
    let rtp_timestamp = u32::from_be_bytes([rtp[4], rtp[5], rtp[6], rtp[7]]);
    let ssrc = u32::from_be_bytes([rtp[8], rtp[9], rtp[10], rtp[11]]);

    Some(RtpRecord {
        arrival_epoch_ns: ts.as_nanos() as u64,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ip_proto: 17,
        ip_len,
        udp_len,
        ssrc,
        rtp_timestamp,
        seq_num,
        payload_type,
        marker,
    })
}
