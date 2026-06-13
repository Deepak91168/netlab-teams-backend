//! # framework/platform.rs
//!
//! **The platform abstraction layer.**
//!
//! A [`Platform`] is one conferencing vendor (Microsoft Teams, Google Meet,
//! Zoom, …).  Each platform owns *everything* vendor-specific behind this
//! single trait:
//!
//!   - **Traffic classification** — [`Platform::classify`] decides, from a
//!     parsed packet, whether the packet belongs to this platform.
//!   - **Packet processing**      — [`Platform::handle_packet`] runs the
//!     vendor's protocol rules and feeds its own PCAP / CSV / session sinks.
//!   - **Session identification & management, media & network metrics** — live
//!     in the worker threads the platform spawns at construction and tears down
//!     in [`Platform::shutdown`].
//!
//! A `Platform` is a *lightweight hot-path front end*: `classify` and
//! `handle_packet` take `&self` and must be cheap and lock-free, pushing work
//! to background threads via channels.  All heavy, stateful logic (sessions,
//! metrics, exporters) lives on those threads, exactly as in the original
//! Teams design.  Because `handle_packet` is called concurrently from every
//! capture core, implementors must be `Send + Sync` and use only interior
//! mutability (channels / atomics) on the hot path.

use crate::capture::ParsedPacket;

/// A point-in-time summary of a platform's counters, used by the live stats
/// thread.  Kept deliberately small and cheap to produce.
#[derive(Clone, Debug, Default)]
pub struct PlatformSnapshot {
    pub name: &'static str,
    pub rtp_packets: usize,
    pub dropped_packets: usize,
    pub csv_records: usize,
    pub duplicate_records: usize,
}

/// One conferencing platform plugged into the shared capture pipeline.
///
/// Object-safe: stored behind `Arc<dyn Platform>` in the dispatcher and shared
/// with `main` for shutdown / reporting.
pub trait Platform: Send + Sync {
    /// Stable identifier, also used as the prefix for this platform's output
    /// files (e.g. `"teams"` → `teams_traffic_rtp.pcap`).
    fn name(&self) -> &'static str;

    /// Hot-path classification: does this packet belong to this platform?
    ///
    /// Must be cheap (typically an IP-range check on the zero-copy
    /// `pkt.src_ip` / `pkt.dst_ip` slices).  The dispatcher calls this for
    /// each registered platform in order and routes to the first match.
    fn classify(&self, pkt: &ParsedPacket) -> bool;

    /// Hot-path processing for a packet this platform claimed in `classify`.
    ///
    /// The platform applies its own protocol rules (e.g. RFC 7983 demux, keep
    /// only RTP) and pushes work to its own background sinks.  Must not block.
    fn handle_packet(&self, pkt: &ParsedPacket);

    /// Flush and stop all of this platform's worker threads.  Called exactly
    /// once at shutdown.  Implementations use interior mutability to take and
    /// join their thread handles, and must be safe to call through `&self`.
    fn shutdown(&self);

    /// Cheap counter snapshot for the periodic live stats line.
    fn snapshot(&self) -> PlatformSnapshot;

    /// Print this platform's detailed end-of-run statistics block.
    fn print_final_stats(&self);
}
