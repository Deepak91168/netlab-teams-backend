//! # platforms/google_meet/
//!
//! **The Google Meet platform — INERT SCAFFOLD.**
//!
//! Provides the complete module skeleton for a future Google Meet
//! implementation, wired into the shared pipeline through the same
//! [`Platform`] trait as Teams — but deliberately *inert*:
//!
//!   - [`classify`] returns `false` for every packet (Google ranges not yet
//!     filled in), so the dispatcher never routes anything here, and
//!   - [`GoogleMeetPlatform::handle_packet`] is a no-op.
//!
//! As a result, registering Google Meet has **zero effect** on the live Teams
//! pipeline — exactly what we want until the implementer is ready.  No worker
//! threads, files, or channels are created.
//!
//! ## What the implementer adds (without touching Teams or the shared layers)
//!   1. Fill in [`ip_ranges`] with Google's media ranges → [`classify`] starts
//!      matching real traffic.
//!   2. In [`GoogleMeetPlatform::start`], spawn this platform's own
//!      `spawn_pcap_writer` / `spawn_record_writer` / session worker (model on
//!      `platforms::teams`), writing `google_meet_traffic_rtp.pcap` and
//!      `google_meet_rtp_records.csv`.
//!   3. Implement [`sessions`] (session id/management + media/network metrics).
//!   4. Replace the no-op `handle_packet` with the real protocol handling.
//!
//! The registration line in `platforms::register_all` already adds Google Meet
//! after Teams; nothing else needs to change.

pub mod classify;
pub mod ip_ranges;
pub mod sessions;

use crate::capture::ParsedPacket;
use crate::framework::{Platform, PlatformSnapshot};
use std::sync::Arc;

/// File-name prefix reserved for this platform's future sinks
/// (`google_meet_traffic_rtp.pcap`, `google_meet_rtp_records.csv`).
const PLATFORM_NAME: &str = "google_meet";

/// The Google Meet platform.  Currently a stateless, inert scaffold; it will
/// gain channel senders and worker-thread handles (like `TeamsPlatform`) once
/// implemented.
pub struct GoogleMeetPlatform {
    // TODO(google_meet): add packet_tx / record_tx / counters / record_stats /
    //                    handles / shutdown flag, mirroring `TeamsPlatform`.
}

impl GoogleMeetPlatform {
    /// Construct the (inert) Google Meet platform.
    ///
    /// Spawns no threads and opens no files while inert, so it cannot affect
    /// the Teams pipeline.  When implemented, this is where the Google Meet
    /// worker threads will be started (see module docs).
    pub fn start() -> Arc<dyn Platform> {
        Arc::new(GoogleMeetPlatform {})
    }
}

impl Platform for GoogleMeetPlatform {
    fn name(&self) -> &'static str {
        PLATFORM_NAME
    }

    /// SCAFFOLD: never claims a packet until `ip_ranges` is implemented.
    #[inline(always)]
    fn classify(&self, pkt: &ParsedPacket) -> bool {
        classify::is_google_meet(pkt)
    }

    /// SCAFFOLD: no-op.  Unreachable while `classify` returns `false`; left as
    /// the obvious place to add Google Meet packet processing.
    #[inline(always)]
    fn handle_packet(&self, _pkt: &ParsedPacket) {
        // TODO(google_meet): process the packet (protocol demux, keep RTP,
        //                    push to this platform's PCAP / CSV / session
        //                    sinks), mirroring `TeamsPlatform::handle_packet`.
    }

    /// SCAFFOLD: nothing to flush or join yet.
    fn shutdown(&self) {
        // TODO(google_meet): send Shutdown to this platform's channels and
        //                    join its worker threads, mirroring Teams.
    }

    fn snapshot(&self) -> PlatformSnapshot {
        PlatformSnapshot {
            name: PLATFORM_NAME,
            ..PlatformSnapshot::default()
        }
    }

    fn print_final_stats(&self) {
        println!("\n── Platform: Google Meet ──────────────────────────────");
        println!("  (scaffold — not yet implemented; no packets processed)");
    }
}
