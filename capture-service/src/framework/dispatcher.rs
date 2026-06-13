//! # framework/dispatcher.rs
//!
//! **The dispatcher / routing layer.**
//!
//! Sits between the single shared capture+parse pipeline and the isolated
//! platforms.  Flow:
//!
//! ```text
//!   NIC → retina → capture callback → dispatch_frame(data)
//!       → capture::parse_frame              (shared parse, once)
//!       → for each registered platform:
//!             if platform.classify(pkt) → platform.handle_packet(pkt); stop
//!       → no match → counted as non-target
//! ```
//!
//! Platforms are registered once at startup (Teams first, then Google Meet,
//! then any future Zoom/Webex/Discord) and stored behind `Arc<dyn Platform>`
//! in a process-global [`OnceLock`].  The capture hot-path reaches the
//! dispatcher through [`dispatch_frame`] without threading any state through
//! the retina filter callback.

use crate::capture::{parse_frame, ParsedPacket};
use crate::framework::platform::Platform;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

/// Process-global dispatcher, installed once in `main`.
static DISPATCHER: OnceLock<Dispatcher> = OnceLock::new();

/// Dispatch-level counters (everything *not* attributable to one platform).
#[derive(Default)]
struct DispatchStats {
    /// Frames that did not parse as UDP-over-IP, or that no platform claimed.
    non_target: AtomicUsize,
}

/// Routes parsed packets to the owning platform.
pub struct Dispatcher {
    platforms: Vec<Arc<dyn Platform>>,
    stats: DispatchStats,
}

impl Dispatcher {
    fn new(platforms: Vec<Arc<dyn Platform>>) -> Self {
        Self {
            platforms,
            stats: DispatchStats::default(),
        }
    }

    /// Route one already-parsed packet.  Returns `true` if a platform claimed
    /// it.
    #[inline(always)]
    fn route(&self, pkt: &ParsedPacket) -> bool {
        for platform in &self.platforms {
            if platform.classify(pkt) {
                platform.handle_packet(pkt);
                return true;
            }
        }
        false
    }

    /// All registered platforms (for shutdown / reporting from `main`).
    pub fn platforms(&self) -> &[Arc<dyn Platform>] {
        &self.platforms
    }

    /// Frames that parsed but were claimed by no platform, plus frames that
    /// failed to parse.
    pub fn non_target_packets(&self) -> usize {
        self.stats.non_target.load(Ordering::Relaxed)
    }
}

/// Install the process-global dispatcher.  Call exactly once from `main`,
/// before the capture runtime starts.
pub fn install(platforms: Vec<Arc<dyn Platform>>) {
    DISPATCHER
        .set(Dispatcher::new(platforms))
        .ok()
        .expect("Dispatcher already installed");
}

/// Borrow the installed dispatcher (for shutdown / stats from `main`).
pub fn get() -> &'static Dispatcher {
    DISPATCHER.get().expect("Dispatcher not installed")
}

/// **Capture hot-path entry point.**
///
/// Called once per frame from the retina filter callback in `main`.  Parses
/// the frame a single time and routes it to the owning platform.
#[inline(always)]
pub fn dispatch_frame(data: &[u8]) {
    let dispatcher = match DISPATCHER.get() {
        Some(d) => d,
        // Capture started before install — should never happen; count and drop.
        None => return,
    };

    match parse_frame(data) {
        Some(pkt) => {
            if !dispatcher.route(&pkt) {
                dispatcher.stats.non_target.fetch_add(1, Ordering::Relaxed);
            }
        }
        None => {
            dispatcher.stats.non_target.fetch_add(1, Ordering::Relaxed);
        }
    }
}
