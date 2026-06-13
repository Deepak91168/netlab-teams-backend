//! # platforms/
//!
//! **The platform registry — the one place you edit to add a vendor.**
//!
//! Each subdirectory is one fully-isolated conferencing platform implementing
//! the shared [`crate::framework::Platform`] trait:
//!   - [`teams`]       — Microsoft Teams (complete; the original implementation
//!                       moved verbatim behind the trait),
//!   - [`google_meet`] — Google Meet (inert scaffold; ready to implement).
//!
//! A platform owns *all* of its vendor-specific logic — classification rules,
//! session identification and management, packet processing, media and network
//! metrics, and its own PCAP/CSV/exporter sinks.  Platforms never reference one
//! another; the only shared code is the generic `capture`, `channels`,
//! `models` and `framework` layers.
//!
//! ## Adding a new platform (e.g. Zoom, Webex, Discord)
//!   1. Create `platforms/zoom/` with its own `classify`, `ip_ranges`,
//!      `sessions`, and a `ZoomPlatform` implementing `Platform::start`.
//!   2. Add `pub mod zoom;` below.
//!   3. Add **one line** to [`register_all`]: `platforms.push(zoom::ZoomPlatform::start());`
//!
//! No existing platform and no shared layer needs to change.

pub mod google_meet;
pub mod teams;

use crate::framework::Platform;
use std::sync::Arc;

/// Build and return every platform, in dispatch (classification) order.
///
/// The dispatcher tries platforms in this order and routes each packet to the
/// first one whose `classify` claims it, so more-specific or higher-priority
/// platforms should come first.  Teams is registered first to preserve its
/// exact original behaviour; Google Meet follows as an inert scaffold.
///
/// Calling this spawns each (non-inert) platform's worker threads, so call it
/// exactly once at startup and hand the result to
/// [`crate::framework::dispatcher::install`].
pub fn register_all() -> Vec<Arc<dyn Platform>> {
    let mut platforms: Vec<Arc<dyn Platform>> = Vec::new();

    // Microsoft Teams — fully implemented; must stay first and unchanged.
    platforms.push(teams::TeamsPlatform::start());

    // Google Meet — inert scaffold; claims nothing until implemented.
    platforms.push(google_meet::GoogleMeetPlatform::start());

    // Future platforms (Zoom, Webex, Discord, …) register here with one line
    // each, e.g.:
    //     platforms.push(zoom::ZoomPlatform::start());

    platforms
}
