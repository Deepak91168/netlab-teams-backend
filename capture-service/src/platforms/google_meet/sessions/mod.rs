//! # platforms/google_meet/sessions/
//!
//! **Google Meet-owned session identification, management and metrics —
//! SCAFFOLD.**
//!
//! This is where the Google Meet implementer will add, fully isolated from
//! Teams:
//!   - session identification (how a Meet call maps to a client/session id),
//!   - session management (lifecycle, timeouts, binning),
//!   - media metrics (FPS, jitter, bitrate, …),
//!   - network metrics (throughput, loss, …),
//!   - any exporter (InfluxDB or otherwise).
//!
//! The shared infrastructure to build on is already in place:
//!   - [`crate::channels::record::Batch`] — the unit of work a session worker
//!     consumes (an empty `Batch` is the shutdown sentinel),
//!   - [`crate::channels::record::spawn_record_writer`] — CSV + de-dup +
//!     batching, parameterised by output path,
//!   - [`crate::channels::pcap::spawn_pcap_writer`] — per-platform PCAP sink,
//!   - [`crate::models::RtpRecord`] — the parsed record type.
//!
//! See `platforms::teams::sessions` for a complete, working reference
//! implementation to model the Google Meet version on.
//!
//! Intentionally empty for now — adding a `session_worker(rx: Receiver<Batch>)`
//! here and wiring it up in [`super`] is all that is required, with no changes
//! to Teams or to the shared layers.

// TODO(google_meet): add `media_metrics`, `network_metrics`, the session
//                     engine, and `session_worker(rx: Receiver<Batch>)`.
