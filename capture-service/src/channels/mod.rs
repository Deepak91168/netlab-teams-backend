//! # channels/
//!
//! **SHARED, generic I/O sinks** that decouple the capture cores from disk and
//! from the session layer.  Both are now vendor-neutral and instantiated
//! per-platform (each platform passes its own output paths and owns its own
//! sender), so two platforms never contend for one file or one global channel.
//!
//! | Module   | Channel carries  | Writer thread     | Output file (per platform)   |
//! |----------|------------------|-------------------|------------------------------|
//! | `pcap`   | raw frame bytes  | pcap writer       | `<platform>_traffic_rtp.pcap`|
//! | `record` | parsed RtpRecord | records thread    | `<platform>_rtp_records.csv` |
//!
//! The record sink additionally performs SSRC de-duplication and batches
//! surviving records onto a platform-supplied session queue.

pub mod pcap;
pub mod record;

pub use pcap::{
    spawn_pcap_writer, CapturedPacket, Message as PcapMessage, MAX_PACKET_SIZE,
};
pub use record::{
    spawn_record_writer, Batch, RecordMessage, RecordStats, BATCH_SIZE,
};
