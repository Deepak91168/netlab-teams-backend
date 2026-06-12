//! # channels/
//!
//! Two bounded MPSC channels that decouple the capture cores from I/O.
//!
//! | Module   | Channel carries  | Writer thread    | Output file              |
//! |----------|-----------------|------------------|--------------------------|
//! | packet   | raw frame bytes | `writer_thread`  | teams_traffic_rtp.pcap   |
//! | record   | parsed RtpRecord| `records_thread` | teams_rtp_records.csv    |
//!
//! Both channels are initialised once in `main` via `init_*_channel()`.
//! The sender halves are stored in `OnceLock` statics so the hot-path
//! (`process_packet`) can reach them without passing references around.

pub mod packet;
pub mod record;

pub use packet::{
    CapturedPacket, MAX_PACKET_SIZE, Message, PACKET_TX, init_packet_channel, writer_thread,
};
pub use record::{RECORD_TX, RecordMessage, init_record_channel, records_thread};
