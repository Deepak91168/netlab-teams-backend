//! # channels/pcap.rs
//!
//! **SHARED, generic PCAP sink.**
//!
//! A reusable bounded MPSC channel + writer thread that appends captured
//! frames to a PCAP file.  Unlike the original Teams-only implementation this
//! is fully parameterised:
//!
//! - the **output path** is passed in (so Teams writes
//!   `teams_traffic_rtp.pcap`, Google Meet `google_meet_traffic_rtp.pcap`, …),
//! - the **sender** is returned to the caller instead of being stored in a
//!   global, so every platform owns its own independent sink.
//!
//! The hot path pushes [`Message::Packet`] via `try_send` (never blocks — a
//! full channel drops the frame).  `Message::Shutdown` tells the writer to
//! flush and exit.

use crossbeam_channel::{bounded, Receiver, Sender};
use pcap_file::pcap::{PcapPacket, PcapWriter};
use std::fs::File;
use std::io::BufWriter;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Maximum Ethernet frame size we will ever capture.
/// 1536 = 1500 (MTU) + 36 bytes of headers/tags headroom.
pub const MAX_PACKET_SIZE: usize = 1536;

/// A captured Ethernet frame, stored in a fixed-size stack buffer.
/// Using a fixed array avoids a heap allocation per packet on the hot path.
pub struct CapturedPacket {
    pub buf: [u8; MAX_PACKET_SIZE],
    pub len: usize,   // actual frame length (<= MAX_PACKET_SIZE)
    pub ts: Duration, // wall-clock timestamp at capture time
}

/// Messages sent from the capture cores to a PCAP writer thread.
pub enum Message {
    /// An RTP frame to be written to the output PCAP.
    Packet(CapturedPacket),
    /// Signals the writer thread to flush all pending writes and exit.
    Shutdown,
}

/// Spawn a PCAP writer thread that drains the returned channel and writes
/// frames to `pcap_path`.
///
/// Returns the sender half (store it on the platform) and the writer's
/// [`JoinHandle`] (join it during shutdown).
pub fn spawn_pcap_writer(
    pcap_path: impl Into<String>,
    capacity: usize,
) -> (Sender<Message>, JoinHandle<()>) {
    let (tx, rx) = bounded::<Message>(capacity);
    let path = pcap_path.into();
    let handle = thread::spawn(move || writer_thread(rx, path));
    (tx, handle)
}

/// Drains the PCAP channel and writes frames to `pcap_path`.
/// Runs until it receives [`Message::Shutdown`], then flushes and returns.
fn writer_thread(rx: Receiver<Message>, pcap_path: String) {
    let file = File::create(&pcap_path)
        .unwrap_or_else(|e| panic!("Failed to create output PCAP file {pcap_path}: {e}"));
    // 8 MB write buffer — reduces syscall overhead at high packet rates
    let buf = BufWriter::with_capacity(8 * 1024 * 1024, file);
    let mut writer = PcapWriter::new(buf).expect("Failed to init PCAP writer");

    while let Ok(msg) = rx.recv() {
        match msg {
            Message::Shutdown => break,
            Message::Packet(cap) => {
                let pkt = PcapPacket::new(cap.ts, cap.len as u32, &cap.buf[..cap.len]);
                if let Err(e) = writer.write_packet(&pkt) {
                    eprintln!("[WARN] PCAP write error ({pcap_path}): {e}");
                }
            }
        }
    }

    println!("[INFO] PCAP writer flushed and exiting ({pcap_path}).");
}
