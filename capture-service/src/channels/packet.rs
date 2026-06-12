//! # channels/packet.rs
//!
//! **What this file does:**
//! - Defines `CapturedPacket` — a fixed-size `[u8; 1536]` frame buffer with
//!   length and timestamp, stack-allocated to avoid heap pressure on the hot
//!   path
//! - Defines `Message` — the enum pushed onto the channel:
//!     - `Packet(CapturedPacket)` for every RTP frame
//!     - `Shutdown` to tell the writer to flush and exit
//! - Owns `PACKET_TX`: the global sender half, set once at startup
//! - `init_packet_channel(capacity)` — creates the bounded channel, stores
//!   the sender in `PACKET_TX`, returns the receiver for `writer_thread`
//! - `writer_thread(rx)` — background thread that drains the channel and
//!   appends each frame to `teams_traffic_rtp.pcap` via an 8 MB `BufWriter`

use crossbeam_channel::{Receiver, Sender, bounded};
use pcap_file::{pcap::PcapPacket, pcap::PcapWriter};
use std::fs::File;
use std::io::BufWriter;
use std::sync::OnceLock;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum Ethernet frame size we will ever capture.
/// 1536 = 1500 (MTU) + 36 bytes of headers/tags headroom.
pub const MAX_PACKET_SIZE: usize = 1536;

// ─────────────────────────────────────────────────────────────────────────────
//  Types
// ─────────────────────────────────────────────────────────────────────────────

/// A captured Ethernet frame, stored in a fixed-size stack buffer.
/// Using a fixed array avoids a heap allocation per packet on the hot path.
pub struct CapturedPacket {
    pub buf: [u8; MAX_PACKET_SIZE],
    pub len: usize,   // actual frame length (<= MAX_PACKET_SIZE)
    pub ts: Duration, // wall-clock timestamp at capture time
}

/// Messages sent from the capture cores to the PCAP writer thread.
pub enum Message {
    /// An RTP frame to be written to the output PCAP.
    Packet(CapturedPacket),
    /// Signals the writer thread to flush all pending writes and exit.
    Shutdown,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Global sender
// ─────────────────────────────────────────────────────────────────────────────

/// Sender half of the PCAP channel.  Set once in `main`, read from the
/// capture hot-path via `PACKET_TX.get()`.
pub static PACKET_TX: OnceLock<Sender<Message>> = OnceLock::new();

/// Initialise the PCAP channel.  Must be called exactly once before the
/// retina runtime starts.  Returns the `Receiver` to move into `writer_thread`.
pub fn init_packet_channel(capacity: usize) -> Receiver<Message> {
    let (tx, rx) = bounded::<Message>(capacity);
    PACKET_TX
        .set(tx)
        .expect("Packet channel already initialised");
    rx
}

// ─────────────────────────────────────────────────────────────────────────────
//  Writer thread
// ─────────────────────────────────────────────────────────────────────────────

/// Drains the PCAP channel and writes frames to `teams_traffic_rtp.pcap`.
/// Runs until it receives `Message::Shutdown`, then flushes and returns.
pub fn writer_thread(rx: Receiver<Message>) {
    let file = File::create("teams_traffic_rtp.pcap").expect("Failed to create output PCAP file");
    // 8 MB write buffer — reduces syscall overhead at high packet rates
    let buf = BufWriter::with_capacity(8 * 1024 * 1024, file);
    let mut writer = PcapWriter::new(buf).expect("Failed to init PCAP writer");

    while let Ok(msg) = rx.recv() {
        match msg {
            Message::Shutdown => break,
            Message::Packet(cap) => {
                let pkt = PcapPacket::new(cap.ts, cap.len as u32, &cap.buf[..cap.len]);
                if let Err(e) = writer.write_packet(&pkt) {
                    eprintln!("[WARN] PCAP write error: {e}");
                }
            }
        }
    }

    println!("[INFO] PCAP writer flushed and exiting.");
}
