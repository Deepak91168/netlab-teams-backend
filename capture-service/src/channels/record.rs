//! # channels/record.rs
//!
//! **SHARED, generic RTP-record sink.**
//!
//! Reusable infrastructure that every RTP-based platform needs:
//!   1. writes each [`RtpRecord`] as a CSV row,
//!   2. de-duplicates retransmitted RTP packets with a 64-entry sliding
//!      window per SSRC,
//!   3. accumulates surviving records into [`Batch`]es and forwards them to a
//!      platform-supplied session queue (`batch_tx`).
//!
//! Everything that used to be Teams-specific has been parameterised:
//!   - the **CSV path** is passed in,
//!   - a **label** is used only for log lines,
//!   - counters live in a per-instance [`RecordStats`] (shared via `Arc` with
//!     the owning platform) instead of global atomics,
//!   - batches are pushed to an injected `Sender<Batch>` rather than a global.
//!
//! ## Batching state-machine
//!
//! ```text
//!  loop:
//!    recv_timeout(BATCH_WINDOW)
//!      ├── Ok(Record)  → write CSV, push to pending
//!      │                 if pending.len() >= BATCH_SIZE → flush (size trigger)
//!      ├── Err(Timeout)→ flush pending if non-empty     (time trigger, 5 s)
//!      └── Ok(Shutdown)→ flush pending, send sentinel, break
//! ```
//!
//! ## Shutdown protocol with the session layer
//! On shutdown the thread flushes any partial batch and then sends an **empty
//! `Batch`** (zero records) as a sentinel.  Session workers treat an empty
//! batch as "flush and stop".  A normal flush never produces an empty batch,
//! so the sentinel is unambiguous.

use crate::models::RtpRecord;
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Records per full batch (size trigger).
pub const BATCH_SIZE: usize = 5_000;

/// Maximum time to wait before flushing a partial batch to the session queue.
const BATCH_WINDOW: Duration = Duration::from_secs(5);

/// A unit of work handed to a platform's session engine.
///
/// An empty `records` vector is the shutdown sentinel (see module docs).
pub struct Batch {
    pub records: Vec<RtpRecord>,
    pub seq: u64,
}

/// Per-instance counters for one record sink.  Shared (`Arc`) between the
/// records thread that increments them and the platform that reports them.
#[derive(Default)]
pub struct RecordStats {
    csv_records: AtomicUsize,       // rows written to CSV
    record_drops: AtomicUsize,      // lost: inbound channel full
    batch_drops: AtomicUsize,       // lost: session queue full
    duplicate_records: AtomicUsize, // dropped RTP duplicates
}

impl RecordStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn csv_records(&self) -> usize {
        self.csv_records.load(Ordering::Relaxed)
    }
    pub fn record_drops(&self) -> usize {
        self.record_drops.load(Ordering::Relaxed)
    }
    pub fn batch_drops(&self) -> usize {
        self.batch_drops.load(Ordering::Relaxed)
    }
    pub fn duplicate_records(&self) -> usize {
        self.duplicate_records.load(Ordering::Relaxed)
    }
    /// Called from the capture hot-path when the inbound channel is full.
    pub fn inc_record_drops(&self) {
        self.record_drops.fetch_add(1, Ordering::Relaxed);
    }
}

/// Messages sent from the capture cores to a records thread.
pub enum RecordMessage {
    /// One parsed RTP record from the capture hot-path.
    Record(RtpRecord),
    /// Sent once by the owning platform on shutdown — flush and exit.
    Shutdown,
}

/// Spawn a records thread.  Returns the inbound sender (store on the platform)
/// and the thread's [`JoinHandle`].
pub fn spawn_record_writer(
    csv_path: impl Into<String>,
    label: impl Into<String>,
    capacity: usize,
    batch_tx: Sender<Batch>,
    stats: Arc<RecordStats>,
) -> (Sender<RecordMessage>, JoinHandle<()>) {
    let (tx, rx) = bounded::<RecordMessage>(capacity);
    let csv_path = csv_path.into();
    let label = label.into();
    let handle = thread::spawn(move || records_thread(rx, csv_path, label, batch_tx, stats));
    (tx, handle)
}

/// Move `pending` into a [`Batch`] and push it to the session queue.
/// No effect if `pending` is empty.
fn flush_batch(
    pending: &mut Vec<RtpRecord>,
    seq: &mut u64,
    reason: &str,
    label: &str,
    batch_tx: &Sender<Batch>,
    stats: &RecordStats,
) {
    if pending.is_empty() {
        return;
    }

    *seq += 1;
    let n = pending.len();
    let records = std::mem::replace(pending, Vec::with_capacity(BATCH_SIZE));

    if batch_tx.try_send(Batch { records, seq: *seq }).is_ok() {
        println!("[{label}][batch] #{} dispatched — {n} records ({reason})", *seq);
    } else {
        stats.batch_drops.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[WARN][{label}] Session queue full — dropped batch #{} ({n} records, {reason})",
            *seq
        );
    }
}

fn records_thread(
    rx: Receiver<RecordMessage>,
    csv_path: String,
    label: String,
    batch_tx: Sender<Batch>,
    stats: Arc<RecordStats>,
) {
    // ── CSV writer ────────────────────────────────────────────────────────
    let file = File::create(&csv_path)
        .unwrap_or_else(|e| panic!("Failed to create CSV file {csv_path}: {e}"));
    let mut writer = BufWriter::with_capacity(8 * 1024 * 1024, file);
    writeln!(
        writer,
        "arrival_epoch_ns,src_ip,dst_ip,ip_proto,ip_len,src_port,dst_port,udp_len,\
         rtp_ssrc,rtp_timestamp,rtp_seq,rtp_pt,rtp_marker"
    )
    .unwrap();

    // ── Session batch accumulator ─────────────────────────────────────────
    let mut pending: Vec<RtpRecord> = Vec::with_capacity(BATCH_SIZE);
    let mut seq: u64 = 0;

    // ── Deduplication state (SSRC -> (max_seq, window_bitmask)) ───────────
    let mut dedup_map: HashMap<u32, (u16, u64)> = HashMap::new();

    loop {
        match rx.recv_timeout(BATCH_WINDOW) {
            // ── New record ────────────────────────────────────────────────
            Ok(RecordMessage::Record(r)) => {
                // 1. Sliding window deduplication
                let is_duplicate = match dedup_map.get_mut(&r.ssrc) {
                    None => {
                        dedup_map.insert(r.ssrc, (r.seq_num, 1));
                        false
                    }
                    Some((max_seq, window)) => {
                        if r.seq_num == *max_seq {
                            true // Exact duplicate of the highest sequence number seen
                        } else {
                            // Handle 16-bit wraparound using standard modular arithmetic
                            let diff = r.seq_num.wrapping_sub(*max_seq) as i16;

                            if diff > 0 {
                                // rtp_seq is newer
                                if diff >= 64 {
                                    // Shift out the entire window
                                    *window = 1;
                                } else {
                                    *window = (*window << diff) | 1;
                                }
                                *max_seq = r.seq_num;
                                false
                            } else {
                                // rtp_seq is older
                                let offset = (-diff) as u16;
                                if offset >= 64 {
                                    // Too old, out of our 64-packet window, drop it to be safe.
                                    true
                                } else {
                                    let bit = 1u64 << offset;
                                    if (*window & bit) != 0 {
                                        true // We already saw this sequence number
                                    } else {
                                        *window |= bit;
                                        false
                                    }
                                }
                            }
                        }
                    }
                };

                if is_duplicate {
                    stats.duplicate_records.fetch_add(1, Ordering::Relaxed);
                    continue; // Skip CSV and session batch for this duplicate
                }

                // 2. CSV row
                let _ = writeln!(
                    writer,
                    "{},{},{},{},{},{},{},{},0x{:08X},{},{},{},{}",
                    r.arrival_epoch_ns,
                    r.src_ip,
                    r.dst_ip,
                    r.ip_proto,
                    r.ip_len,
                    r.src_port,
                    r.dst_port,
                    r.udp_len,
                    r.ssrc,
                    r.rtp_timestamp,
                    r.seq_num,
                    r.payload_type,
                    if r.marker { 1 } else { 0 }
                );
                stats.csv_records.fetch_add(1, Ordering::Relaxed);

                // 3. Accumulate for session layer
                pending.push(r);

                // Size trigger — batch is full, send immediately
                if pending.len() >= BATCH_SIZE {
                    flush_batch(
                        &mut pending,
                        &mut seq,
                        "size limit",
                        &label,
                        &batch_tx,
                        &stats,
                    );
                }
            }

            // ── 5-second window elapsed — send whatever we have ───────────
            Err(RecvTimeoutError::Timeout) => {
                flush_batch(
                    &mut pending,
                    &mut seq,
                    "5s timeout",
                    &label,
                    &batch_tx,
                    &stats,
                );
            }

            // ── Shutdown — flush partial batch then exit ──────────────────
            Ok(RecordMessage::Shutdown) => {
                flush_batch(
                    &mut pending,
                    &mut seq,
                    "shutdown",
                    &label,
                    &batch_tx,
                    &stats,
                );
                // Sentinel: empty batch tells the session worker to stop.
                let _ = batch_tx.send(Batch {
                    records: Vec::new(),
                    seq: 0,
                });
                break;
            }

            // ── Sender dropped (should not happen before Shutdown) ────────
            Err(RecvTimeoutError::Disconnected) => {
                flush_batch(
                    &mut pending,
                    &mut seq,
                    "disconnected",
                    &label,
                    &batch_tx,
                    &stats,
                );
                let _ = batch_tx.send(Batch {
                    records: Vec::new(),
                    seq: 0,
                });
                break;
            }
        }
    }

    let _ = writer.flush();
    println!(
        "[INFO][{label}] Records thread exiting — {} batches dispatched, {} batch drops.",
        seq,
        stats.batch_drops()
    );
}
