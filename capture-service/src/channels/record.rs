//! # channels/record.rs
//!
//! **What this file does:**
//! - Receives `RtpRecord`s from the capture cores via `RECORD_TX`
//! - For every record:
//!     1. Writes a CSV row immediately (unchanged from original)
//!     2. Clones it into a `pending` accumulator for the session layer
//! - Flushes `pending` as a `Batch` to the session queue under two conditions:
//!     - **Size trigger** : `pending.len() >= BATCH_SIZE` (5 000 records)
//!     - **Time trigger**  : 5 seconds have elapsed since the last flush,
//!                           regardless of how many records accumulated
//!   Whichever fires first wins.  The time trigger uses `recv_timeout` so no
//!   extra ticker thread is needed.
//! - On `Shutdown`, flushes whatever partial batch remains then exits.
//!
//! ## Batching state-machine
//!
//! ```
//!  loop:
//!    recv_timeout(BATCH_WINDOW)
//!      ├── Ok(Record)  → write CSV, push to pending
//!      │                 if pending.len() >= BATCH_SIZE → flush (size trigger)
//!      ├── Err(Timeout)→ flush pending if non-empty     (time trigger, 5 s)
//!      └── Ok(Shutdown)→ flush pending, break
//! ```

use crate::models::RtpRecord;
use crate::sessions::{BATCH_SIZE, Batch, push_batch, push_shutdown_batch};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
//  Timing constant
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum time to wait before flushing a partial batch to the session queue.
/// Whatever packets arrived in this window are sent immediately, even if the
/// batch is smaller than `BATCH_SIZE`.
const BATCH_WINDOW: Duration = Duration::from_secs(5);

// ─────────────────────────────────────────────────────────────────────────────
//  Counters
// ─────────────────────────────────────────────────────────────────────────────
static CSV_RECORDS: AtomicUsize = AtomicUsize::new(0); // rows written to CSV
static RECORD_DROPS: AtomicUsize = AtomicUsize::new(0); // lost: inbound channel full
static BATCH_DROPS: AtomicUsize = AtomicUsize::new(0); // lost: session queue full
static DUPLICATE_RECORDS: AtomicUsize = AtomicUsize::new(0); // dropped RTP duplicates

/// Total CSV rows written so far.
pub fn csv_records() -> usize {
    CSV_RECORDS.load(Ordering::Relaxed)
}
/// Records dropped because the inbound `RECORD_TX` channel was full.
pub fn record_drops() -> usize {
    RECORD_DROPS.load(Ordering::Relaxed)
}
/// Batches dropped because the session queue was full.
pub fn batch_drops() -> usize {
    BATCH_DROPS.load(Ordering::Relaxed)
}
/// Duplicate records dropped in the record thread.
pub fn duplicate_records() -> usize {
    DUPLICATE_RECORDS.load(Ordering::Relaxed)
}
/// Called from `process_packet` in main.rs on `try_send` failure.
pub fn inc_record_drops() {
    RECORD_DROPS.fetch_add(1, Ordering::Relaxed);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Message type
// ─────────────────────────────────────────────────────────────────────────────
pub enum RecordMessage {
    /// One parsed RTP record from the capture hot-path.
    Record(RtpRecord),
    /// Sent once by `main` after the runtime stops — flush and exit.
    Shutdown,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Global inbound sender
// ─────────────────────────────────────────────────────────────────────────────
pub static RECORD_TX: OnceLock<Sender<RecordMessage>> = OnceLock::new();

/// Initialise the inbound record channel.  Call once from `main`.
/// Returns the `Receiver` to move into `records_thread`.
pub fn init_record_channel(capacity: usize) -> Receiver<RecordMessage> {
    let (tx, rx) = bounded::<RecordMessage>(capacity);
    RECORD_TX
        .set(tx)
        .expect("Record channel already initialised");
    rx
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal helper — move pending into a Batch and push to session queue
//  Has no effect if pending is empty (common on a quiet 5-second window).
// ─────────────────────────────────────────────────────────────────────────────
fn flush_batch(pending: &mut Vec<RtpRecord>, seq: &mut u64, reason: &str) {
    if pending.is_empty() {
        return;
    }

    *seq += 1;
    let n = pending.len();
    let records = std::mem::replace(pending, Vec::with_capacity(BATCH_SIZE));

    if push_batch(Batch { records, seq: *seq }) {
        println!("[batch] #{} dispatched — {n} records ({reason})", *seq);
    } else {
        BATCH_DROPS.fetch_add(1, Ordering::Relaxed);
        eprintln!(
            "[WARN] Session queue full — dropped batch #{} ({n} records, {reason})",
            *seq
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  records_thread
// ─────────────────────────────────────────────────────────────────────────────
pub fn records_thread(rx: Receiver<RecordMessage>) {
    // ── CSV writer (unchanged from original) ──────────────────────────────
    let file = File::create("teams_rtp_records.csv").expect("Failed to create CSV file");
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
                    DUPLICATE_RECORDS.fetch_add(1, Ordering::Relaxed);
                    continue; // Skip CSV and session batch for this duplicate
                }

                // 2. CSV row (original, unchanged)
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
                CSV_RECORDS.fetch_add(1, Ordering::Relaxed);

                // 3. Accumulate for session layer
                pending.push(r);

                // Size trigger — batch is full, send immediately
                if pending.len() >= BATCH_SIZE {
                    flush_batch(&mut pending, &mut seq, "size limit");
                }
            }

            // ── 5-second window elapsed — send whatever we have ───────────
            Err(RecvTimeoutError::Timeout) => {
                flush_batch(&mut pending, &mut seq, "5s timeout");
            }

            // ── Shutdown — flush partial batch then exit ──────────────────
            Ok(RecordMessage::Shutdown) => {
                flush_batch(&mut pending, &mut seq, "shutdown");
                push_shutdown_batch();
                break;
            }

            // ── Sender dropped (should not happen before Shutdown) ────────
            Err(RecvTimeoutError::Disconnected) => {
                flush_batch(&mut pending, &mut seq, "disconnected");
                push_shutdown_batch();
                break;
            }
        }
    }

    let _ = writer.flush();
    println!(
        "[INFO] Records thread exiting — {} batches dispatched, {} batch drops.",
        seq,
        batch_drops()
    );
}
