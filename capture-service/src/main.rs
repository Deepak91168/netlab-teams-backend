//! # capture-service — main.rs
//!
//! **What this file does:**
//! - Declares all submodules (`channels`, `ip_ranges`, `models`, `protocol`)
//! - Owns all the per-protocol packet counters (atomics) — one place to read
//!   them at shutdown, one place to increment them in `process_packet`
//! - `send_packet`   — copies raw bytes into a fixed buffer and pushes to the
//!                     PCAP writer channel
//! - `process_packet` — the hot-path dispatcher: calls `quick_precheck` then
//!                      `identify_protocol`, routes RTP to both channels,
//!                      increments counters for every outcome
//! - `capture_teams_udp` — the `#[filter("udp")]` callback retina calls per
//!                         packet; MUST live in the crate root (proc-macro
//!                         restriction)
//! - `stats_thread`  — prints a live summary line every 15 s
//! - `main`          — CLI parse, channel init, thread spawn, runtime run,
//!                     graceful shutdown, final stats print

mod channels;
mod ip_ranges;
mod models;
mod protocol;
mod sessions;

use channels::record::{batch_drops, csv_records, inc_record_drops, record_drops};
use channels::{
    CapturedPacket, MAX_PACKET_SIZE, Message, PACKET_TX, RECORD_TX, RecordMessage,
    init_packet_channel, init_record_channel, records_thread, writer_thread,
};
use clap::Parser;
use ip_ranges::quick_precheck;
use models::parse_rtp_record;
use protocol::identify_protocol;
use retina_core::{CoreId, Runtime, config::load_config};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};


// to stop the process
static RUNNING: AtomicBool = AtomicBool::new(true);


// ─────────────────────────────────────────────────────────────────────────────
//  Packet-level counters
//  (CSV_RECORDS and RECORD_DROPS live in channels::record alongside the
//   thread that owns them; accessed here via csv_records() / record_drops())
// ─────────────────────────────────────────────────────────────────────────────
static TEAMS_PACKETS: AtomicUsize = AtomicUsize::new(0); // RTP pkts queued to PCAP writer
static FILTERED_PACKETS: AtomicUsize = AtomicUsize::new(0); // non-Teams IP, discarded early
static DROPPED_PACKETS: AtomicUsize = AtomicUsize::new(0); // PCAP channel full, pkt lost
static IPV4_PACKETS: AtomicUsize = AtomicUsize::new(0); // Teams UDP via IPv4
static IPV6_PACKETS: AtomicUsize = AtomicUsize::new(0); // Teams UDP via IPv6
static STUN_FILTERED: AtomicUsize = AtomicUsize::new(0);
static DTLS_FILTERED: AtomicUsize = AtomicUsize::new(0);
static QUIC_FILTERED: AtomicUsize = AtomicUsize::new(0);
static RTCP_FILTERED: AtomicUsize = AtomicUsize::new(0);
static RTP_PACKETS: AtomicUsize = AtomicUsize::new(0); // RTP kept (saved to PCAP + CSV)
static UNKNOWN_FILTERED: AtomicUsize = AtomicUsize::new(0);

// ─────────────────────────────────────────────────────────────────────────────
//  send_packet
//  Copies `data` into a fixed-size stack buffer and pushes a `Message::Packet`
//  onto the bounded PCAP channel.  `try_send` never blocks — if the channel is
//  full the packet is counted as dropped and discarded.
// ─────────────────────────────────────────────────────────────────────────────
#[inline(always)]
fn send_packet(data: &[u8], ts: Duration) {
    let len = data.len().min(MAX_PACKET_SIZE);
    let mut buf = [0u8; MAX_PACKET_SIZE];
    buf[..len].copy_from_slice(&data[..len]);

    if let Some(tx) = PACKET_TX.get() {
        if tx
            .try_send(Message::Packet(CapturedPacket { buf, len, ts }))
            .is_ok()
        {
            TEAMS_PACKETS.fetch_add(1, Ordering::Relaxed);
        } else {
            DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  process_packet  (hot path — called from the retina filter callback)
//
//  1. quick_precheck  — Ethernet / IP / UDP / Teams-IP-range gate
//  2. identify_protocol — RFC 7983 demux on the UDP payload
//  3. RTP only: push raw bytes to PCAP channel + parsed record to CSV channel
//  4. Everything else: increment the appropriate discard counter and return
// ─────────────────────────────────────────────────────────────────────────────
#[inline(always)]
fn process_packet(data: &[u8]) {
    match quick_precheck(data) {
        None => {
            // Packet is not Teams UDP — discard before any further work
            FILTERED_PACKETS.fetch_add(1, Ordering::Relaxed);
        }
        Some((is_ipv6, ip_start, udp_payload_offset)) => {
            if is_ipv6 {
                IPV6_PACKETS.fetch_add(1, Ordering::Relaxed);
            } else {
                IPV4_PACKETS.fetch_add(1, Ordering::Relaxed);
            }

            // Guard: UDP payload must exist and have at least 2 bytes for
            // the RFC 7983 first-byte checks to be meaningful
            let udp_payload = if udp_payload_offset < data.len() {
                &data[udp_payload_offset..]
            } else {
                UNKNOWN_FILTERED.fetch_add(1, Ordering::Relaxed);
                return;
            };
            if udp_payload.len() < 2 {
                UNKNOWN_FILTERED.fetch_add(1, Ordering::Relaxed);
                return;
            }

            match identify_protocol(udp_payload) {
                // ── RTP: the only protocol we keep ──────────────────────
                1 => {
                    RTP_PACKETS.fetch_add(1, Ordering::Relaxed);
                    let ts = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::ZERO);

                    // Push raw frame to PCAP writer thread
                    send_packet(data, ts);

                    // Parse and push structured record to CSV writer thread
                    if let Some(record) =
                        parse_rtp_record(data, is_ipv6, ip_start, udp_payload_offset, ts)
                    {
                        if let Some(tx) = RECORD_TX.get() {
                            // try_send: non-blocking — drop the record if
                            // the channel is full rather than stalling the
                            // capture core.
                            if tx.try_send(RecordMessage::Record(record)).is_err() {
                                inc_record_drops();
                            }
                        }
                    }
                }
                // ── Discarded protocols ──────────────────────────────────
                2 => {
                    RTCP_FILTERED.fetch_add(1, Ordering::Relaxed);
                }
                3 => {
                    STUN_FILTERED.fetch_add(1, Ordering::Relaxed);
                }
                4 => {
                    DTLS_FILTERED.fetch_add(1, Ordering::Relaxed);
                }
                5 => {
                    QUIC_FILTERED.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    UNKNOWN_FILTERED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Retina filter callback
//  Must live in the crate root — retina_filtergen expands #[filter] and
//  #[retina_main] into a `SubscribedWrapper` type and a `filter` fn here.
// ─────────────────────────────────────────────────────────────────────────────
#[filter("udp")]
fn capture_teams_udp(packet: &ZcFrame, _core_id: &CoreId) {
    process_packet(packet.data());
}

// ─────────────────────────────────────────────────────────────────────────────
//  stats_thread — prints a one-liner every 15 s so you can watch progress
//  without tailing a log file
// ─────────────────────────────────────────────────────────────────────────────
fn stats_thread() {
    let mut last_rtp = 0usize;
    let mut last_dropped = 0usize;
    let mut elapsed = 0u64;

    loop {
        thread::sleep(Duration::from_secs(15));
        elapsed += 15;

        let rtp = RTP_PACKETS.load(Ordering::Relaxed);
        let dropped = DROPPED_PACKETS.load(Ordering::Relaxed);
        let duplicates = channels::record::duplicate_records();
        let delta = rtp.saturating_sub(last_rtp);
        let new_drops = dropped.saturating_sub(last_dropped);

        println!(
            "[{:5}s] RTP: {:>9} (+{:<7}) | CSV: {} | Dropped: {} | Dups: {}{}",
            elapsed,
            rtp,
            delta,
            csv_records(), // read from channels::record
            dropped,
            duplicates,
            if new_drops > 0 {
                format!("  ⚠️  +{new_drops} NEW DROPS!")
            } else {
                String::new()
            }
        );

        last_rtp = rtp;
        last_dropped = dropped;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  CLI
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, value_name = "FILE")]
    config: PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────────────────────────────────────
#[retina_main(1)]
fn main() {


    println!("Microsoft Teams Campus Traffic Capture (RTP-Only Filter)");
    println!("========================================================");
    println!("Filters: UDP + RFC 7983 Demux — STUN/DTLS/QUIC/RTCP removed, RTP only");

    // Init channels — returns Receivers that are moved into each worker thread
    let packet_rx = init_packet_channel(2_000_000);
    let record_rx = init_record_channel(2_000_000);
    // Batch queue: 64 slots × 5 000 records = up to 320 000 records buffered
    let batch_rx = sessions::init_batch_queue(64);

    let writer_handle = thread::spawn(move || writer_thread(packet_rx));
    let records_handle = thread::spawn(move || records_thread(record_rx));
    // Session processor: runs the batch-processing and InfluxDB export engine
    let session_handle = thread::spawn(move || {
        sessions::session_worker(batch_rx);
        println!("[INFO] Session processor exiting.");
    });
    thread::spawn(stats_thread);

    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run(); // blocks until duration expires or SIGINT

    // ── Graceful shutdown ─────────────────────────────────────────────────
    // Spin until the Shutdown sentinel fits in the PCAP channel (it may be
    // nearly full when the runtime stops).
    println!("\n[INFO] Shutting down — draining packet queue...");
    if let Some(tx) = PACKET_TX.get() {
        loop {
            if tx.try_send(Message::Shutdown).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    // Record channel is smaller / faster to drain; blocking send is fine here
    if let Some(tx) = RECORD_TX.get() {
        let _ = tx.send(RecordMessage::Shutdown);
    }

    writer_handle.join().expect("Writer thread panicked");
    // records_handle exiting drops BATCH_TX → session_worker drains remaining
    // batches, flushes QoE rows, and exits on channel disconnect.
    records_handle.join().expect("Records thread panicked");
    session_handle.join().expect("Session thread panicked");

    // ── Final stats ───────────────────────────────────────────────────────
    let total = TEAMS_PACKETS.load(Ordering::Relaxed);
    let rtp = RTP_PACKETS.load(Ordering::Relaxed);
    let duplicates = channels::record::duplicate_records();
    let ipv4 = IPV4_PACKETS.load(Ordering::Relaxed);
    let ipv6 = IPV6_PACKETS.load(Ordering::Relaxed);
    let filtered = FILTERED_PACKETS.load(Ordering::Relaxed);
    let dropped = DROPPED_PACKETS.load(Ordering::Relaxed);
    let stun = STUN_FILTERED.load(Ordering::Relaxed);
    let dtls = DTLS_FILTERED.load(Ordering::Relaxed);
    let quic = QUIC_FILTERED.load(Ordering::Relaxed);
    let rtcp = RTCP_FILTERED.load(Ordering::Relaxed);
    let unknown = UNKNOWN_FILTERED.load(Ordering::Relaxed);
    let csv = csv_records();
    let rec_drops = record_drops();
    let b_drops = batch_drops();

    println!("\nCapture Statistics");
    println!("==================");
    let teams_udp = ipv4 + ipv6;
    if teams_udp > 0 {
        println!("  Teams UDP packets        : {teams_udp}");
        println!(
            "  Via IPv4                 : {ipv4}  ({:.1}%)",
            (ipv4 as f64 / teams_udp as f64) * 100.0
        );
        println!(
            "  Via IPv6                 : {ipv6}  ({:.1}%)",
            (ipv6 as f64 / teams_udp as f64) * 100.0
        );
    } else {
        println!("  Teams UDP packets        : 0");
    }
    println!();
    println!("  RFC 7983 Protocol Filter");
    println!("  ────────────────────────");
    println!("  ✅ RTP packets (saved)   : {rtp}");
    println!("  ❌ STUN/TURN filtered    : {stun}");
    println!("  ❌ DTLS filtered         : {dtls}");
    println!("  ❌ QUIC filtered         : {quic}");
    println!("  ❌ RTCP filtered         : {rtcp}");
    println!("  ❌ UNKNOWN filtered      : {unknown}");
    println!();
    println!("  Filtered out (non-Teams) : {filtered}");
    println!("  Dropped (queue full)     : {dropped}");
    println!("  Written to PCAP          : {total}");
    println!("  Written to CSV           : {csv}");
    println!("  Duplicate RTP skipped    : {duplicates}");
    if rec_drops > 0 {
        println!("  ⚠️ Record queue drops    : {rec_drops}");
    }
    if b_drops > 0 {
        println!("  ⚠️ Session batch drops   : {b_drops}");
    }
}
