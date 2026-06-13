//! # platforms/teams/
//!
//! **The Microsoft Teams platform.**
//!
//! Implements the [`Platform`] trait over the shared capture pipeline.  Owns,
//! in complete isolation from every other platform:
//!   - its classification rule ([`classify`] + [`ip_ranges`]),
//!   - its PCAP sink (`teams_traffic_rtp.pcap`),
//!   - its RTP record / CSV sink (`teams_rtp_records.csv`),
//!   - its session engine + QoE exporter ([`sessions`]),
//!   - its own packet counters.
//!
//! The hot-path methods (`classify`, `handle_packet`) reproduce the original
//! Teams `quick_precheck`-gated `process_packet` behaviour exactly: keep RTP
//! (to PCAP + CSV + sessions), count and discard STUN / DTLS / QUIC / RTCP /
//! UNKNOWN.

pub mod classify;
pub mod ip_ranges;
pub mod sessions;

use crate::capture::{classify_protocol, ParsedPacket, Protocol};
use crate::channels::pcap::{spawn_pcap_writer, CapturedPacket, Message as PcapMessage, MAX_PACKET_SIZE};
use crate::channels::record::{spawn_record_writer, Batch, RecordMessage, RecordStats};
use crate::framework::{Platform, PlatformSnapshot};
use crate::models::parse_rtp_record;
use crossbeam_channel::{bounded, Sender};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PCAP_PATH: &str = "teams_traffic_rtp.pcap";
const CSV_PATH: &str = "teams_rtp_records.csv";
const PCAP_CHANNEL_CAPACITY: usize = 2_000_000;
const RECORD_CHANNEL_CAPACITY: usize = 2_000_000;
/// Batch queue: 64 slots × 5 000 records = up to 320 000 records buffered.
const BATCH_QUEUE_CAPACITY: usize = 64;

/// Teams packet-level counters (the per-platform half of the original
/// crate-root atomics).
#[derive(Default)]
struct TeamsCounters {
    ipv4: AtomicUsize,         // Teams UDP via IPv4
    ipv6: AtomicUsize,         // Teams UDP via IPv6
    rtp: AtomicUsize,          // RTP kept (PCAP + CSV)
    rtcp: AtomicUsize,         // RTCP discarded
    stun: AtomicUsize,         // STUN/TURN discarded
    dtls: AtomicUsize,         // DTLS discarded
    quic: AtomicUsize,         // QUIC discarded
    unknown: AtomicUsize,      // UNKNOWN discarded
    pcap_queued: AtomicUsize,  // frames accepted by the PCAP channel
    pcap_dropped: AtomicUsize, // frames lost — PCAP channel full
}

/// The Microsoft Teams platform.  Constructed (and its worker threads spawned)
/// by [`TeamsPlatform::start`].
pub struct TeamsPlatform {
    packet_tx: Sender<PcapMessage>,
    record_tx: Sender<RecordMessage>,
    counters: TeamsCounters,
    record_stats: Arc<RecordStats>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    shutdown_done: AtomicBool,
}

impl TeamsPlatform {
    /// Spawn the Teams worker threads (PCAP writer, records/CSV writer, session
    /// engine) and return the platform ready to register with the dispatcher.
    pub fn start() -> Arc<dyn Platform> {
        // Platform-private batch queue: records thread → session worker.
        let (batch_tx, batch_rx) = bounded::<Batch>(BATCH_QUEUE_CAPACITY);

        let record_stats = RecordStats::new();

        let (packet_tx, pcap_handle) = spawn_pcap_writer(PCAP_PATH, PCAP_CHANNEL_CAPACITY);
        let (record_tx, records_handle) = spawn_record_writer(
            CSV_PATH,
            "teams",
            RECORD_CHANNEL_CAPACITY,
            batch_tx,
            record_stats.clone(),
        );
        let session_handle = thread::spawn(move || {
            sessions::session_worker(batch_rx);
            println!("[INFO][teams] Session processor exiting.");
        });

        Arc::new(TeamsPlatform {
            packet_tx,
            record_tx,
            counters: TeamsCounters::default(),
            record_stats,
            // Join order matters: PCAP, then records (emits the session
            // shutdown sentinel), then the session worker.
            handles: Mutex::new(vec![pcap_handle, records_handle, session_handle]),
            shutdown_done: AtomicBool::new(false),
        })
    }

    /// Copy `data` into a fixed buffer and push it to the PCAP channel.
    /// `try_send` never blocks; a full channel counts the frame as dropped.
    #[inline(always)]
    fn send_packet(&self, data: &[u8], ts: Duration) {
        let len = data.len().min(MAX_PACKET_SIZE);
        let mut buf = [0u8; MAX_PACKET_SIZE];
        buf[..len].copy_from_slice(&data[..len]);

        if self
            .packet_tx
            .try_send(PcapMessage::Packet(CapturedPacket { buf, len, ts }))
            .is_ok()
        {
            self.counters.pcap_queued.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.pcap_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Platform for TeamsPlatform {
    fn name(&self) -> &'static str {
        "teams"
    }

    #[inline(always)]
    fn classify(&self, pkt: &ParsedPacket) -> bool {
        classify::is_teams(pkt)
    }

    #[inline(always)]
    fn handle_packet(&self, pkt: &ParsedPacket) {
        if pkt.is_ipv6 {
            self.counters.ipv6.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.ipv4.fetch_add(1, Ordering::Relaxed);
        }

        // UDP payload must have at least 2 bytes for the RFC 7983 first-byte
        // checks to be meaningful (covers the truncated / zero-length case).
        if pkt.udp_payload.len() < 2 {
            self.counters.unknown.fetch_add(1, Ordering::Relaxed);
            return;
        }

        match classify_protocol(pkt.udp_payload) {
            // ── RTP: the only protocol Teams keeps ───────────────────────
            Protocol::Rtp => {
                self.counters.rtp.fetch_add(1, Ordering::Relaxed);
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO);

                // Raw frame → PCAP writer thread.
                self.send_packet(pkt.raw, ts);

                // Structured record → records/CSV/session thread.
                if let Some(record) = parse_rtp_record(
                    pkt.raw,
                    pkt.is_ipv6,
                    pkt.ip_start,
                    pkt.udp_payload_offset,
                    ts,
                ) {
                    if self
                        .record_tx
                        .try_send(RecordMessage::Record(record))
                        .is_err()
                    {
                        self.record_stats.inc_record_drops();
                    }
                }
            }
            // ── Discarded protocols ───────────────────────────────────────
            Protocol::Rtcp => {
                self.counters.rtcp.fetch_add(1, Ordering::Relaxed);
            }
            Protocol::Stun => {
                self.counters.stun.fetch_add(1, Ordering::Relaxed);
            }
            Protocol::Dtls => {
                self.counters.dtls.fetch_add(1, Ordering::Relaxed);
            }
            Protocol::Quic => {
                self.counters.quic.fetch_add(1, Ordering::Relaxed);
            }
            Protocol::Unknown => {
                self.counters.unknown.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn shutdown(&self) {
        if self.shutdown_done.swap(true, Ordering::SeqCst) {
            return; // idempotent
        }

        // 1. PCAP channel may be nearly full when the runtime stops — spin
        //    until the Shutdown sentinel fits.
        loop {
            if self.packet_tx.try_send(PcapMessage::Shutdown).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        // 2. Record channel is smaller / faster to drain; blocking send is fine.
        let _ = self.record_tx.send(RecordMessage::Shutdown);

        // 3. Join worker threads in spawn order. The records thread emits the
        //    empty-batch sentinel that stops the session worker.
        if let Ok(mut handles) = self.handles.lock() {
            for handle in handles.drain(..) {
                let _ = handle.join();
            }
        }
    }

    fn snapshot(&self) -> PlatformSnapshot {
        PlatformSnapshot {
            name: "teams",
            rtp_packets: self.counters.rtp.load(Ordering::Relaxed),
            dropped_packets: self.counters.pcap_dropped.load(Ordering::Relaxed),
            csv_records: self.record_stats.csv_records(),
            duplicate_records: self.record_stats.duplicate_records(),
        }
    }

    fn print_final_stats(&self) {
        let ipv4 = self.counters.ipv4.load(Ordering::Relaxed);
        let ipv6 = self.counters.ipv6.load(Ordering::Relaxed);
        let rtp = self.counters.rtp.load(Ordering::Relaxed);
        let stun = self.counters.stun.load(Ordering::Relaxed);
        let dtls = self.counters.dtls.load(Ordering::Relaxed);
        let quic = self.counters.quic.load(Ordering::Relaxed);
        let rtcp = self.counters.rtcp.load(Ordering::Relaxed);
        let unknown = self.counters.unknown.load(Ordering::Relaxed);
        let pcap_queued = self.counters.pcap_queued.load(Ordering::Relaxed);
        let dropped = self.counters.pcap_dropped.load(Ordering::Relaxed);
        let csv = self.record_stats.csv_records();
        let duplicates = self.record_stats.duplicate_records();
        let rec_drops = self.record_stats.record_drops();
        let b_drops = self.record_stats.batch_drops();

        println!("\n── Platform: Microsoft Teams ──────────────────────────");
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
        println!("  Dropped (queue full)     : {dropped}");
        println!("  Written to PCAP          : {pcap_queued}");
        println!("  Written to CSV           : {csv}");
        println!("  Duplicate RTP skipped    : {duplicates}");
        if rec_drops > 0 {
            println!("  ⚠️ Record queue drops    : {rec_drops}");
        }
        if b_drops > 0 {
            println!("  ⚠️ Session batch drops   : {b_drops}");
        }
    }
}
