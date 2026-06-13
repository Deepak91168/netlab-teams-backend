//! # capture-service — main.rs
//!
//! **What this file does (multi-platform orchestrator):**
//! - Declares the shared layers (`capture`, `channels`, `models`, `framework`)
//!   and the per-vendor `platforms` tree.
//! - `capture_udp` — the `#[filter("udp")]` callback retina calls per packet;
//!   MUST live in the crate root (proc-macro restriction).  It does nothing
//!   vendor-specific: it hands every frame to the shared dispatcher.
//! - `process_packet` — thin wrapper over `framework::dispatcher::dispatch_frame`,
//!   which parses each frame **once** and routes it to the owning platform.
//! - `stats_thread` — prints a live per-platform summary every 15 s.
//! - `main` — builds + registers every platform (Teams, then the Google Meet
//!   scaffold), installs the dispatcher, runs the retina runtime, then shuts
//!   each platform down and prints its final stats.
//!
//! The single capture pipeline is:
//! ```text
//!   NIC → retina → capture_udp → dispatch_frame
//!       → capture::parse_frame      (parse once, shared)
//!       → platform.classify / handle_packet   (isolated per vendor)
//! ```
//! No vendor logic lives here; Teams behaviour is preserved exactly inside
//! `platforms::teams`.

mod capture;
mod channels;
mod framework;
mod models;
mod platforms;

use clap::Parser;
use framework::dispatcher;
use retina_core::{CoreId, Runtime, config::load_config};
use retina_datatypes::*;
use retina_filtergen::{filter, retina_main};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

// ─────────────────────────────────────────────────────────────────────────────
//  Hot path
//
//  All counting and protocol handling now lives inside each platform.  The
//  crate root only forwards frames to the shared dispatcher, which parses once
//  and routes to the first platform whose `classify` claims the packet.
// ─────────────────────────────────────────────────────────────────────────────
#[inline(always)]
fn process_packet(data: &[u8]) {
    dispatcher::dispatch_frame(data);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Retina filter callback
//  Must live in the crate root — retina_filtergen expands #[filter] and
//  #[retina_main] into a `SubscribedWrapper` type and a `filter` fn here.
// ─────────────────────────────────────────────────────────────────────────────
#[filter("udp")]
fn capture_udp(packet: &ZcFrame, _core_id: &CoreId) {
    process_packet(packet.data());
}

// ─────────────────────────────────────────────────────────────────────────────
//  stats_thread — prints a one-liner per platform every 15 s so you can watch
//  progress without tailing a log file.  Aggregates each platform's cheap
//  snapshot plus the dispatcher's non-target (parsed-but-unclaimed) count.
// ─────────────────────────────────────────────────────────────────────────────
fn stats_thread() {
    // Per-platform deltas, indexed in registration order.
    let platform_count = dispatcher::get().platforms().len();
    let mut last_rtp = vec![0usize; platform_count];
    let mut last_dropped = vec![0usize; platform_count];
    let mut elapsed = 0u64;

    loop {
        thread::sleep(Duration::from_secs(15));
        elapsed += 15;

        let dispatcher = dispatcher::get();
        let non_target = dispatcher.non_target_packets();

        println!("[{elapsed:5}s] non-target (other) packets: {non_target}");

        for (i, platform) in dispatcher.platforms().iter().enumerate() {
            let snap = platform.snapshot();
            let delta = snap.rtp_packets.saturating_sub(last_rtp[i]);
            let new_drops = snap.dropped_packets.saturating_sub(last_dropped[i]);

            println!(
                "         [{}] RTP: {:>9} (+{:<7}) | CSV: {} | Dropped: {} | Dups: {}{}",
                snap.name,
                snap.rtp_packets,
                delta,
                snap.csv_records,
                snap.dropped_packets,
                snap.duplicate_records,
                if new_drops > 0 {
                    format!("  ⚠️  +{new_drops} NEW DROPS!")
                } else {
                    String::new()
                }
            );

            last_rtp[i] = snap.rtp_packets;
            last_dropped[i] = snap.dropped_packets;
        }
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
    println!("Multi-Platform Campus Traffic Capture (RTP-Only Filter)");
    println!("=======================================================");
    println!("Single shared capture + parse pipeline → per-platform classification");
    println!("Active platforms: Microsoft Teams (Google Meet: scaffold, inert)");

    // Build every platform (spawns each platform's own worker threads) and
    // install the shared dispatcher.  Teams is registered first and behaves
    // exactly as before; Google Meet is an inert scaffold that claims nothing.
    let platforms = platforms::register_all();
    dispatcher::install(platforms);

    // Live stats — reads platform snapshots through the installed dispatcher.
    thread::spawn(stats_thread);

    let args = Args::parse();
    let config = load_config(&args.config);

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run(); // blocks until duration expires or SIGINT

    // ── Graceful shutdown ─────────────────────────────────────────────────
    // Each platform flushes and joins its own worker threads (PCAP, records,
    // session engine) inside `shutdown()`.
    println!("\n[INFO] Shutting down — draining per-platform queues...");
    let dispatcher = dispatcher::get();
    for platform in dispatcher.platforms() {
        platform.shutdown();
    }

    // ── Final stats ───────────────────────────────────────────────────────
    println!("\nCapture Statistics");
    println!("==================");
    println!("  Non-target (other) packets : {}", dispatcher.non_target_packets());
    for platform in dispatcher.platforms() {
        platform.print_final_stats();
    }
}
