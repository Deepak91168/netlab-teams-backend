# Adding a New Platform — Reference Playbook

A step-by-step guide for adding a conferencing platform (Zoom, Webex, Discord,
…) to capture-service. Worked example: **Zoom**.

> Golden rule: you only ever **add** files under `platforms/<vendor>/` and add
> **one line** to `platforms/mod.rs`. You never touch the shared layers
> (`capture/`, `channels/`, `models/`, `framework/`) or any other platform.

---

## 0. Mental model (what you're plugging into)

The capture pipeline is already built and shared:

```
NIC → retina → capture_udp (main.rs) → dispatcher::dispatch_frame
    → capture::parse_frame      ← parses Ethernet/VLAN/IP/UDP ONCE, gives you a ParsedPacket
    → YOUR platform.classify()  ← "is this packet mine?"  (cheap IP check)
    → YOUR platform.handle_packet() ← keep RTP, push to YOUR pcap/csv/sessions
```

You implement the `Platform` trait. The dispatcher calls your `classify` for
every parsed packet (in registration order) and routes the first match to your
`handle_packet`. Everything downstream — PCAP writing, CSV writing, SSRC
de-dup, batching, the session-worker plumbing — is generic and reusable; you
just instantiate it with your own file names and wire in your own session
logic.

What you get from the shared layers:
- `capture::ParsedPacket` — zero-copy `raw`, `is_ipv6`, `ip_start`,
  `udp_payload_offset`, `src_ip`, `dst_ip`, `udp_payload`.
- `capture::{classify_protocol, Protocol}` — RFC 7983 demux
  (RTP/RTCP/STUN/DTLS/QUIC).
- `channels::pcap::spawn_pcap_writer(path, capacity)` → `(Sender, JoinHandle)`.
- `channels::record::spawn_record_writer(csv_path, label, capacity, batch_tx, stats)`
  → `(Sender, JoinHandle)` — does CSV + SSRC de-dup + batching for you.
- `channels::record::{Batch, RecordStats, RecordMessage}`.
- `models::{RtpRecord, parse_rtp_record}`.
- `framework::{Platform, PlatformSnapshot}`.

The single best reference implementation is `platforms/teams/` — copy its shape.

---

## 1. Create the module folder

```
src/platforms/zoom/
├── mod.rs            ZoomPlatform + Platform impl (start/classify/handle_packet/…)
├── classify.rs       is_zoom(pkt) — calls ip_ranges
├── ip_ranges.rs      byte-level IPv4/IPv6 range checks for Zoom media
└── sessions/
    ├── mod.rs            session_worker(rx: Receiver<Batch>) + SessionEngine
    ├── media_metrics.rs  per-bin media QoE accumulation
    └── network_metrics.rs per-bin network QoE accumulation
```

---

## 2. `ip_ranges.rs` — who owns this traffic

Fill in Zoom's published media IP ranges as byte-level checks. Model exactly on
`platforms/teams/ip_ranges.rs`.

```rust
//! platforms/zoom/ip_ranges.rs

/// True if `ip` (4 bytes) is in a Zoom media IPv4 range.
#[inline(always)]
pub fn is_zoom_ipv4(ip: &[u8]) -> bool {
    if ip.len() < 4 { return false; }
    // Example shape — replace with Zoom's real published ranges.
    // e.g. 170.114.0.0/16, 213.19.144.0/20, 103.122.166.0/23, etc.
    match ip[0] {
        170 => ip[1] == 114,
        _ => false,
    }
}

/// True if `ip` (16 bytes, big-endian) is in a Zoom media IPv6 range.
#[inline(always)]
pub fn is_zoom_ipv6(ip: &[u8]) -> bool {
    if ip.len() < 16 { return false; }
    // e.g. 2407:30c0::/32 — match on the leading bytes.
    false
}
```

> Tip: match on the fewest leading bytes that define the CIDR prefix. A `/16`
> needs 2 bytes; a `/22` needs 2 bytes plus a mask on the third
> (`(ip[2] & 0xFC) == …`). This is a hot path — keep it allocation-free and
> branch-cheap.

---

## 3. `classify.rs` — the hot-path "is this mine?" check

```rust
//! platforms/zoom/classify.rs
use super::ip_ranges::{is_zoom_ipv4, is_zoom_ipv6};
use crate::capture::ParsedPacket;

#[inline(always)]
pub fn is_zoom(pkt: &ParsedPacket) -> bool {
    if pkt.is_ipv6 {
        is_zoom_ipv6(pkt.src_ip) || is_zoom_ipv6(pkt.dst_ip)
    } else {
        is_zoom_ipv4(pkt.src_ip) || is_zoom_ipv4(pkt.dst_ip)
    }
}
```

> Ordering note: the dispatcher routes to the **first** platform whose
> `classify` returns true. Ranges across vendors don't overlap in practice, but
> if you ever need priority, control it via the order in `register_all`.

---

## 4. `sessions/` — your isolated session + metrics logic

This is the only part with real work. The simplest path is to copy
`platforms/teams/sessions/{mod.rs, media_metrics.rs, network_metrics.rs}` and
adapt:

- Change the InfluxDB measurement name and any env-var names
  (e.g. `teams_session_qoe` → `zoom_session_qoe`,
  `TEAMS_QOE_INFLUX_*` → `ZOOM_QOE_INFLUX_*`).
- Change log prefixes (`[teams]` → `[zoom]`).
- Adjust how a "session" / "client" is derived if Zoom differs from Teams.
- Keep the public entry point identical in shape:

```rust
//! platforms/zoom/sessions/mod.rs
use crate::channels::record::Batch;
use crossbeam_channel::{Receiver, RecvTimeoutError};
use std::time::Duration;

pub fn session_worker(rx: Receiver<Batch>) {
    println!("[INFO][zoom] Session processor starting.");
    let mut engine = SessionEngine::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(batch) => {
                if batch.records.is_empty() {   // empty Batch == shutdown sentinel
                    engine.shutdown();
                    break;
                }
                engine.process_batch(batch);
                engine.cleanup_stale_sessions();
            }
            Err(RecvTimeoutError::Timeout) => engine.cleanup_stale_sessions(),
            Err(RecvTimeoutError::Disconnected) => { engine.shutdown(); break; }
        }
    }
}
```

> Contract you must honour: an **empty `Batch`** is the shutdown sentinel sent
> by the records thread. Treat it as "flush everything and stop." A normal
> flush never emits an empty batch, so it's unambiguous.

If Zoom doesn't need session analytics yet, you can leave `sessions/` as a stub
and skip spawning the session worker (see the Google Meet scaffold).

---

## 5. `mod.rs` — the platform itself

Mirror `platforms/teams/mod.rs`. The essentials:

```rust
//! platforms/zoom/mod.rs
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

const PCAP_PATH: &str = "zoom_traffic_rtp.pcap";   // per-platform output
const CSV_PATH:  &str = "zoom_rtp_records.csv";    // per-platform output
const PCAP_CHANNEL_CAPACITY: usize = 2_000_000;
const RECORD_CHANNEL_CAPACITY: usize = 2_000_000;
const BATCH_QUEUE_CAPACITY: usize = 64;

#[derive(Default)]
struct ZoomCounters {
    ipv4: AtomicUsize, ipv6: AtomicUsize, rtp: AtomicUsize,
    rtcp: AtomicUsize, stun: AtomicUsize, dtls: AtomicUsize,
    quic: AtomicUsize, unknown: AtomicUsize,
    pcap_queued: AtomicUsize, pcap_dropped: AtomicUsize,
}

pub struct ZoomPlatform {
    packet_tx: Sender<PcapMessage>,
    record_tx: Sender<RecordMessage>,
    counters: ZoomCounters,
    record_stats: Arc<RecordStats>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    shutdown_done: AtomicBool,
}

impl ZoomPlatform {
    pub fn start() -> Arc<dyn Platform> {
        let (batch_tx, batch_rx) = bounded::<Batch>(BATCH_QUEUE_CAPACITY);
        let record_stats = RecordStats::new();

        let (packet_tx, pcap_handle) = spawn_pcap_writer(PCAP_PATH, PCAP_CHANNEL_CAPACITY);
        let (record_tx, records_handle) = spawn_record_writer(
            CSV_PATH, "zoom", RECORD_CHANNEL_CAPACITY, batch_tx, record_stats.clone(),
        );
        let session_handle = thread::spawn(move || {
            sessions::session_worker(batch_rx);
            println!("[INFO][zoom] Session processor exiting.");
        });

        Arc::new(ZoomPlatform {
            packet_tx, record_tx,
            counters: ZoomCounters::default(),
            record_stats,
            // Join order: pcap, records (emits session sentinel), session.
            handles: Mutex::new(vec![pcap_handle, records_handle, session_handle]),
            shutdown_done: AtomicBool::new(false),
        })
    }

    #[inline(always)]
    fn send_packet(&self, data: &[u8], ts: Duration) {
        let len = data.len().min(MAX_PACKET_SIZE);
        let mut buf = [0u8; MAX_PACKET_SIZE];
        buf[..len].copy_from_slice(&data[..len]);
        if self.packet_tx.try_send(PcapMessage::Packet(CapturedPacket { buf, len, ts })).is_ok() {
            self.counters.pcap_queued.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.pcap_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Platform for ZoomPlatform {
    fn name(&self) -> &'static str { "zoom" }

    #[inline(always)]
    fn classify(&self, pkt: &ParsedPacket) -> bool { classify::is_zoom(pkt) }

    #[inline(always)]
    fn handle_packet(&self, pkt: &ParsedPacket) {
        if pkt.is_ipv6 { self.counters.ipv6.fetch_add(1, Ordering::Relaxed); }
        else           { self.counters.ipv4.fetch_add(1, Ordering::Relaxed); }

        if pkt.udp_payload.len() < 2 {
            self.counters.unknown.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match classify_protocol(pkt.udp_payload) {
            Protocol::Rtp => {
                self.counters.rtp.fetch_add(1, Ordering::Relaxed);
                let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
                self.send_packet(pkt.raw, ts);
                if let Some(rec) = parse_rtp_record(pkt.raw, pkt.is_ipv6, pkt.ip_start, pkt.udp_payload_offset, ts) {
                    if self.record_tx.try_send(RecordMessage::Record(rec)).is_err() {
                        self.record_stats.inc_record_drops();
                    }
                }
            }
            Protocol::Rtcp    => { self.counters.rtcp.fetch_add(1, Ordering::Relaxed); }
            Protocol::Stun    => { self.counters.stun.fetch_add(1, Ordering::Relaxed); }
            Protocol::Dtls    => { self.counters.dtls.fetch_add(1, Ordering::Relaxed); }
            Protocol::Quic    => { self.counters.quic.fetch_add(1, Ordering::Relaxed); }
            Protocol::Unknown => { self.counters.unknown.fetch_add(1, Ordering::Relaxed); }
        }
    }

    fn shutdown(&self) {
        if self.shutdown_done.swap(true, Ordering::SeqCst) { return; } // idempotent
        loop { // PCAP channel may be full — spin until the sentinel fits
            if self.packet_tx.try_send(PcapMessage::Shutdown).is_ok() { break; }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.record_tx.send(RecordMessage::Shutdown);
        if let Ok(mut handles) = self.handles.lock() {
            for h in handles.drain(..) { let _ = h.join(); }
        }
    }

    fn snapshot(&self) -> PlatformSnapshot {
        PlatformSnapshot {
            name: "zoom",
            rtp_packets: self.counters.rtp.load(Ordering::Relaxed),
            dropped_packets: self.counters.pcap_dropped.load(Ordering::Relaxed),
            csv_records: self.record_stats.csv_records(),
            duplicate_records: self.record_stats.duplicate_records(),
        }
    }

    fn print_final_stats(&self) {
        // Copy the Teams block and relabel "Microsoft Teams" → "Zoom".
        println!("\n── Platform: Zoom ─────────────────────────────────────");
        // … print counters …
    }
}
```

### Why the parts are shaped this way
- **Counters via atomics, heavy work on threads.** `classify`/`handle_packet`
  run on every capture core concurrently, so the platform holds only channel
  senders + atomic counters (`&self`, lock-free). All real work (disk, dedup,
  sessions, HTTP) happens on the worker threads you spawn in `start()`.
- **`try_send` on the hot path.** Never block a capture core; a full queue
  drops the packet and bumps a drop counter.
- **Join order matters.** pcap first, then records (it emits the empty-batch
  sentinel), then the session worker — so nothing is dropped on shutdown.
- **`shutdown` is idempotent** via the `AtomicBool` swap, so it's safe even if
  called more than once.

---

## 6. Register it — the ONE line you change outside your folder

`src/platforms/mod.rs`:

```rust
pub mod google_meet;
pub mod teams;
pub mod zoom;                    // ← add module

pub fn register_all() -> Vec<Arc<dyn Platform>> {
    let mut platforms: Vec<Arc<dyn Platform>> = Vec::new();
    platforms.push(teams::TeamsPlatform::start());
    platforms.push(google_meet::GoogleMeetPlatform::start());
    platforms.push(zoom::ZoomPlatform::start());   // ← add registration
    platforms
}
```

That's it. `main.rs`, the dispatcher, the stats thread, and shutdown all pick
up the new platform automatically — `register_all()` is the only wiring point.

---

## 7. Verify

- `cargo build` — clean.
- Run against a capture/pcap with Zoom traffic; confirm `zoom_traffic_rtp.pcap`
  and `zoom_rtp_records.csv` appear and the live stats line shows a `[zoom]`
  row.
- Confirm Teams output is unchanged (it shares no state with Zoom).
- If you wired InfluxDB, set `ZOOM_QOE_INFLUX_URL` / `ZOOM_QOE_INFLUX_TOKEN`
  and confirm the `zoom_session_qoe` measurement lands.

---

## Checklist (copy per platform)

- [ ] `platforms/<vendor>/ip_ranges.rs` — real published media ranges, byte-level.
- [ ] `platforms/<vendor>/classify.rs` — `is_<vendor>(pkt)`.
- [ ] `platforms/<vendor>/sessions/` — session worker + media/network metrics
      (or a stub if not needed yet).
- [ ] `platforms/<vendor>/mod.rs` — `<Vendor>Platform` + `Platform` impl;
      `PCAP_PATH` / `CSV_PATH` use the `<vendor>_` prefix; measurement +
      env-var names relabelled.
- [ ] `platforms/mod.rs` — `pub mod <vendor>;` + one `register_all()` line.
- [ ] Built clean, verified output files, Teams unaffected.

## Things you must NOT do
- Don't edit `capture/`, `channels/`, `models/`, or `framework/` — they're
  shared and vendor-neutral.
- Don't reference another platform's module from yours — platforms are isolated.
- Don't block in `classify` / `handle_packet` — push to channels instead.
- Don't reuse another platform's file names — always prefix with your vendor.


## Part 1 — How the service works (5-minute orientation)

One capture pipeline is shared by all platforms. A packet flows like this:

```
NIC
 │  (retina delivers every UDP frame)
 ▼
capture_udp                         src/main.rs        ← single capture point
 │  hands raw bytes to the dispatcher
 ▼
dispatcher::dispatch_frame          src/framework/dispatcher.rs
 │  1) parse_frame(data)            src/capture/frame.rs   ← parses ONCE, shared
 │  2) for each platform in order: platform.classify(pkt)?
 │  3) first match → platform.handle_packet(pkt)
 │  4) nobody matches → counted as "non_target"
 ▼
YOUR platform                       src/platforms/<vendor>/mod.rs
 │  keep RTP only, drop the rest, then:
 ├─ raw frame  → PCAP channel   → pcap writer thread  → <vendor>_traffic_rtp.pcap
 └─ RtpRecord  → record channel → records thread      → <vendor>_rtp_records.csv
                                          │  (CSV + SSRC de-dup + batching)
                                          └─ Batch → session worker → InfluxDB
```

The key idea: **the frame is captured and parsed exactly once**, then routed to
whichever platform "owns" the IPs. Each platform owns everything
vendor-specific; the plumbing (parsing, PCAP writing, CSV writing, de-dup,
batching) is generic and reused.

---

## Part 2 — The two zones: what you touch, what you don't

The codebase is split into a **SHARED zone** (the generic engine) and a
**PLATFORM zone** (one isolated folder per vendor). Adding a platform happens
almost entirely inside a new folder in the platform zone.

### 🟥 SHARED zone — DO NOT EDIT

These files are vendor-neutral. Editing them risks breaking *every* platform,
including Teams. You only *call into* them.

| File | What it gives you | You… |
|------|-------------------|------|
| `src/main.rs` | retina entry point + dispatcher wiring + live stats | **don't touch** |
| `src/capture/frame.rs` | `parse_frame` → `ParsedPacket` (Ethernet/VLAN/IP/UDP) | **don't touch** — you read `ParsedPacket` |
| `src/capture/protocol.rs` | `classify_protocol` → `Protocol` (RFC 7983 demux) | **don't touch** — you call it |
| `src/capture/mod.rs` | re-exports | **don't touch** |
| `src/channels/pcap.rs` | `spawn_pcap_writer(path, cap)` | **don't touch** — you call it |
| `src/channels/record.rs` | `spawn_record_writer(...)`, `Batch`, `RecordStats` | **don't touch** — you call it |
| `src/channels/mod.rs` | re-exports | **don't touch** |
| `src/models/rtp_record.rs` | `RtpRecord` + `parse_rtp_record` | **don't touch** — you call it |
| `src/models/mod.rs` | re-exports | **don't touch** |
| `src/framework/platform.rs` | the `Platform` trait you implement | **don't touch** — you implement it |
| `src/framework/dispatcher.rs` | routing | **don't touch** |
| `src/framework/mod.rs` | re-exports | **don't touch** |

### 🟩 PLATFORM zone — your work

| File | Action |
|------|--------|
| `src/platforms/zoom/ip_ranges.rs` | **CREATE** — Zoom's media IP ranges |
| `src/platforms/zoom/classify.rs` | **CREATE** — `is_zoom(pkt)` |
| `src/platforms/zoom/mod.rs` | **CREATE** — `ZoomPlatform` (the `Platform` impl) |
| `src/platforms/zoom/sessions/mod.rs` | **CREATE** — session worker + engine |
| `src/platforms/zoom/sessions/media_metrics.rs` | **CREATE** — media QoE |
| `src/platforms/zoom/sessions/network_metrics.rs` | **CREATE** — network QoE |
| `src/platforms/mod.rs` | **EDIT (2 lines)** — register Zoom |

> Existing platform folders (`teams/`, `google_meet/`) are **never edited** when
> adding Zoom — platforms don't reference each other.

So the entire footprint of "add Zoom" is: **6 new files in one new folder + 2
edited lines in `platforms/mod.rs`.** Nothing else.

---

## Part 3 — The contracts you must honour

Three things the shared engine assumes. Get these right and everything else is
mechanical.

1. **`classify` and `handle_packet` run on every capture core at once.** They
   take `&self` and must be cheap and non-blocking — only atomics and channel
   `try_send`. All heavy work (disk, dedup, sessions, HTTP) lives on worker
   threads you spawn in `start()`.

2. **Keep RTP, drop the rest.** After `classify_protocol`, only `Protocol::Rtp`
   is written to PCAP/CSV/sessions. Other protocols are just counted. (This is
   what "RTP-only filter" means — change it only if your vendor needs
   different behaviour.)

3. **Shutdown uses an empty-`Batch` sentinel.** The records thread, on
   shutdown, sends a `Batch` with zero records to your session worker. Your
   session worker must treat an empty batch as "flush and stop." A normal flush
   never produces an empty batch, so it's unambiguous.

---

## Part 4 — Build Zoom, file by file

### Step 1 — `src/platforms/zoom/ip_ranges.rs`  (CREATE)

Byte-level membership tests for Zoom's published media ranges. This is the only
file with vendor data you must research. Match on the fewest leading bytes that
define each CIDR prefix.

```rust
//! platforms/zoom/ip_ranges.rs
//! Zoom-owned traffic classification data — byte-level IP range checks.

/// True if `ip` (4 bytes) is in a Zoom media IPv4 range.
#[inline(always)]
pub fn is_zoom_ipv4(ip: &[u8]) -> bool {
    if ip.len() < 4 {
        return false;
    }
    // ⚠️ PLACEHOLDER ranges — replace with Zoom's CURRENT published media
    // ranges (see Zoom's "network firewall / media IP ranges" docs).
    // Examples of the shape only:
    match ip[0] {
        170 => ip[1] == 114,                          // 170.114.0.0/16
        213 => ip[1] == 19 && (ip[2] & 0xF0) == 144,  // 213.19.144.0/20
        _ => false,
    }
}

/// True if `ip` (16 bytes, big-endian) is in a Zoom media IPv6 range.
#[inline(always)]
pub fn is_zoom_ipv6(ip: &[u8]) -> bool {
    if ip.len() < 16 {
        return false;
    }
    // ⚠️ PLACEHOLDER — e.g. 2407:30c0::/32 would be:
    //   ip[0]==0x24 && ip[1]==0x07 && ip[2]==0x30 && ip[3]==0xc0
    false
}
```

**How to turn a CIDR into a byte check:**
- `/8` → check `ip[0]`.
- `/16` → check `ip[0]` and `ip[1]`.
- `/20` → check `ip[0]`, `ip[1]`, and the top 4 bits of `ip[2]`: `(ip[2] & 0xF0) == X`.
- `/24` → check `ip[0..3]`.
- IPv6 `/32` → check `ip[0..4]`; `/48` → `ip[0..6]`.

### Step 2 — `src/platforms/zoom/classify.rs`  (CREATE)

The hot-path "is this packet mine?" check. Source **or** destination IP in range.

```rust
//! platforms/zoom/classify.rs
use super::ip_ranges::{is_zoom_ipv4, is_zoom_ipv6};
use crate::capture::ParsedPacket;

/// Hot-path check: is this parsed UDP packet Zoom media?
#[inline(always)]
pub fn is_zoom(pkt: &ParsedPacket) -> bool {
    if pkt.is_ipv6 {
        is_zoom_ipv6(pkt.src_ip) || is_zoom_ipv6(pkt.dst_ip)
    } else {
        is_zoom_ipv4(pkt.src_ip) || is_zoom_ipv4(pkt.dst_ip)
    }
}
```

`ParsedPacket` (from `capture::frame`) gives you, zero-copy:
`raw: &[u8]`, `is_ipv6: bool`, `ip_start: usize`, `udp_payload_offset: usize`,
`src_ip: &[u8]`, `dst_ip: &[u8]`, `udp_payload: &[u8]`.

### Step 3 — the `sessions/` folder  (CREATE — easiest by copying Teams)

The session engine groups records by client into time-binned sessions, computes
QoE, and emits InfluxDB line-protocol. **The reliable way to create this is to
copy the three Teams files and relabel them**, because the engine is already
correct and battle-tested.

```bash
cd src/platforms
mkdir -p zoom/sessions
cp teams/sessions/mod.rs             zoom/sessions/mod.rs
cp teams/sessions/media_metrics.rs   zoom/sessions/media_metrics.rs
cp teams/sessions/network_metrics.rs zoom/sessions/network_metrics.rs
```

Then in `zoom/sessions/mod.rs` make these exact substitutions:

| Find | Replace with | Why |
|------|--------------|-----|
| `teams_session_qoe` | `zoom_session_qoe` | InfluxDB measurement name |
| `TEAMS_QOE_INFLUX_URL` | `ZOOM_QOE_INFLUX_URL` | env var for your endpoint |
| `TEAMS_QOE_INFLUX_TOKEN` | `ZOOM_QOE_INFLUX_TOKEN` | env var for your token |
| `[teams]` | `[zoom]` | log prefixes |

The public entry point — `pub fn session_worker(rx: Receiver<Batch>)` — must
keep its name and signature. Confirm it still honours the empty-batch sentinel:

```rust
pub fn session_worker(rx: Receiver<Batch>) {
    println!("[INFO][zoom] Session processor starting.");
    let mut engine = SessionEngine::new();
    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(batch) => {
                if batch.records.is_empty() {   // ← shutdown sentinel
                    engine.shutdown();
                    break;
                }
                engine.process_batch(batch);
                engine.cleanup_stale_sessions();
            }
            Err(RecvTimeoutError::Timeout) => engine.cleanup_stale_sessions(),
            Err(RecvTimeoutError::Disconnected) => { engine.shutdown(); break; }
        }
    }
}
```

`media_metrics.rs` / `network_metrics.rs` consume the fields on `RtpRecord`
(`ssrc`, `seq_num`, `rtp_timestamp`, `payload_type`, `marker`, `udp_len`, …).
If Zoom's QoE definition matches Teams', leave the math alone. If it differs,
this is the isolated place to change it — nothing else is affected.

> **Don't need analytics yet?** You can skip the session engine entirely: make
> `sessions/mod.rs` contain a no-op `session_worker` that just drains until the
> empty batch, and skip spawning it in `start()` (see how `google_meet/`
> stays inert). You can add the real engine later without touching anything else.

### Step 4 — `src/platforms/zoom/mod.rs`  (CREATE — the platform itself)

This wires your pieces to the shared engine and implements the `Platform` trait.
It's a near-copy of `teams/mod.rs` with names changed. Full file:

```rust
//! platforms/zoom/ — the Zoom platform over the shared capture pipeline.

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

// Per-platform output files — ALWAYS prefix with the vendor name so two
// platforms never write the same file.
const PCAP_PATH: &str = "zoom_traffic_rtp.pcap";
const CSV_PATH:  &str = "zoom_rtp_records.csv";
const PCAP_CHANNEL_CAPACITY: usize = 2_000_000;
const RECORD_CHANNEL_CAPACITY: usize = 2_000_000;
const BATCH_QUEUE_CAPACITY: usize = 64;

#[derive(Default)]
struct ZoomCounters {
    ipv4: AtomicUsize,
    ipv6: AtomicUsize,
    rtp: AtomicUsize,
    rtcp: AtomicUsize,
    stun: AtomicUsize,
    dtls: AtomicUsize,
    quic: AtomicUsize,
    unknown: AtomicUsize,
    pcap_queued: AtomicUsize,
    pcap_dropped: AtomicUsize,
}

pub struct ZoomPlatform {
    packet_tx: Sender<PcapMessage>,
    record_tx: Sender<RecordMessage>,
    counters: ZoomCounters,
    record_stats: Arc<RecordStats>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    shutdown_done: AtomicBool,
}

impl ZoomPlatform {
    /// Spawn Zoom's worker threads and return the ready-to-register platform.
    pub fn start() -> Arc<dyn Platform> {
        let (batch_tx, batch_rx) = bounded::<Batch>(BATCH_QUEUE_CAPACITY);
        let record_stats = RecordStats::new();

        let (packet_tx, pcap_handle) = spawn_pcap_writer(PCAP_PATH, PCAP_CHANNEL_CAPACITY);
        let (record_tx, records_handle) = spawn_record_writer(
            CSV_PATH,
            "zoom",                 // log label
            RECORD_CHANNEL_CAPACITY,
            batch_tx,
            record_stats.clone(),
        );
        let session_handle = thread::spawn(move || {
            sessions::session_worker(batch_rx);
            println!("[INFO][zoom] Session processor exiting.");
        });

        Arc::new(ZoomPlatform {
            packet_tx,
            record_tx,
            counters: ZoomCounters::default(),
            record_stats,
            // Join order MATTERS: pcap, then records (emits the session
            // shutdown sentinel), then the session worker.
            handles: Mutex::new(vec![pcap_handle, records_handle, session_handle]),
            shutdown_done: AtomicBool::new(false),
        })
    }

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

impl Platform for ZoomPlatform {
    fn name(&self) -> &'static str {
        "zoom"
    }

    #[inline(always)]
    fn classify(&self, pkt: &ParsedPacket) -> bool {
        classify::is_zoom(pkt)
    }

    #[inline(always)]
    fn handle_packet(&self, pkt: &ParsedPacket) {
        if pkt.is_ipv6 {
            self.counters.ipv6.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.ipv4.fetch_add(1, Ordering::Relaxed);
        }

        if pkt.udp_payload.len() < 2 {
            self.counters.unknown.fetch_add(1, Ordering::Relaxed);
            return;
        }

        match classify_protocol(pkt.udp_payload) {
            Protocol::Rtp => {
                self.counters.rtp.fetch_add(1, Ordering::Relaxed);
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO);
                self.send_packet(pkt.raw, ts);
                if let Some(rec) = parse_rtp_record(
                    pkt.raw, pkt.is_ipv6, pkt.ip_start, pkt.udp_payload_offset, ts,
                ) {
                    if self.record_tx.try_send(RecordMessage::Record(rec)).is_err() {
                        self.record_stats.inc_record_drops();
                    }
                }
            }
            Protocol::Rtcp => { self.counters.rtcp.fetch_add(1, Ordering::Relaxed); }
            Protocol::Stun => { self.counters.stun.fetch_add(1, Ordering::Relaxed); }
            Protocol::Dtls => { self.counters.dtls.fetch_add(1, Ordering::Relaxed); }
            Protocol::Quic => { self.counters.quic.fetch_add(1, Ordering::Relaxed); }
            Protocol::Unknown => { self.counters.unknown.fetch_add(1, Ordering::Relaxed); }
        }
    }

    fn shutdown(&self) {
        if self.shutdown_done.swap(true, Ordering::SeqCst) {
            return; // idempotent
        }
        // PCAP channel may be nearly full — spin until the sentinel fits.
        loop {
            if self.packet_tx.try_send(PcapMessage::Shutdown).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.record_tx.send(RecordMessage::Shutdown);
        if let Ok(mut handles) = self.handles.lock() {
            for h in handles.drain(..) {
                let _ = h.join();
            }
        }
    }

    fn snapshot(&self) -> PlatformSnapshot {
        PlatformSnapshot {
            name: "zoom",
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

        println!("\n── Platform: Zoom ─────────────────────────────────────");
        let udp = ipv4 + ipv6;
        if udp > 0 {
            println!("  Zoom UDP packets         : {udp}");
            println!("  Via IPv4                 : {ipv4}  ({:.1}%)", (ipv4 as f64 / udp as f64) * 100.0);
            println!("  Via IPv6                 : {ipv6}  ({:.1}%)", (ipv6 as f64 / udp as f64) * 100.0);
        } else {
            println!("  Zoom UDP packets         : 0");
        }
        println!();
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
    }
}
```

#### What each `Platform` method is for
- `name()` — stable id, also your file-name prefix.
- `classify(&self, pkt)` — cheap "mine?" check (your `is_zoom`).
- `handle_packet(&self, pkt)` — hot path: count, keep RTP → pcap + record.
- `shutdown(&self)` — flush + join your worker threads (idempotent).
- `snapshot(&self)` — cheap counters for the live stats line.
- `print_final_stats(&self)` — your end-of-run block.

### Step 5 — register Zoom: `src/platforms/mod.rs`  (EDIT — 2 lines)

This is the **only** file outside your folder that changes.

```rust
pub mod google_meet;
pub mod teams;
pub mod zoom;                                       // ← LINE 1: declare module

pub fn register_all() -> Vec<Arc<dyn Platform>> {
    let mut platforms: Vec<Arc<dyn Platform>> = Vec::new();
    platforms.push(teams::TeamsPlatform::start());
    platforms.push(google_meet::GoogleMeetPlatform::start());
    platforms.push(zoom::ZoomPlatform::start());    // ← LINE 2: register it
    platforms
}
```

Order = classification priority (first match wins). Vendor ranges don't overlap
in practice, so order rarely matters; if it ever does, control it here.

**Done.** `main.rs`, the dispatcher, the live-stats thread, and graceful
shutdown all pick up Zoom automatically — they iterate whatever `register_all`
returns.

---

## Part 5 — Build & verify

```bash
# In your retina workspace:
cargo build --bin capture-service        # must be clean

# Run against an interface / pcap that contains Zoom media:
./run.sh                                  # or your usual invocation
```

Verify:
1. `zoom_traffic_rtp.pcap` and `zoom_rtp_records.csv` are created.
2. The live stats line shows a `[zoom]` row counting RTP.
3. Teams output (`teams_*`) is unchanged — Teams shares no state with Zoom.
4. If using InfluxDB: `export ZOOM_QOE_INFLUX_URL=… ZOOM_QOE_INFLUX_TOKEN=…`
   and confirm the `zoom_session_qoe` measurement lands. Without those env
   vars, QoE lines print to the terminal instead.

---

## Part 6 — Checklist (copy this per new platform)

Create under `src/platforms/<vendor>/`:
- [ ] `ip_ranges.rs` — real published media ranges, byte-level checks.
- [ ] `classify.rs` — `is_<vendor>(pkt)` using `ip_ranges`.
- [ ] `sessions/mod.rs` — `session_worker(rx: Receiver<Batch>)` honouring the
      empty-batch sentinel (copy + relabel Teams, or stub it).
- [ ] `sessions/media_metrics.rs`, `sessions/network_metrics.rs`.
- [ ] `mod.rs` — `<Vendor>Platform` + `impl Platform`; `PCAP_PATH`/`CSV_PATH`
      use the `<vendor>_` prefix; measurement + env-var names relabelled.

Edit once:
- [ ] `src/platforms/mod.rs` — `pub mod <vendor>;` + one `register_all()` line.

Verify:
- [ ] `cargo build` clean; output files appear; `[<vendor>]` stats row shows;
      Teams unaffected.

---

## Part 7 — Common mistakes (read before you start)

- **Editing a shared file.** If you find yourself changing anything under
  `capture/`, `channels/`, `models/`, or `framework/`, stop — the right change
  is almost always inside your platform folder. The exception is a genuine new
  shared capability (e.g. a brand-new protocol parser), which should be
  designed to stay vendor-neutral.
- **Reusing file names.** Two platforms writing `traffic_rtp.pcap` will clobber
  each other. Always prefix: `zoom_traffic_rtp.pcap`.
- **Blocking the hot path.** No file I/O, no HTTP, no `recv`, no blocking
  `send` inside `classify`/`handle_packet`. Use atomics + `try_send`; do the
  work on a thread.
- **Forgetting the sentinel.** If your `session_worker` doesn't stop on an
  empty `Batch`, shutdown will hang on `join`.
- **Wrong join order.** Keep `[pcap, records, session]`. Records must shut down
  before the session worker so the sentinel is delivered.
- **Referencing another platform.** `use crate::platforms::teams::…` from Zoom
  breaks isolation — don't. Share only through the shared layers.
- **Stale IP ranges.** Vendor media ranges change. Pull the current published
  list when you implement, and revisit periodically.