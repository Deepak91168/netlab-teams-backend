# capture-service — Multi-Platform Architecture

Refactored from the Teams-only capture service into a multi-platform design
where Microsoft Teams, Google Meet, Zoom, etc. share **one** capture + parse
pipeline but keep their vendor logic fully isolated.

## Pipeline

```
NIC
 ↓  retina runtime
capture_udp                 (crate root — #[filter("udp")] callback)
 ↓
dispatcher::dispatch_frame
 ↓
capture::parse_frame        (SHARED — parse Ethernet/VLAN/IP/UDP exactly once)
 ↓
platform.classify(pkt)      (per-vendor — first match wins)
 ↓
platform.handle_packet(pkt) (per-vendor — protocol demux + own PCAP/CSV/sessions)
```

A frame is captured and parsed a single time, then routed to the first platform
whose classifier claims it. Frames no platform claims are counted as
`non-target` by the dispatcher.

## Module layout

```
src/
├── main.rs                       retina entry point; forwards frames to the dispatcher
├── capture/                      SHARED, vendor-agnostic
│   ├── frame.rs                  parse_frame → ParsedPacket (zero-copy)
│   └── protocol.rs               RFC 7983 demux → Protocol enum
├── channels/                     SHARED, generic, per-platform instances
│   ├── pcap.rs                   spawn_pcap_writer(path)  → <platform>_traffic_rtp.pcap
│   └── record.rs                 spawn_record_writer(path) → <platform>_rtp_records.csv
│                                 (CSV + SSRC de-dup + batching → session queue)
├── models/                       SHARED
│   └── rtp_record.rs             RtpRecord + parse_rtp_record (verbatim)
├── framework/                    SHARED spine — no vendor logic
│   ├── platform.rs               Platform trait + PlatformSnapshot
│   └── dispatcher.rs             parse-once routing + non-target counter
└── platforms/                    one isolated module per vendor
    ├── mod.rs                    register_all() — the single registration point
    ├── teams/                    Microsoft Teams (complete; original logic moved verbatim)
    │   ├── classify.rs           is_teams() — MS IP gate (was inside quick_precheck)
    │   ├── ip_ranges.rs          MS media IPv4/IPv6 ranges
    │   └── sessions/             session engine + media/network metrics + Influx export
    └── google_meet/             Google Meet (INERT scaffold — claims nothing)
        ├── classify.rs / ip_ranges.rs   return false until you fill in Google ranges
        └── sessions/             empty scaffold with TODOs
```

## What stayed exactly the same (Teams)

- Same RFC 7983 byte checks and check order; same MS IPv4/IPv6 ranges.
- Same de-dup (64-entry sliding window per SSRC), batching (5 000 / 5 s),
  session binning (5 s), session timeout (120 s).
- Byte-identical CSV header + row format → `teams_rtp_records.csv`.
- Byte-identical PCAP output → `teams_traffic_rtp.pcap`.
- Byte-identical InfluxDB line: `teams_session_qoe,client_ip=…,session_id=… …`.
- Same env vars: `TEAMS_QOE_INFLUX_URL`, `TEAMS_QOE_INFLUX_TOKEN`.
- Same CLI (`-c <config>`), same channel capacities (2 000 000 / 64 batches).

The only behavioural note: IPv6 extension-header walking now runs for all IPv6
UDP before the per-platform IP check (previously the MS check short-circuited
first). Teams output is unaffected — non-Teams IPv6 is simply counted as
`non-target` instead of `Filtered`.

## Adding a new platform (e.g. Zoom)

1. Create `platforms/zoom/` with `classify.rs`, `ip_ranges.rs`, `sessions/`,
   and a `ZoomPlatform` implementing `Platform` (model on `platforms/teams`).
2. Add `pub mod zoom;` to `platforms/mod.rs`.
3. Add one line to `register_all()`:
   `platforms.push(zoom::ZoomPlatform::start());`

No change to Teams, Google Meet, or any shared layer is required.

## Implementing Google Meet (your part)

1. Fill `google_meet/ip_ranges.rs` with Google's media ranges → `classify`
   starts matching.
2. In `google_meet/mod.rs::start()`, spawn the platform's own
   `spawn_pcap_writer` / `spawn_record_writer` / session worker (writing
   `google_meet_traffic_rtp.pcap` / `google_meet_rtp_records.csv`).
3. Implement `google_meet/sessions/` and replace the no-op `handle_packet`.

## Build

`Cargo.toml` is unchanged (edition 2024, retina path deps). Build/run via the
same `build.sh` / `run.sh` as before.

> Note: the shared layers and platform modules were compile-checked in
> isolation. `main.rs` depends on the retina crates / DPDK, so build it in your
> retina workspace with `cargo build --bin capture-service` as usual.
