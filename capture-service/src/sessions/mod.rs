pub mod media_metrics;
pub mod network_metrics;

use crate::models::RtpRecord;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, bounded};
use media_metrics::MediaMetrics;
use network_metrics::NetworkMetrics;
use std::collections::HashMap;
use std::env;
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const BATCH_SIZE: usize = 5_000;

const SESSION_TIMEOUT_NS: u64 = 120 * 1_000_000_000; // 120 seconds
const BIN_SIZE_NS: u64 = 5 * 1_000_000_000; // 5 seconds

pub struct Batch {
    pub records: Vec<RtpRecord>,
    pub seq: u64,
}

static BATCH_TX: OnceLock<Sender<Batch>> = OnceLock::new();

pub fn init_batch_queue(capacity: usize) -> Receiver<Batch> {
    let (tx, rx) = bounded::<Batch>(capacity);
    BATCH_TX.set(tx).expect("Batch queue already initialised");
    rx
}

pub fn push_batch(batch: Batch) -> bool {
    match BATCH_TX.get() {
        Some(tx) => tx.try_send(batch).is_ok(),
        None => false,
    }
}

pub fn push_shutdown_batch() {
    if let Some(tx) = BATCH_TX.get() {
        let _ = tx.send(Batch {
            records: Vec::new(),
            seq: 0,
        });
    }
}

struct SessionState {
    session_id: String,
    client_ip: String,
    first_seen_ns: u64,
    last_seen_ns: u64,
    current_bin_id: u64,
    network: NetworkMetrics,
    media: MediaMetrics,
}

struct InfluxConfig {
    url: Option<String>,
    token: Option<String>,
}

pub struct SessionEngine {
    sessions: HashMap<String, SessionState>,
    influx_tx: Option<Sender<String>>,
    influx_handle: Option<JoinHandle<()>>,
}

fn is_microsoft_ip(ip: &str) -> bool {
    if let Some(rest) = ip.strip_prefix("52.") {
        if let Some(second_octet) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
            return (112..=115).contains(&second_octet) || (122..=123).contains(&second_octet);
        }
    }

    ip.starts_with("2603:1010")
        || ip.starts_with("2603:1027")
        || ip.starts_with("2603:1037")
        || ip.starts_with("2603:1047")
        || ip.starts_with("2603:1057")
        || ip.starts_with("2620:1ec")
}

fn get_client_ip(r: &RtpRecord) -> String {
    if is_microsoft_ip(&r.src_ip) {
        r.dst_ip.clone()
    } else {
        r.src_ip.clone()
    }
}

fn new_session_id(client_ip: &str, first_seen_ns: u64) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    client_ip.hash(&mut hasher);
    first_seen_ns.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn tag_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace('=', "\\=")
        .replace(' ', "\\ ")
}

fn load_influx_config() -> InfluxConfig {
    let url = env::var("TEAMS_QOE_INFLUX_URL").ok();
    let token = env::var("TEAMS_QOE_INFLUX_TOKEN").ok();

    if url.is_none() {
        eprintln!(
            "[WARN] TEAMS_QOE_INFLUX_URL is not set — QoE lines will be computed but not exported."
        );
    }
    if token.is_none() {
        eprintln!(
            "[WARN] TEAMS_QOE_INFLUX_TOKEN is not set — QoE lines will be computed but not exported."
        );
    }

    InfluxConfig { url, token }
}

impl SessionEngine {
    pub fn new() -> Self {
        let config = load_influx_config();
        let (tx, rx) = bounded::<String>(10_000);
        let handle = std::thread::spawn(move || influx_writer_thread(rx, config));

        Self {
            sessions: HashMap::new(),
            influx_tx: Some(tx),
            influx_handle: Some(handle),
        }
    }

    pub fn process_batch(&mut self, batch: Batch) {
        for record in batch.records {
            self.process_record(record);
        }
    }

    fn process_record(&mut self, record: RtpRecord) {
        let client_ip = get_client_ip(&record);
        let packet_bin_id = record.arrival_epoch_ns / BIN_SIZE_NS;
        let influx_tx = self.influx_tx.clone();

        let state = self
            .sessions
            .entry(client_ip.clone())
            .or_insert_with(|| SessionState {
                session_id: new_session_id(&client_ip, record.arrival_epoch_ns),
                client_ip: client_ip.clone(),
                first_seen_ns: record.arrival_epoch_ns,
                last_seen_ns: record.arrival_epoch_ns,
                current_bin_id: packet_bin_id,
                network: NetworkMetrics::new(),
                media: MediaMetrics::new(),
            });

        if record.arrival_epoch_ns.saturating_sub(state.last_seen_ns) > SESSION_TIMEOUT_NS {
            flush_session(influx_tx.as_ref(), state);
            reset_session(state, record.arrival_epoch_ns, packet_bin_id);
        }

        if packet_bin_id > state.current_bin_id {
            flush_session(influx_tx.as_ref(), state);
            state.current_bin_id = packet_bin_id;
        }

        state.network.process_packet(&record);
        state.media.process_packet(&record);
        state.last_seen_ns = record.arrival_epoch_ns;
    }

    pub fn cleanup_stale_sessions(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64;
        let influx_tx = self.influx_tx.clone();

        let mut stale_keys = Vec::new();
        for (key, state) in self.sessions.iter_mut() {
            if now.saturating_sub(state.last_seen_ns) > SESSION_TIMEOUT_NS {
                flush_session(influx_tx.as_ref(), state);
                stale_keys.push(key.clone());
            }
        }

        for key in stale_keys {
            self.sessions.remove(&key);
        }
    }

    pub fn shutdown(mut self) {
        let influx_tx = self.influx_tx.clone();
        for state in self.sessions.values_mut() {
            flush_session(influx_tx.as_ref(), state);
        }
        self.influx_tx.take();
        drop(influx_tx);

        if let Some(handle) = self.influx_handle.take() {
            if handle.join().is_err() {
                eprintln!("[WARN] InfluxDB writer thread panicked.");
            }
        }
    }
}

fn reset_session(state: &mut SessionState, first_seen_ns: u64, current_bin_id: u64) {
    state.session_id = new_session_id(&state.client_ip, first_seen_ns);
    state.first_seen_ns = first_seen_ns;
    state.last_seen_ns = first_seen_ns;
    state.current_bin_id = current_bin_id;
    state.network = NetworkMetrics::new();
    state.media = MediaMetrics::new();
}

fn flush_session(influx_tx: Option<&Sender<String>>, state: &mut SessionState) {
    if !state.network.has_data() {
        return;
    }

    let duration_sec = 5.0;
    let timestamp_ns = (state.current_bin_id + 1) * BIN_SIZE_NS;
    let client_tag = tag_value(&state.client_ip);
    let session_tag = tag_value(&state.session_id);

    let line = format!(
        "teams_session_qoe,client_ip={},session_id={} {},{},session_age_ns={} {}",
        client_tag,
        session_tag,
        state.network.to_influx_fields(duration_sec),
        state.media.to_influx_fields(duration_sec),
        state.last_seen_ns.saturating_sub(state.first_seen_ns),
        timestamp_ns
    );
    push_influx_line(influx_tx, line);

    state.network.reset_bin();
    state.media.reset_bin();
}

fn push_influx_line(influx_tx: Option<&Sender<String>>, line: String) {
    if let Some(tx) = influx_tx {
        if tx.try_send(line).is_err() {
            eprintln!("[WARN] InfluxDB queue full — dropped QoE line.");
        }
    }
}

pub fn session_worker(rx: Receiver<Batch>) {
    println!("[INFO] Session processor starting.");
    let mut engine = SessionEngine::new();

    loop {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(batch) => {
                if batch.records.is_empty() {
                    engine.shutdown();
                    break;
                }
                engine.process_batch(batch);
                engine.cleanup_stale_sessions();
            }
            Err(RecvTimeoutError::Timeout) => {
                engine.cleanup_stale_sessions();
            }
            Err(RecvTimeoutError::Disconnected) => {
                engine.shutdown();
                break;
            }
        }
    }
}

fn influx_writer_thread(rx: Receiver<String>, config: InfluxConfig) {
    let Some(url) = config.url else {
        drain_without_export(rx);
        return;
    };
    let Some(token) = config.token else {
        drain_without_export(rx);
        return;
    };

    let agent = ureq::AgentBuilder::new()
        .timeout_write(Duration::from_secs(2))
        .timeout_read(Duration::from_secs(2))
        .build();

    while let Some(payload) = collect_payload(&rx) {
        if payload.is_empty() {
            continue;
        }

        let res = agent
            .post(&url)
            .set("Authorization", &format!("Token {token}"))
            .set("Content-Type", "text/plain")
            .send_string(&payload);

        if let Err(e) = res {
            eprintln!("[WARN] InfluxDB write failed: {e}");
        }
    }

    println!("[INFO] InfluxDB writer exiting.");
}

fn collect_payload(rx: &Receiver<String>) -> Option<String> {
    let mut payload = String::new();
    let mut count = 0;

    match rx.recv_timeout(Duration::from_secs(1)) {
        Ok(line) => {
            payload.push_str(&line);
            payload.push('\n');
            count += 1;
        }
        Err(RecvTimeoutError::Timeout) => return Some(payload),
        Err(RecvTimeoutError::Disconnected) => return None,
    }

    while count < 100 {
        match rx.try_recv() {
            Ok(line) => {
                payload.push_str(&line);
                payload.push('\n');
                count += 1;
            }
            Err(_) => break,
        }
    }

    Some(payload)
}

fn drain_without_export(rx: Receiver<String>) {
    println!("[INFO] InfluxDB export disabled; printing metrics to terminal instead...");
    while let Ok(line) = rx.recv() {
        println!("[METRICS] {}", line);
    }
    println!("[INFO] Writer exiting.");
}
