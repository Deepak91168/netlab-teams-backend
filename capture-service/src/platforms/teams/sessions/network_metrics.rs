use crate::models::RtpRecord;
use std::collections::HashMap;

// Global Microsoft Server IP prefixes
const MICROSOFT_SERVER_IPS: &[&str] = &[
    "52.112.",
    "52.113.",
    "52.114.",
    "52.115.",
    "52.122.",
    "52.123.",
    "2603:1010",
    "2603:1027",
    "2603:1037",
    "2603:1047",
    "2603:1057",
    "2620:1ec",
];

pub fn is_server_ip(ip: &str) -> bool {
    MICROSOFT_SERVER_IPS.iter().any(|&prefix| ip.starts_with(prefix))
}

#[derive(Clone, Copy)]
struct SeqState {
    last_seq: u16,
}

#[derive(Default)]
pub struct NetworkMetrics {
    uplink_bytes: u64,
    downlink_bytes: u64,
    uplink_packets: u64,
    downlink_packets: u64,
    uplink_lost_packets: u64,
    downlink_lost_packets: u64,
    seq_state: HashMap<u32, SeqState>,
}

impl NetworkMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called for every packet. Calculates metrics based on server IP direction.
    pub fn process_packet(&mut self, record: &RtpRecord) {
        let is_uplink = is_server_ip(&record.dst_ip);
        let is_downlink = is_server_ip(&record.src_ip);

        // If it's not going to or from Microsoft, skip it
        if !is_uplink && !is_downlink {
            return;
        }

        // 1. Calculate Packet Loss
        let mut lost_this_packet = 0;
        match self.seq_state.get_mut(&record.ssrc) {
            Some(state) => {
                let diff = record.seq_num.wrapping_sub(state.last_seq) as i16;
                if diff > 0 {
                    if diff > 1 {
                        lost_this_packet = (diff as u64) - 1;
                    }
                    state.last_seq = record.seq_num;
                }
            }
            None => {
                self.seq_state.insert(
                    record.ssrc,
                    SeqState {
                        last_seq: record.seq_num,
                    },
                );
            }
        }

        // 2. Route the data to the correct Uplink/Downlink bucket
        if is_uplink {
            self.uplink_bytes += record.udp_len as u64;
            self.uplink_packets += 1;
            self.uplink_lost_packets += lost_this_packet;
        } else if is_downlink {
            self.downlink_bytes += record.udp_len as u64;
            self.downlink_packets += 1;
            self.downlink_lost_packets += lost_this_packet;
        }
    }

    /// Returns true if there was any traffic in this bin.
    pub fn has_data(&self) -> bool {
        self.uplink_bytes > 0 || self.downlink_bytes > 0
    }

    /// Helper to calculate percentage safely (prevents dividing by zero)
    fn calculate_loss_pct(received: u64, lost: u64) -> f64 {
        let expected = received + lost;
        if expected == 0 {
            0.0
        } else {
            (lost as f64 / expected as f64) * 100.0
        }
    }

    /// Compute throughput and return as InfluxDB field string.
    pub fn to_influx_fields(&self, bin_duration_sec: f64) -> String {
        let up_bps = (self.uplink_bytes as f64 * 8.0) / bin_duration_sec;
        let down_bps = (self.downlink_bytes as f64 * 8.0) / bin_duration_sec;
        let up_pps = (self.uplink_packets as f64) / bin_duration_sec;
        let down_pps = (self.downlink_packets as f64) / bin_duration_sec;
        let up_loss_pct = Self::calculate_loss_pct(self.uplink_packets, self.uplink_lost_packets);
        let down_loss_pct = Self::calculate_loss_pct(self.downlink_packets, self.downlink_lost_packets);

        format!(
        
            "up_throughput={},down_throughput={},up_bps={:.2},down_bps={:.2},up_pps={:.2},down_pps={:.2},up_loss_pct={:.4},down_loss_pct={:.4}",
            self.uplink_bytes,
            self.downlink_bytes,
            up_bps,
            down_bps,
            up_pps,
            down_pps,
            up_loss_pct,
            down_loss_pct
        )
    }

    /// Reset all counters for the next 5-second window.
    pub fn reset_bin(&mut self) {
        self.uplink_bytes = 0;
        self.downlink_bytes = 0;
        self.uplink_packets = 0;
        self.downlink_packets = 0;
        self.uplink_lost_packets = 0;
        self.downlink_lost_packets = 0;
        // Notice we do NOT clear `seq_state`! 
        // We must remember the last sequence number crossing into the next 5 seconds!
    }
}
