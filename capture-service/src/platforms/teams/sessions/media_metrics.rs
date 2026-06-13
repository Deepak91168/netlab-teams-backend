use crate::models::RtpRecord;
use std::collections::{HashMap, HashSet};
use super::network_metrics::is_server_ip;

// Valid gap range in 90kHz ticks (corresponds to 1–60 FPS)
const MIN_GAP: u32 = 1_500;  // 60 FPS
const MAX_GAP: u32 = 90_000; // 1 FPS

/// Per-SSRC tracker for Media Metrics
struct StreamState {
    /// Maps RTP timestamp → first arrival time (epoch_ns).
    /// Each unique RTP timestamp represents one video frame.
    frame_arrivals: HashMap<u32, u64>,
    /// Total bytes of all video packets (for bitrate calculation)
    total_bytes: u64,
}

#[derive(Default)]
pub struct MediaMetrics {
    streams: HashMap<u32, StreamState>,
    all_ssrcs: HashSet<u32>,
    audio_bytes: u64,
    video_bytes: u64,
}

impl MediaMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called for every packet. Tracks unique RTP timestamps and
    /// their first arrival time for Downlink video packets (>400 bytes).
    pub fn process_packet(&mut self, record: &RtpRecord) {
        let is_downlink = is_server_ip(&record.src_ip);

        // Track every SSRC (both Audio and Video) seen in this bin
        if is_downlink {
            self.all_ssrcs.insert(record.ssrc);
            if record.udp_len <= 400 {
                self.audio_bytes += record.udp_len as u64;
            } else {
                self.video_bytes += record.udp_len as u64;
            }
        }

        // Only process Downlink video packets (>400 bytes filters out audio)
        if is_downlink && record.udp_len > 400 {
            let stream = self.streams.entry(record.ssrc).or_insert_with(|| StreamState {
                frame_arrivals: HashMap::new(),
                total_bytes: 0,
            });

            // Only record the FIRST packet's arrival time for each frame
            stream.frame_arrivals
                .entry(record.rtp_timestamp)
                .or_insert(record.arrival_epoch_ns);

            // Accumulate bytes for video bitrate calculation
            stream.total_bytes += record.udp_len as u64;
        }
    }

    /// Compute FPS, Frame Jitter, and Video Bitrate.
    ///
    /// FPS: (frames - 1) / ((last_rtp_ts - first_rtp_ts) / 90000)
    /// Frame Jitter: Standard deviation of inter-frame arrival gaps (ms)
    /// Video Bitrate: total_bytes * 8 / actual_duration (bps)
    ///
    /// All metrics use simple average across all valid video streams.
    pub fn to_influx_fields(&self, _bin_duration_sec: f64) -> String {
        let mut total_fps = 0.0_f64;
        let mut total_jitter = 0.0_f64;
        let mut total_bitrate = 0.0_f64;
        let mut valid_stream_count = 0_u32;

        for stream in self.streams.values() {
            // Need at least 2 unique timestamps to compute metrics
            if stream.frame_arrivals.len() < 2 {
                continue;
            }

            // Sort frames by RTP timestamp to get correct ordering
            let mut frames: Vec<(u32, u64)> = stream.frame_arrivals
                .iter()
                .map(|(&ts, &arrival)| (ts, arrival))
                .collect();
            frames.sort_unstable_by_key(|&(ts, _)| ts);

            // Validate: check if RTP timestamp gaps fall within video range
            let mut valid_gap_count = 0_u32;

            for i in 1..frames.len() {
                let gap = frames[i].0.wrapping_sub(frames[i - 1].0);
                if gap >= MIN_GAP && gap <= MAX_GAP {
                    valid_gap_count += 1;
                }
            }

            // Skip this stream if no valid gaps (not real video)
            if valid_gap_count == 0 {
                continue;
            }

            // ── FPS ──────────────────────────────────────────────
            let span_ticks = frames.last().unwrap().0.wrapping_sub(frames.first().unwrap().0);
            let actual_duration_sec = span_ticks as f64 / 90_000.0;

            if actual_duration_sec <= 0.0 {
                continue;
            }

            let stream_fps = (frames.len() - 1) as f64 / actual_duration_sec;

            // ── Frame Jitter (std dev of arrival gaps in ms) ─────
            let mut arrival_gaps_ms: Vec<f64> = Vec::with_capacity(frames.len() - 1);

            for i in 1..frames.len() {
                let gap_ns = frames[i].1.saturating_sub(frames[i - 1].1);
                arrival_gaps_ms.push(gap_ns as f64 / 1_000_000.0); // ns → ms
            }

            let mean_gap = arrival_gaps_ms.iter().sum::<f64>() / arrival_gaps_ms.len() as f64;

            let variance = arrival_gaps_ms.iter()
                .map(|g| (g - mean_gap) * (g - mean_gap))
                .sum::<f64>() / arrival_gaps_ms.len() as f64;

            let stream_jitter = variance.sqrt(); // standard deviation in ms

            // ── Video Bitrate (bps) ──────────────────────────────
            let stream_bitrate = (stream.total_bytes * 8) as f64 / actual_duration_sec;

            total_fps += stream_fps;
            total_jitter += stream_jitter;
            total_bitrate += stream_bitrate;
            valid_stream_count += 1;
        }

        // Simple average across all valid video streams
        let fps = if valid_stream_count > 0 {
            total_fps / valid_stream_count as f64
        } else {
            0.0
        };

        let frame_jitter_ms = if valid_stream_count > 0 {
            total_jitter / valid_stream_count as f64
        } else {
            0.0
        };

        let video_bitrate_bps = if valid_stream_count > 0 {
            total_bitrate / valid_stream_count as f64
        } else {
            0.0
        };

        let active_total_streams = self.all_ssrcs.len();
        let active_audio_streams = active_total_streams.saturating_sub(valid_stream_count as usize);

        let audio_bps = (self.audio_bytes * 8) as f64 / _bin_duration_sec;
        let video_total_bps = (self.video_bytes * 8) as f64 / _bin_duration_sec;

        format!("fps={:.2},frame_jitter_ms={:.2},video_bitrate_bps={:.0},active_video_streams={},active_total_streams={},active_audio_streams={},audio_bps={:.0},video_total_bps={:.0}", fps, frame_jitter_ms, video_bitrate_bps, valid_stream_count, active_total_streams, active_audio_streams, audio_bps, video_total_bps)
    }

    /// Reset frame counters for the next 5-second window.
    pub fn reset_bin(&mut self) {
        for stream in self.streams.values_mut() {
            stream.frame_arrivals.clear();
            stream.total_bytes = 0;
        }
        self.all_ssrcs.clear();
        self.audio_bytes = 0;
        self.video_bytes = 0;
    }
}
