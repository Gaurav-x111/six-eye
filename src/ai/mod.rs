pub mod behavior;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Local};
use chrono::Timelike;
use serde::{Deserialize, Serialize};

use crate::models::{ConnectedDevice, Network};

// ── Anomaly Detection ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyReport {
    pub timestamp: DateTime<Local>,
    pub anomaly_type: AnomalyType,
    pub severity: AnomalySeverity,
    pub description: String,
    pub evidence: Vec<String>,
    pub behavior_score: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyType {
    NewDevice,
    PortChange,
    SignalAnomaly,
    TimeAnomaly,
    VendorMismatch,
    SubnetScan,
    TrafficSpike,
    DeviceDisappear,
}

impl AnomalyType {
    pub fn label(&self) -> &'static str {
        match self {
            AnomalyType::NewDevice => "New Device",
            AnomalyType::PortChange => "Port Change",
            AnomalyType::SignalAnomaly => "Signal Anomaly",
            AnomalyType::TimeAnomaly => "Time Anomaly",
            AnomalyType::VendorMismatch => "Vendor Mismatch",
            AnomalyType::SubnetScan => "Subnet Scan",
            AnomalyType::TrafficSpike => "Traffic Spike",
            AnomalyType::DeviceDisappear => "Device Disappeared",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            AnomalyType::NewDevice => "🆕",
            AnomalyType::PortChange => "🔌",
            AnomalyType::SignalAnomaly => "📊",
            AnomalyType::TimeAnomaly => "🕐",
            AnomalyType::VendorMismatch => "🏷",
            AnomalyType::SubnetScan => "🔍",
            AnomalyType::TrafficSpike => "📈",
            AnomalyType::DeviceDisappear => "👻",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Info,
    Low,
    Medium,
    High,
}

impl AnomalySeverity {
    pub fn label(&self) -> &'static str {
        match self {
            AnomalySeverity::Info => "Info",
            AnomalySeverity::Low => "Low",
            AnomalySeverity::Medium => "Medium",
            AnomalySeverity::High => "High",
        }
    }
}

// ── Behavior Baseline ───────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BehaviorBaseline {
    /// MAC → set of known IP addresses
    pub known_ips: HashMap<String, Vec<String>>,
    /// MAC → set of known open ports
    pub known_ports: HashMap<String, Vec<u16>>,
    /// MAC → first seen time
    pub first_seen: HashMap<String, DateTime<Local>>,
    /// MAC → last seen time
    pub last_seen: HashMap<String, DateTime<Local>>,
    /// Hourly device count histogram (24 buckets)
    pub hourly_counts: [u32; 24],
    /// Total scan cycles
    pub scan_count: u64,
}

impl BehaviorBaseline {
    pub fn new() -> Self {
        Self {
            known_ips: HashMap::new(),
            known_ports: HashMap::new(),
            first_seen: HashMap::new(),
            last_seen: HashMap::new(),
            hourly_counts: [0; 24],
            scan_count: 0,
        }
    }
}

// ── AI Analysis Engine ──────────────────────────────────────────────

pub struct AiEngine {
    pub baseline: BehaviorBaseline,
    pub anomalies: VecDeque<AnomalyReport>,
    pub behavior_analyzer: behavior::BehaviorAnalyzer,
    pub max_anomalies: usize,
}

impl AiEngine {
    pub fn new() -> Self {
        Self {
            baseline: BehaviorBaseline::new(),
            anomalies: VecDeque::new(),
            behavior_analyzer: behavior::BehaviorAnalyzer::new(),
            max_anomalies: 200,
        }
    }

    /// Analyze devices and networks for anomalies.
    pub fn analyze(
        &mut self,
        networks: &[Network],
        devices: &[ConnectedDevice],
    ) -> Vec<AnomalyReport> {
        let mut new_anomalies = Vec::new();
        self.baseline.scan_count += 1;

        let hour = Local::now().hour() as usize;
        self.baseline.hourly_counts[hour] += 1;

        // Detect new devices
        for device in devices {
            let mac = device
                .mac_address
                .as_deref()
                .unwrap_or(device.primary_address());

            if !self.baseline.known_ips.contains_key(mac) {
                // This is a new device
                let is_unusual_hour = hour < 6 || hour > 22;
                let severity = if is_unusual_hour {
                    AnomalySeverity::Medium
                } else {
                    AnomalySeverity::Low
                };

                new_anomalies.push(AnomalyReport {
                    timestamp: Local::now(),
                    anomaly_type: AnomalyType::NewDevice,
                    severity,
                    description: format!(
                        "New device detected: {} ({}) — {}",
                        device.primary_address(),
                        device.vendor.as_deref().unwrap_or("Unknown vendor"),
                        device.fingerprint
                    ),
                    evidence: vec![
                        format!("IP: {}", device.primary_address()),
                        format!("MAC: {}", mac),
                        format!(
                            "Vendor: {}",
                            device.vendor.as_deref().unwrap_or("Unknown")
                        ),
                        format!("Role: {}", device.role.label()),
                    ],
                    behavior_score: if is_unusual_hour { 0.7 } else { 0.3 },
                });

                self.baseline
                    .known_ips
                    .insert(mac.to_string(), device.addresses.clone());
                self.baseline
                    .first_seen
                    .insert(mac.to_string(), Local::now());
            } else {
                // Update last seen
                self.baseline
                    .last_seen
                    .insert(mac.to_string(), Local::now());

                // Check for IP change (potential spoofing or DHCP issue)
                if let Some(known_ips) = self.baseline.known_ips.get(mac) {
                    let new_ips: Vec<&str> = device
                        .addresses
                        .iter()
                        .map(|s| s.as_str())
                        .collect();
                    let changed = new_ips.iter().any(|ip| !known_ips.contains(&ip.to_string()));
                    if changed && known_ips.len() > 0 {
                        new_anomalies.push(AnomalyReport {
                            timestamp: Local::now(),
                            anomaly_type: AnomalyType::PortChange,
                            severity: AnomalySeverity::Medium,
                            description: format!(
                                "IP address changed for device {} ({}). Was: {}, Now: {}",
                                mac,
                                device.vendor.as_deref().unwrap_or("Unknown"),
                                known_ips.join(", "),
                                device.addresses.join(", ")
                            ),
                            evidence: vec![
                                format!("Previous IPs: {}", known_ips.join(", ")),
                                format!("Current IPs: {}", device.addresses.join(", ")),
                            ],
                            behavior_score: 0.5,
                        });
                    }
                }
            }
        }

        // Detect disappeared devices
        for (mac, last_seen) in &self.baseline.last_seen {
            let elapsed = Local::now().signed_duration_since(*last_seen);
            if elapsed.num_hours() > 24 {
                let ip = self
                    .baseline
                    .known_ips
                    .get(mac)
                    .and_then(|ips| ips.first())
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string());

                new_anomalies.push(AnomalyReport {
                    timestamp: Local::now(),
                    anomaly_type: AnomalyType::DeviceDisappear,
                    severity: AnomalySeverity::Info,
                    description: format!("Device {} ({}) has not been seen for over 24 hours.", ip, mac),
                    evidence: vec![
                        format!("Last seen: {}", last_seen.format("%Y-%m-%d %H:%M")),
                        format!("Hours since seen: {}", elapsed.num_hours()),
                    ],
                    behavior_score: 0.2,
                });
            }
        }

        // Detect unusual time patterns
        let current_hour_count = self.baseline.hourly_counts[hour];
        let avg_hourly = if self.baseline.scan_count > 0 {
            self.baseline.hourly_counts.iter().sum::<u32>() as f32 / 24.0
        } else {
            0.0
        };

        if avg_hourly > 0.0 && current_hour_count as f32 > avg_hourly * 3.0 && hour < 6 {
            new_anomalies.push(AnomalyReport {
                timestamp: Local::now(),
                anomaly_type: AnomalyType::TimeAnomaly,
                severity: AnomalySeverity::Medium,
                description: format!(
                    "Unusual activity spike at {}:00 — {} device events vs avg {:.0}.",
                    hour, current_hour_count, avg_hourly
                ),
                evidence: vec![
                    format!("Hour: {}:00", hour),
                    format!("Events this hour: {}", current_hour_count),
                    format!("Average per hour: {:.1}", avg_hourly),
                ],
                behavior_score: 0.6,
            });
        }

        // Run behavior analysis
        let behavior_anomalies = self
            .behavior_analyzer
            .analyze(networks, devices, &self.baseline);
        new_anomalies.extend(behavior_anomalies);

        // Store anomalies
        for anomaly in new_anomalies {
            self.anomalies.push_back(anomaly);
        }

        while self.anomalies.len() > self.max_anomalies {
            self.anomalies.pop_front();
        }

        self.anomalies.iter().rev().take(5).cloned().collect()
    }

    pub fn total_anomalies(&self) -> usize {
        self.anomalies.len()
    }

    pub fn high_severity_count(&self) -> usize {
        self.anomalies
            .iter()
            .filter(|a| a.severity >= AnomalySeverity::Medium)
            .count()
    }

    pub fn recent_anomalies(&self, count: usize) -> Vec<AnomalyReport> {
        self.anomalies.iter().rev().take(count).cloned().collect()
    }
}

impl Default for AiEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub type SharedAi = Arc<Mutex<AiEngine>>;

pub fn new_shared_ai() -> SharedAi {
    Arc::new(Mutex::new(AiEngine::new()))
}
