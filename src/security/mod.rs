pub mod deauth_detector;
pub mod evil_twin;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::models::Network;

// ── Security Alert ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub timestamp: DateTime<Local>,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub recommendation: String,
    pub source_bssid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlertType {
    EvilTwin,
    DowngradeAttack,
    RogueAP,
    SuspiciousVendor,
    HiddenAPSpike,
    DeauthFlood,
    Jamming,
    ProbeFlood,
    BeaconAnomaly,
    NewUnknownDevice,
}

impl AlertType {
    pub fn label(&self) -> &'static str {
        match self {
            AlertType::EvilTwin => "Evil Twin",
            AlertType::DowngradeAttack => "Downgrade Attack",
            AlertType::RogueAP => "Rogue AP",
            AlertType::SuspiciousVendor => "Suspicious Vendor",
            AlertType::HiddenAPSpike => "Hidden AP Spike",
            AlertType::DeauthFlood => "Deauth Flood",
            AlertType::Jamming => "Jamming",
            AlertType::ProbeFlood => "Probe Flood",
            AlertType::BeaconAnomaly => "Beacon Anomaly",
            AlertType::NewUnknownDevice => "New Device",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            AlertType::EvilTwin => "👯",
            AlertType::DowngradeAttack => "📉",
            AlertType::RogueAP => "🏴",
            AlertType::SuspiciousVendor => "⚠",
            AlertType::HiddenAPSpike => "👁",
            AlertType::DeauthFlood => "🚫",
            AlertType::Jamming => "📡",
            AlertType::ProbeFlood => "🔍",
            AlertType::BeaconAnomaly => "📡",
            AlertType::NewUnknownDevice => "🆕",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "Info",
            AlertSeverity::Low => "Low",
            AlertSeverity::Medium => "Medium",
            AlertSeverity::High => "High",
            AlertSeverity::Critical => "Critical",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            AlertSeverity::Info => "ℹ",
            AlertSeverity::Low => "🔵",
            AlertSeverity::Medium => "🟡",
            AlertSeverity::High => "🟠",
            AlertSeverity::Critical => "🔴",
        }
    }
}

// ── AP Fingerprint ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ApFingerprint {
    pub bssid: String,
    pub ssid: String,
    pub security: String,
    pub channel: u8,
    pub frequency: f32,
    pub vendor: Option<String>,
    pub first_seen: DateTime<Local>,
    pub last_seen: DateTime<Local>,
    pub signal_history: VecDeque<i32>,
}

impl ApFingerprint {
    pub fn from_network(network: &Network) -> Self {
        let mut signal_history = VecDeque::new();
        for (_, signal) in &network.signal_history {
            signal_history.push_back(*signal);
        }
        if signal_history.is_empty() {
            signal_history.push_back(network.signal_strength);
        }

        Self {
            bssid: network.bssid.clone(),
            ssid: network.ssid.clone(),
            security: network.security.clone(),
            channel: network.channel,
            frequency: network.frequency,
            vendor: network.vendor.clone(),
            first_seen: Local::now(),
            last_seen: Local::now(),
            signal_history,
        }
    }
}

// ── Security Engine ─────────────────────────────────────────────────

pub struct SecurityEngine {
    pub known_aps: HashMap<String, ApFingerprint>,
    pub alerts: VecDeque<SecurityAlert>,
    pub evil_twin_detector: evil_twin::EvilTwinDetector,
    pub deauth_detector: deauth_detector::DeauthDetector,
    pub max_alerts: usize,
}

impl SecurityEngine {
    pub fn new() -> Self {
        Self {
            known_aps: HashMap::new(),
            alerts: VecDeque::new(),
            evil_twin_detector: evil_twin::EvilTwinDetector::new(),
            deauth_detector: deauth_detector::DeauthDetector::new(),
            max_alerts: 200,
        }
    }

    /// Analyze a batch of networks for security threats.
    pub fn analyze(&mut self, networks: &[Network]) {
        // Update AP fingerprint database
        for network in networks {
            let entry = self
                .known_aps
                .entry(network.bssid.clone())
                .or_insert_with(|| ApFingerprint::from_network(network));

            entry.last_seen = Local::now();
            entry.signal_history.push_back(network.signal_strength);
            while entry.signal_history.len() > 48 {
                entry.signal_history.pop_front();
            }
        }

        // Run evil twin detection
        let new_alerts = self.evil_twin_detector.analyze(networks, &self.known_aps);
        for alert in new_alerts {
            self.push_alert(alert);
        }

        // Run deauth/jamming detection
        let deauth_alerts = self.deauth_detector.analyze(networks);
        for alert in deauth_alerts {
            self.push_alert(alert);
        }
    }

    fn push_alert(&mut self, alert: SecurityAlert) {
        // Deduplicate: don't fire same alert type within 60 seconds
        let is_duplicate = self.alerts.iter().any(|existing| {
            existing.alert_type == alert.alert_type
                && existing.timestamp.signed_duration_since(alert.timestamp).num_seconds().abs() < 60
        });

        if !is_duplicate {
            self.alerts.push_back(alert);
        }

        while self.alerts.len() > self.max_alerts {
            self.alerts.pop_front();
        }
    }

    pub fn critical_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| a.severity >= AlertSeverity::High)
            .count()
    }

    pub fn recent_alerts(&self, count: usize) -> Vec<SecurityAlert> {
        self.alerts.iter().rev().take(count).cloned().collect()
    }
}

impl Default for SecurityEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub type SharedSecurity = Arc<Mutex<SecurityEngine>>;

pub fn new_shared_security() -> SharedSecurity {
    Arc::new(Mutex::new(SecurityEngine::new()))
}
