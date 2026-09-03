pub mod nmap_runner;
pub mod port_database;
pub mod report;
pub mod scheduler;
pub mod vuln_correlator;

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::models::ConnectedDevice;

// ── Scan Tiers ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTier {
    Fast,
    Deep,
    Stealth,
}

impl ScanTier {
    pub fn label(&self) -> &'static str {
        match self {
            ScanTier::Fast => "Fast",
            ScanTier::Deep => "Deep",
            ScanTier::Stealth => "Stealth",
        }
    }

    pub fn nmap_args(&self, privileged: bool) -> Vec<&'static str> {
        match (self, privileged) {
            // Root: full OS fingerprinting + SYN stealth capability
            (ScanTier::Fast, true) => vec!["-sV", "-O", "-T4", "--top-ports", "100"],
            (ScanTier::Deep, true) => vec!["-sV", "-sC", "-p-", "-T3"],
            (ScanTier::Stealth, true) => vec!["-sS", "-Pn", "-T2", "--top-ports", "1000"],
            // Non-root: connect-scan only, no OS fingerprinting, no SYN
            (ScanTier::Fast, false) => vec!["-sV", "-T4", "--top-ports", "100"],
            (ScanTier::Deep, false) => vec!["-sV", "-sC", "-T3", "--top-ports", "5000"],
            (ScanTier::Stealth, false) => vec!["-sT", "-Pn", "-T2", "--top-ports", "1000"],
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            ScanTier::Fast => "⚡",
            ScanTier::Deep => "🔬",
            ScanTier::Stealth => "🕵",
        }
    }
}

// ── Scan Status ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStatus {
    Queued,
    Running,
    Completed,
    Failed(String),
}

impl ScanStatus {
    pub fn label(&self) -> String {
        match self {
            ScanStatus::Queued => "Queued".to_string(),
            ScanStatus::Running => "Scanning...".to_string(),
            ScanStatus::Completed => "Done".to_string(),
            ScanStatus::Failed(reason) => format!("Failed: {reason}"),
        }
    }
}

// ── Nmap Result Models ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapResult {
    pub os_guess: Vec<OsGuess>,
    pub ports: Vec<PortInfo>,
    pub scripts: Vec<ScriptOutput>,
    pub traceroute: Vec<String>,
    pub raw_xml: String,
}

impl Default for NmapResult {
    fn default() -> Self {
        Self {
            os_guess: Vec::new(),
            ports: Vec::new(),
            scripts: Vec::new(),
            traceroute: Vec::new(),
            raw_xml: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsGuess {
    pub name: String,
    pub accuracy: u8,
    pub cpe: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub version: String,
    pub extra_info: String,
    pub risk_level: PortRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortRisk {
    Safe,
    Info,
    Suspicious,
    Critical,
}

impl PortRisk {
    pub fn label(&self) -> &'static str {
        match self {
            PortRisk::Safe => "Safe",
            PortRisk::Info => "Info",
            PortRisk::Suspicious => "Suspicious",
            PortRisk::Critical => "Critical",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            PortRisk::Safe => "🟢",
            PortRisk::Info => "🔵",
            PortRisk::Suspicious => "🟡",
            PortRisk::Critical => "🔴",
        }
    }

    pub fn sort_key(&self) -> u8 {
        match self {
            PortRisk::Critical => 0,
            PortRisk::Suspicious => 1,
            PortRisk::Info => 2,
            PortRisk::Safe => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptOutput {
    pub id: String,
    pub output: String,
}

// ── Recon Target ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconTarget {
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub tier: ScanTier,
    pub status: ScanStatus,
    pub result: Option<NmapResult>,
    pub queued_at: DateTime<Local>,
    pub completed_at: Option<DateTime<Local>>,
}

impl ReconTarget {
    pub fn new(ip: String, mac: Option<String>, vendor: Option<String>, tier: ScanTier) -> Self {
        Self {
            ip,
            mac,
            vendor,
            tier,
            status: ScanStatus::Queued,
            result: None,
            queued_at: Local::now(),
            completed_at: None,
        }
    }

    pub fn risk_score(&self) -> u8 {
        self.result
            .as_ref()
            .map(|r| {
                let critical = r.ports.iter().filter(|p| p.risk_level == PortRisk::Critical).count();
                let suspicious = r.ports.iter().filter(|p| p.risk_level == PortRisk::Suspicious).count();
                let open = r.ports.iter().filter(|p| p.state == "open").count() as u8;

                let mut score = 0u8;
                score = score.saturating_add((critical as u8) * 25);
                score = score.saturating_add((suspicious as u8) * 10);
                score = score.saturating_add(open.min(10));
                score.min(100)
            })
            .unwrap_or(0)
    }
}

// ── Recon Engine ────────────────────────────────────────────────────

pub struct ReconEngine {
    pub targets: Vec<ReconTarget>,
    pub max_concurrent: usize,
    pub auto_scan_new_devices: bool,
    pub default_tier: ScanTier,
    pub last_full_scan: Option<DateTime<Local>>,
}

impl ReconEngine {
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            max_concurrent: 2,
            auto_scan_new_devices: true,
            default_tier: ScanTier::Fast,
            last_full_scan: None,
        }
    }

    pub fn queue_device(&mut self, device: &ConnectedDevice) {
        let ip = device.primary_address().to_string();
        if self.targets.iter().any(|t| t.ip == ip) {
            return;
        }

        if !nmap_runner::is_nmap_available() {
            return;
        }

        let mac = device.mac_address.clone();
        let vendor = device.vendor.clone();
        let target = ReconTarget::new(ip, mac, vendor, self.default_tier);
        self.targets.push(target);
    }

    pub fn queue_target(&mut self, ip: String, tier: ScanTier) {
        if self.targets.iter().any(|t| t.ip == ip) {
            return;
        }
        self.targets.push(ReconTarget::new(ip, None, None, tier));
    }

    pub fn running_count(&self) -> usize {
        self.targets
            .iter()
            .filter(|t| t.status == ScanStatus::Running)
            .count()
    }

    pub fn completed_count(&self) -> usize {
        self.targets
            .iter()
            .filter(|t| t.status == ScanStatus::Completed)
            .count()
    }

    pub fn total_risk_score(&self) -> u8 {
        if self.targets.is_empty() {
            return 0;
        }
        let sum: u32 = self.targets.iter().map(|t| t.risk_score() as u32).sum();
        (sum / self.targets.len() as u32).min(100) as u8
    }

    pub fn critical_ports(&self) -> Vec<(ReconTarget, PortInfo)> {
        self.targets
            .iter()
            .filter_map(|target| {
                target.result.as_ref().map(|result| {
                    result
                        .ports
                        .iter()
                        .filter(|p| p.risk_level == PortRisk::Critical)
                        .map(move |port| (target.clone(), port.clone()))
                })
            })
            .flatten()
            .collect()
    }

    pub fn scan_next_pending(&mut self) -> Option<String> {
        if self.running_count() >= self.max_concurrent {
            return None;
        }

        let pending = self
            .targets
            .iter_mut()
            .find(|t| t.status == ScanStatus::Queued);

        pending.map(|target| {
            target.status = ScanStatus::Running;
            target.ip.clone()
        })
    }
}

impl Default for ReconEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether the current process is running as root (effective UID 0).
/// nmap's OS detection (-O) and SYN stealth scans (-sS) require this.
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    let fields: Vec<&str> = rest.split_whitespace().collect();
                    // Uid: real, effective, saved, fs — check effective
                    if fields.len() >= 2 {
                        return fields[1] == "0";
                    }
                }
            }
        }
        false
    }
    #[cfg(not(unix))]
    {
        false
    }
}

// ── Shared State ────────────────────────────────────────────────────

pub type SharedRecon = Arc<Mutex<ReconEngine>>;

pub fn new_shared_recon() -> SharedRecon {
    Arc::new(Mutex::new(ReconEngine::new()))
}
