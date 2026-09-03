use std::collections::HashMap;

use crate::models::{ConnectedDevice, Network};

use super::{AnomalyReport, AnomalySeverity, AnomalyType, BehaviorBaseline};

pub struct BehaviorAnalyzer {
    /// Track signal variance patterns per BSSID
    signal_patterns: HashMap<String, Vec<f32>>,
    /// Known device count at last scan
    last_device_count: usize,
}

impl BehaviorAnalyzer {
    pub fn new() -> Self {
        Self {
            signal_patterns: HashMap::new(),
            last_device_count: 0,
        }
    }

    pub fn analyze(
        &mut self,
        networks: &[Network],
        devices: &[ConnectedDevice],
        baseline: &BehaviorBaseline,
    ) -> Vec<AnomalyReport> {
        let mut anomalies = Vec::new();

        // Check 1: Sudden device count change (possible subnet scan)
        let device_count = devices.len();
        if self.last_device_count > 0 {
            let delta = if device_count > self.last_device_count {
                device_count - self.last_device_count
            } else {
                self.last_device_count - device_count
            };

            // More than 3 devices appeared/disappeared at once
            if delta > 3 {
                anomalies.push(AnomalyReport {
                    timestamp: chrono::Local::now(),
                    anomaly_type: AnomalyType::SubnetScan,
                    severity: AnomalySeverity::High,
                    description: format!(
                        "Sudden {} device {} detected ({} → {}). Possible network scan or enumeration.",
                        delta,
                        if device_count > self.last_device_count {
                            "addition"
                        } else {
                            "disappearance"
                        },
                        self.last_device_count,
                        device_count
                    ),
                    evidence: vec![
                        format!("Previous count: {}", self.last_device_count),
                        format!("Current count: {}", device_count),
                        format!("Delta: {}", delta),
                    ],
                    behavior_score: 0.8,
                });
            }
        }
        self.last_device_count = device_count;

        // Check 2: Signal pattern anomalies (sustained unusual variance)
        for network in networks {
            let variance = network.signal_stddev();
            let entry = self
                .signal_patterns
                .entry(network.bssid.clone())
                .or_default();
            entry.push(variance);
            while entry.len() > 30 {
                entry.remove(0);
            }

            // If we have enough history, check for sustained high variance
            if entry.len() >= 10 {
                let recent_avg: f32 = entry.iter().rev().take(5).sum::<f32>() / 5.0;
                let historical_avg: f32 = entry.iter().take(entry.len() - 5).sum::<f32>()
                    / (entry.len() - 5).max(1) as f32;

                // Recent variance is 3x higher than historical
                if historical_avg > 0.0 && recent_avg > historical_avg * 3.0 && recent_avg > 2.0 {
                    anomalies.push(AnomalyReport {
                        timestamp: chrono::Local::now(),
                        anomaly_type: AnomalyType::SignalAnomaly,
                        severity: AnomalySeverity::Medium,
                        description: format!(
                            "Unusual signal variance on \"{}\" ({}) — recent {:.2} vs historical {:.2}",
                            network.ssid, network.bssid, recent_avg, historical_avg
                        ),
                        evidence: vec![
                            format!("BSSID: {}", network.bssid),
                            format!("Recent stddev: {:.2}", recent_avg),
                            format!("Historical stddev: {:.2}", historical_avg),
                            format!("Signal: {} dBm", network.signal_strength),
                        ],
                        behavior_score: 0.5,
                    });
                }
            }
        }

        // Check 3: Vendor mismatch (known MAC with unexpected vendor)
        for device in devices {
            if let (Some(mac), Some(vendor)) = (&device.mac_address, &device.vendor) {
                if let Some(known_vendor) = baseline.known_ips.get(mac) {
                    // This is a simple heuristic — in real implementation
                    // you'd store vendor history per MAC
                    let _ = known_vendor;
                    let _ = vendor;
                }
            }
        }

        anomalies
    }
}
