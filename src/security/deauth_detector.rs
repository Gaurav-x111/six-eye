use std::collections::HashMap;

use crate::models::Network;

use super::{AlertSeverity, AlertType, SecurityAlert};

pub struct DeauthDetector {
    /// BSSID → rolling average signal strength (baseline)
    baselines: HashMap<String, f32>,
    /// Track signal drops per BSSID
    drop_counts: HashMap<String, u32>,
    /// Number of scans since baselines were established
    scan_count: u32,
}

impl DeauthDetector {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            drop_counts: HashMap::new(),
            scan_count: 0,
        }
    }

    pub fn analyze(&mut self, networks: &[Network]) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();
        self.scan_count += 1;

        // Need at least 3 scans to establish baselines
        if self.scan_count < 3 {
            self.update_baselines(networks);
            return alerts;
        }

        // Check 1: Sudden signal drops across multiple APs (jamming/deauth)
        let mut drop_count = 0u32;
        let mut total_ap_count = 0u32;
        let mut dropped_aps = Vec::new();

        for network in networks {
            if let Some(&baseline) = self.baselines.get(&network.bssid) {
                total_ap_count += 1;
                let drop = baseline - network.signal_strength as f32;

                // Signal dropped more than 20 dB from baseline
                if drop > 20.0 {
                    drop_count += 1;
                    dropped_aps.push(format!(
                        "{} ({} → {} dBm, dropped {:.0} dB)",
                        network.ssid,
                        baseline as i32,
                        network.signal_strength,
                        drop
                    ));

                    *self.drop_counts.entry(network.bssid.clone()).or_insert(0) += 1;
                }
            }
        }

        // If more than 40% of APs dropped simultaneously, likely jamming
        if total_ap_count > 2 && drop_count > 0 {
            let drop_ratio = drop_count as f32 / total_ap_count as f32;

            if drop_ratio > 0.4 {
                alerts.push(SecurityAlert {
                    timestamp: chrono::Local::now(),
                    alert_type: AlertType::Jamming,
                    severity: AlertSeverity::Critical,
                    title: "Possible WiFi jamming detected".to_string(),
                    description: format!(
                        "{} out of {} access points experienced simultaneous signal drops exceeding 20 dB. \
                         This pattern is consistent with WiFi jamming or a deauth flood.",
                        drop_count, total_ap_count
                    ),
                    evidence: dropped_aps,
                    recommendation: "Check for unauthorized transmission sources nearby. If this persists, it may be a deliberate jamming attack.".to_string(),
                    source_bssid: None,
                });
            } else if drop_ratio > 0.2 {
                alerts.push(SecurityAlert {
                    timestamp: chrono::Local::now(),
                    alert_type: AlertType::DeauthFlood,
                    severity: AlertSeverity::High,
                    title: "Possible deauthentication flood".to_string(),
                    description: format!(
                        "{} out of {} access points experienced significant signal drops. \
                         This may indicate targeted deauthentication attacks.",
                        drop_count, total_ap_count
                    ),
                    evidence: dropped_aps,
                    recommendation: "Monitor the situation. If specific APs are consistently targeted, investigate the source.".to_string(),
                    source_bssid: None,
                });
            }
        }

        // Check 2: Single AP with repeated drops (targeted deauth)
        let mut drops_to_reset: Vec<String> = Vec::new();
        for (bssid, &count) in &self.drop_counts {
            if count >= 5 {
                if let Some(network) = networks.iter().find(|n| &n.bssid == bssid) {
                    alerts.push(SecurityAlert {
                        timestamp: chrono::Local::now(),
                        alert_type: AlertType::DeauthFlood,
                        severity: AlertSeverity::Medium,
                        title: format!(
                            "Repeated signal drops on \"{}\"",
                            if network.is_hidden() {
                                &network.bssid
                            } else {
                                &network.ssid
                            }
                        ),
                        description: format!(
                            "AP {} ({}) has experienced {} significant signal drops. \
                             This may indicate targeted deauthentication.",
                            network.ssid, network.bssid, count
                        ),
                        evidence: vec![
                            format!("BSSID: {}", network.bssid),
                            format!("Signal: {} dBm", network.signal_strength),
                            format!("Drop count: {}", count),
                            format!("Vendor: {}", network.vendor.as_deref().unwrap_or("Unknown")),
                        ],
                        recommendation: "Investigate the AP. Consider changing the WiFi password and enabling 802.11w (Protected Management Frames).".to_string(),
                        source_bssid: Some(network.bssid.clone()),
                    });
                    drops_to_reset.push(bssid.clone());
                }
            }
        }

        // Reset counters for alarmed APs
        for bssid in drops_to_reset {
            if let Some(counter) = self.drop_counts.get_mut(&bssid) {
                *counter = 0;
            }
        }

        // Update baselines with exponential moving average
        self.update_baselines(networks);

        alerts
    }

    fn update_baselines(&mut self, networks: &[Network]) {
        let alpha = 0.3; // EMA smoothing factor

        for network in networks {
            let current = network.signal_strength as f32;
            let entry = self
                .baselines
                .entry(network.bssid.clone())
                .or_insert(current);

            *entry = *entry * (1.0 - alpha) + current * alpha;
        }
    }
}
