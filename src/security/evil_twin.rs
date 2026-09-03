use std::collections::HashMap;

use crate::models::Network;

use super::{AlertSeverity, AlertType, ApFingerprint, SecurityAlert};

pub struct EvilTwinDetector {
    /// SSID → list of known BSSIDs for that SSID
    ssid_bssids: HashMap<String, Vec<String>>,
    /// BSSID → known security type
    bssid_security: HashMap<String, String>,
    /// BSSID → known channel
    bssid_channel: HashMap<String, u8>,
}

impl EvilTwinDetector {
    pub fn new() -> Self {
        Self {
            ssid_bssids: HashMap::new(),
            bssid_security: HashMap::new(),
            bssid_channel: HashMap::new(),
        }
    }

    pub fn analyze(
        &mut self,
        networks: &[Network],
        _known_aps: &HashMap<String, ApFingerprint>,
    ) -> Vec<SecurityAlert> {
        let mut alerts = Vec::new();

        // Build current SSID → BSSID mapping
        let mut current_ssid_map: HashMap<String, Vec<&Network>> = HashMap::new();
        for network in networks {
            current_ssid_map
                .entry(network.ssid.clone())
                .or_default()
                .push(network);
        }

        // Check 1: Same SSID with multiple BSSIDs (possible evil twin)
        for (ssid, networks_with_ssid) in &current_ssid_map {
            if networks_with_ssid.len() < 2 {
                continue;
            }

            // Check if all BSSIDs are from the same vendor
            let vendors: Vec<Option<&str>> = networks_with_ssid
                .iter()
                .map(|n| n.vendor.as_deref())
                .collect();
            let unique_vendors: Vec<&str> = vendors
                .iter()
                .filter_map(|v| *v)
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            // If multiple BSSIDs with same SSID from DIFFERENT vendors → evil twin likely
            if unique_vendors.len() > 1 && networks_with_ssid.len() >= 2 {
                alerts.push(SecurityAlert {
                    timestamp: chrono::Local::now(),
                    alert_type: AlertType::EvilTwin,
                    severity: AlertSeverity::Critical,
                    title: format!("Evil Twin detected: \"{ssid}\""),
                    description: format!(
                        "Multiple access points broadcasting SSID \"{}\" from different vendors detected. \
                         This is a strong indicator of an evil twin attack.",
                        ssid
                    ),
                    evidence: networks_with_ssid
                        .iter()
                        .map(|n| {
                            format!(
                                "BSSID {} — {} — {} dBm — {}",
                                n.bssid,
                                n.vendor.as_deref().unwrap_or("Unknown"),
                                n.signal_strength,
                                n.security
                            )
                        })
                        .collect(),
                    recommendation: "Investigate the rogue AP. Connect only to your known, trusted access point. Change your WiFi password immediately.".to_string(),
                    source_bssid: networks_with_ssid.first().map(|n| n.bssid.clone()),
                });
            }

            // Check 2: Same SSID, same vendor, but different security types (downgrade)
            let securities: Vec<&str> = networks_with_ssid
                .iter()
                .map(|n| n.security.as_str())
                .collect();
            let unique_securities: Vec<&str> = securities
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .copied()
                .collect();

            if unique_securities.len() > 1 && networks_with_ssid.len() >= 2 {
                let has_open = unique_securities.iter().any(|s| *s == "Open");
                if has_open {
                    alerts.push(SecurityAlert {
                        timestamp: chrono::Local::now(),
                        alert_type: AlertType::DowngradeAttack,
                        severity: AlertSeverity::High,
                        title: format!("Security downgrade on \"{ssid}\""),
                        description: format!(
                            "SSID \"{}\" is broadcast with mixed security types including Open. \
                             An attacker may be running a downgrade AP to capture credentials.",
                            ssid
                        ),
                        evidence: networks_with_ssid
                            .iter()
                            .map(|n| format!("{} — {} — {}", n.bssid, n.security, n.vendor.as_deref().unwrap_or("?")))
                            .collect(),
                        recommendation: "Only connect to the encrypted version of this network. Report the open AP to your network administrator.".to_string(),
                        source_bssid: networks_with_ssid
                            .iter()
                            .find(|n| n.security == "Open")
                            .map(|n| n.bssid.clone()),
                    });
                }
            }
        }

        // Check 3: Hidden AP with unusually high signal (possible rogue)
        for network in networks {
            if network.is_hidden() && network.signal_strength > -40 {
                alerts.push(SecurityAlert {
                    timestamp: chrono::Local::now(),
                    alert_type: AlertType::HiddenAPSpike,
                    severity: AlertSeverity::Medium,
                    title: "High-signal hidden AP detected".to_string(),
                    description: format!(
                        "Hidden access point {} is broadcasting with unusually strong signal ({} dBm). \
                         This may indicate a rogue AP in close proximity.",
                        network.bssid, network.signal_strength
                    ),
                    evidence: vec![
                        format!("BSSID: {}", network.bssid),
                        format!("Signal: {} dBm", network.signal_strength),
                        format!("Channel: {}", network.channel),
                        format!("Band: {}", network.band_label()),
                    ],
                    recommendation: "Investigate the source. A hidden AP this close to your device is unusual.".to_string(),
                    source_bssid: Some(network.bssid.clone()),
                });
            }
        }

        // Check 4: New BSSID appearing with a known SSID
        for (ssid, networks_with_ssid) in &current_ssid_map {
            if let Some(known_bssids) = self.ssid_bssids.get(ssid) {
                for network in networks_with_ssid {
                    if !known_bssids.contains(&network.bssid) && !network.is_hidden() {
                        alerts.push(SecurityAlert {
                            timestamp: chrono::Local::now(),
                            alert_type: AlertType::RogueAP,
                            severity: AlertSeverity::High,
                            title: format!("New BSSID for known SSID: \"{}\"", ssid),
                            description: format!(
                                "A new access point {} is broadcasting SSID \"{}\" which was previously associated with different BSSIDs. \
                                 This could be a rogue AP.",
                                network.bssid, ssid
                            ),
                            evidence: vec![
                                format!("New BSSID: {}", network.bssid),
                                format!("Vendor: {}", network.vendor.as_deref().unwrap_or("Unknown")),
                                format!("Known BSSIDs: {}", known_bssids.join(", ")),
                            ],
                            recommendation: "Verify this AP is authorized. Check the MAC address against your network inventory.".to_string(),
                            source_bssid: Some(network.bssid.clone()),
                        });
                    }
                }
            }
        }

        // Update internal state
        for network in networks {
            self.ssid_bssids
                .entry(network.ssid.clone())
                .or_default();
            let bssids = self.ssid_bssids.get_mut(&network.ssid).unwrap();
            if !bssids.contains(&network.bssid) {
                bssids.push(network.bssid.clone());
            }
            self.bssid_security
                .insert(network.bssid.clone(), network.security.clone());
            self.bssid_channel
                .insert(network.bssid.clone(), network.channel);
        }

        alerts
    }
}
