use serde::{Deserialize, Serialize};

use super::{NmapResult, PortInfo, PortRisk};

// ── Vulnerability Database ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnEntry {
    pub cve_id: String,
    pub severity: VulnSeverity,
    pub description: String,
    pub affected_versions: String,
    pub cvss_score: f32,
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl VulnSeverity {
    pub fn label(&self) -> &'static str {
        match self {
            VulnSeverity::Critical => "Critical",
            VulnSeverity::High => "High",
            VulnSeverity::Medium => "Medium",
            VulnSeverity::Low => "Low",
            VulnSeverity::Info => "Info",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            VulnSeverity::Critical => "🔴",
            VulnSeverity::High => "🟠",
            VulnSeverity::Medium => "🟡",
            VulnSeverity::Low => "🔵",
            VulnSeverity::Info => "⚪",
        }
    }

    pub fn sort_key(&self) -> u8 {
        match self {
            VulnSeverity::Critical => 0,
            VulnSeverity::High => 1,
            VulnSeverity::Medium => 2,
            VulnSeverity::Low => 3,
            VulnSeverity::Info => 4,
        }
    }
}

// ── Scan Result with Vulnerabilities ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnScanResult {
    pub target_ip: String,
    pub total_ports_scanned: usize,
    pub open_ports: usize,
    pub vulnerable_ports: usize,
    pub findings: Vec<VulnFinding>,
    pub risk_score: u8,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnFinding {
    pub port: u16,
    pub service: String,
    pub version: String,
    pub risk_level: PortRisk,
    pub vulns: Vec<VulnEntry>,
    pub recommendation: String,
}

// ── Built-in Vulnerability Signatures ───────────────────────────────

fn built_in_signatures() -> Vec<(&'static str, Vec<VulnEntry>)> {
    vec![
        (
            "telnet",
            vec![VulnEntry {
                cve_id: "PLAIN-TEXT".to_string(),
                severity: VulnSeverity::Critical,
                description: "Telnet transmits all data including credentials in plaintext. Any observer on the network can capture usernames and passwords.".to_string(),
                affected_versions: "All Telnet implementations".to_string(),
                cvss_score: 9.1,
                recommendation: "Replace Telnet with SSH (port 22) for encrypted remote access. Disable the Telnet service immediately.".to_string(),
            }],
        ),
        (
            "smbv1",
            vec![
                VulnEntry {
                    cve_id: "CVE-2017-0144".to_string(),
                    severity: VulnSeverity::Critical,
                    description: "SMBv1 is vulnerable to EternalBlue exploit, used by WannaCry and NotPetya ransomware.".to_string(),
                    affected_versions: "SMBv1 / SMB 1.0".to_string(),
                    cvss_score: 9.8,
                    recommendation: "Disable SMBv1 protocol. Upgrade to SMBv2 or SMBv3.".to_string(),
                },
                VulnEntry {
                    cve_id: "CVE-2017-0145".to_string(),
                    severity: VulnSeverity::Critical,
                    description: "SMBv1 vulnerable to EternalRomance exploit for remote code execution.".to_string(),
                    affected_versions: "SMBv1 / SMB 1.0".to_string(),
                    cvss_score: 9.3,
                    recommendation: "Disable SMBv1 immediately. Apply Microsoft security patches.".to_string(),
                },
            ],
        ),
        (
            "ftp-anon",
            vec![VulnEntry {
                cve_id: "ANON-FTP".to_string(),
                severity: VulnSeverity::High,
                description: "FTP server allows anonymous access. Unauthorized users can read or upload files.".to_string(),
                affected_versions: "FTP servers with anonymous login enabled".to_string(),
                cvss_score: 7.5,
                recommendation: "Disable anonymous FTP access. Use SFTP or FTPS with authentication.".to_string(),
            }],
        ),
        (
            "vnc",
            vec![VulnEntry {
                cve_id: "VNC-NOAUTH".to_string(),
                severity: VulnSeverity::High,
                description: "VNC server detected without authentication or with weak password. Remote desktop can be accessed by anyone on the network.".to_string(),
                affected_versions: "VNC without authentication".to_string(),
                cvss_score: 8.0,
                recommendation: "Configure VNC to require strong passwords. Use SSH tunneling for VNC access.".to_string(),
            }],
        ),
        (
            "rdp",
            vec![
                VulnEntry {
                    cve_id: "CVE-2019-0708".to_string(),
                    severity: VulnSeverity::Critical,
                    description: "BlueKeep — RDP remote code execution vulnerability. Wormable exploit that can spread without user interaction.".to_string(),
                    affected_versions: "Windows 7, Server 2008, XP".to_string(),
                    cvss_score: 9.8,
                    recommendation: "Apply Microsoft patch KB4499175. Enable NLA. Consider disabling RDP if not needed.".to_string(),
                },
                VulnEntry {
                    cve_id: "CVE-2023-36884".to_string(),
                    severity: VulnSeverity::High,
                    description: "Office and Windows HTML RCE vulnerability via crafted documents.".to_string(),
                    affected_versions: "Multiple Windows versions".to_string(),
                    cvss_score: 8.3,
                    recommendation: "Apply security updates. Enable attack surface reduction rules.".to_string(),
                },
            ],
        ),
        (
            "http-admin",
            vec![VulnEntry {
                cve_id: "ADMIN-EXPOSED".to_string(),
                severity: VulnSeverity::Medium,
                description: "Web administration panel exposed on the network. May be target for brute-force attacks.".to_string(),
                affected_versions: "Various admin interfaces".to_string(),
                cvss_score: 5.3,
                recommendation: "Restrict admin panel access to specific IPs. Use VPN for remote administration. Enable 2FA.".to_string(),
            }],
        ),
        (
            "upnp",
            vec![VulnEntry {
                cve_id: "UPNP-SSRF".to_string(),
                severity: VulnSeverity::Medium,
                description: "UPnP service exposed. May allow SSRF attacks and port forwarding manipulation.".to_string(),
                affected_versions: "UPnP implementations".to_string(),
                cvss_score: 5.0,
                recommendation: "Disable UPnP on the router. Block UPnP ports (1900/5000) at the firewall.".to_string(),
            }],
        ),
        (
            "snmp-public",
            vec![VulnEntry {
                cve_id: "SNMP-PUBLIC".to_string(),
                severity: VulnSeverity::High,
                description: "SNMP using default 'public' community string. Allows network enumeration and device configuration.".to_string(),
                affected_versions: "SNMPv1/v2c with default community strings".to_string(),
                cvss_score: 7.5,
                recommendation: "Change SNMP community strings. Upgrade to SNMPv3 with authentication and encryption.".to_string(),
            }],
        ),
        (
            "netbios",
            vec![VulnEntry {
                cve_id: "NETBIOS-INFO".to_string(),
                severity: VulnSeverity::Low,
                description: "NetBIOS service exposed. Leaks device names, domain information, and shared resources.".to_string(),
                affected_versions: "Windows NetBIOS".to_string(),
                cvss_score: 3.7,
                recommendation: "Disable NetBIOS over TCP/IP if not needed. Use firewall rules to restrict access.".to_string(),
            }],
        ),
    ]
}

// ── Correlation Engine ──────────────────────────────────────────────

pub fn correlate_vulnerabilities(target_ip: &str, nmap_result: &NmapResult) -> VulnScanResult {
    let signatures = built_in_signatures();
    let mut findings: Vec<VulnFinding> = Vec::new();

    for port_info in &nmap_result.ports {
        if port_info.state != "open" {
            continue;
        }

        let mut matched_vulns: Vec<VulnEntry> = Vec::new();
        let service_lower = port_info.service.to_ascii_lowercase();
        let version_lower = port_info.version.to_ascii_lowercase();
        let combined = format!("{} {}", service_lower, version_lower);

        // Check built-in signatures
        for (sig_key, vulns) in &signatures {
            if matched_by_signature(port_info.port, &combined, sig_key) {
                matched_vulns.extend(vulns.iter().cloned());
            }
        }

        // Version-specific checks
        if version_lower.contains("apache/2.2") {
            matched_vulns.push(VulnEntry {
                cve_id: "EOL-SOFTWARE".to_string(),
                severity: VulnSeverity::Medium,
                description: "Apache 2.2 is end-of-life and no longer receives security updates.".to_string(),
                affected_versions: "Apache 2.2.x".to_string(),
                cvss_score: 5.0,
                recommendation: "Upgrade to Apache 2.4.x or later.".to_string(),
            });
        }

        if version_lower.contains("openssh") {
            let version = extract_version_number(&version_lower);
            if let Some(ver) = version {
                if ver < 7.4 {
                    matched_vulns.push(VulnEntry {
                        cve_id: "OLD-OPENSSH".to_string(),
                        severity: VulnSeverity::Medium,
                        description: format!("OpenSSH {ver} is outdated and may contain known vulnerabilities."),
                        affected_versions: format!("OpenSSH < 7.4"),
                        cvss_score: 5.0,
                        recommendation: "Upgrade OpenSSH to the latest stable version.".to_string(),
                    });
                }
            }
        }

        if version_lower.contains("nginx") && version_lower.contains("1.0") {
            matched_vulns.push(VulnEntry {
                cve_id: "OLD-NGINX".to_string(),
                severity: VulnSeverity::Medium,
                description: "Nginx 1.0.x is severely outdated with multiple known vulnerabilities.".to_string(),
                affected_versions: "Nginx 1.0.x".to_string(),
                cvss_score: 6.0,
                recommendation: "Upgrade Nginx to the latest stable version.".to_string(),
            });
        }

        if port_info.risk_level == PortRisk::Critical && matched_vulns.is_empty() {
            matched_vulns.push(VulnEntry {
                cve_id: format!("HIGH-RISK-PORT-{}", port_info.port),
                severity: VulnSeverity::High,
                description: format!(
                    "Port {} ({}) is classified as high-risk. {}",
                    port_info.port,
                    port_info.service,
                    super::port_database::port_description(port_info.port, &port_info.service)
                ),
                affected_versions: port_info.version.clone(),
                cvss_score: 7.0,
                recommendation: "Review and restrict access to this service. Consider disabling if not needed.".to_string(),
            });
        }

        if !matched_vulns.is_empty() {
            findings.push(VulnFinding {
                port: port_info.port,
                service: port_info.service.clone(),
                version: port_info.version.clone(),
                risk_level: port_info.risk_level,
                vulns: matched_vulns,
                recommendation: generate_recommendation(port_info),
            });
        }
    }

    findings.sort_by(|a, b| {
        a.risk_level
            .sort_key()
            .cmp(&b.risk_level.sort_key())
            .then_with(|| a.port.cmp(&b.port))
    });

    let open_ports = nmap_result.ports.iter().filter(|p| p.state == "open").count();
    let vulnerable_ports = findings.len();
    let critical_count = findings
        .iter()
        .filter(|f| f.risk_level == PortRisk::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.risk_level == PortRisk::Suspicious)
        .count();

    let risk_score = compute_risk_score(critical_count, high_count, open_ports);

    let summary = if findings.is_empty() {
        format!(
            "No known vulnerabilities found across {} open ports.",
            open_ports
        )
    } else {
        format!(
            "Found {} vulnerabilities across {} ports. {} critical, {} suspicious.",
            findings.len(),
            vulnerable_ports,
            critical_count,
            high_count
        )
    };

    VulnScanResult {
        target_ip: target_ip.to_string(),
        total_ports_scanned: nmap_result.ports.len(),
        open_ports,
        vulnerable_ports,
        findings,
        risk_score,
        summary,
    }
}

fn matched_by_signature(port: u16, combined: &str, sig_key: &str) -> bool {
    match sig_key {
        "telnet" => port == 23 || combined.contains("telnet"),
        "smbv1" => combined.contains("smbv1") || combined.contains("smb 1") || combined.contains("samba 3"),
        "ftp-anon" => combined.contains("ftp") && combined.contains("anonymous"),
        "vnc" => (5900..=5999).contains(&port) || combined.contains("vnc"),
        "rdp" => port == 3389 || combined.contains("rdp") || combined.contains("ms-wbt"),
        "http-admin" => (8080..=8888).contains(&port) || port == 8443,
        "upnp" => combined.contains("upnp") || combined.contains("ssdp"),
        "snmp-public" => combined.contains("snmp") && combined.contains("public"),
        "netbios" => (135..=139).contains(&port) || combined.contains("netbios"),
        _ => false,
    }
}

fn extract_version_number(version_str: &str) -> Option<f32> {
    let parts: Vec<&str> = version_str.split_whitespace().collect();
    for part in &parts {
        let nums: Vec<&str> = part.split('.').collect();
        if nums.len() >= 2 {
            if let (Some(major), Some(minor)) = (nums[0].parse::<f32>().ok(), nums[1].parse::<f32>().ok()) {
                return Some(major + minor / 10.0);
            }
        }
    }
    None
}

fn compute_risk_score(critical: usize, high: usize, open_ports: usize) -> u8 {
    let mut score = 0u32;
    score += (critical as u32) * 30;
    score += (high as u32) * 15;
    score += (open_ports as u32) * 2;
    (score.min(100)) as u8
}

fn generate_recommendation(port_info: &PortInfo) -> String {
    match port_info.port {
        23 => "Replace Telnet with SSH for encrypted remote access.".to_string(),
        21 => "Use SFTP or FTPS instead of plain FTP. Disable if not needed.".to_string(),
        3389 => "Enable NLA on RDP. Use VPN for remote desktop access.".to_string(),
        445 => "Restrict SMB access. Disable SMBv1. Use firewall rules.".to_string(),
        5900 => "Use SSH tunneling for VNC. Set strong passwords.".to_string(),
        80 | 8080 => "Ensure admin panels require authentication. Use HTTPS.".to_string(),
        161 => "Change SNMP community strings. Upgrade to SNMPv3.".to_string(),
        _ => format!("Review {} service and restrict access if not needed.", port_info.service),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telnet_is_critical() {
        let risk = super::super::port_database::classify_port_risk(23, "telnet", "");
        assert_eq!(risk, PortRisk::Critical);
    }

    #[test]
    fn test_ssh_is_safe() {
        let risk = super::super::port_database::classify_port_risk(22, "ssh", "");
        assert_eq!(risk, PortRisk::Safe);
    }

    #[test]
    fn test_risk_score_computation() {
        let score = compute_risk_score(2, 3, 10);
        assert!(score > 50);
    }
}
