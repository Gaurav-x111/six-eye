use chrono::Local;
use serde::Serialize;

use super::vuln_correlator::VulnSeverity;
use super::{PortRisk, ReconEngine};

// ── Recon Report ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ReconReport {
    pub generated_at: String,
    pub total_devices: usize,
    pub scanned_devices: usize,
    pub total_open_ports: usize,
    pub critical_findings: usize,
    pub suspicious_findings: usize,
    pub overall_risk_score: u8,
    pub device_reports: Vec<DeviceReport>,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceReport {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub os: String,
    pub open_ports: usize,
    pub critical_ports: usize,
    pub risk_score: u8,
    pub status: String,
    pub ports_summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Recommendation {
    pub priority: Priority,
    pub title: String,
    pub description: String,
    pub affected_ips: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

impl Priority {
    pub fn label(&self) -> &'static str {
        match self {
            Priority::Critical => "CRITICAL",
            Priority::High => "HIGH",
            Priority::Medium => "MEDIUM",
            Priority::Low => "LOW",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Priority::Critical => "🔴",
            Priority::High => "🟠",
            Priority::Medium => "🟡",
            Priority::Low => "🔵",
        }
    }
}

// ── Report Generation ───────────────────────────────────────────────

pub fn generate_report(engine: &ReconEngine) -> ReconReport {
    let mut device_reports = Vec::new();
    let mut recommendations = Vec::new();
    let mut total_open_ports = 0usize;
    let mut critical_findings = 0usize;
    let mut suspicious_findings = 0usize;

    for target in &engine.targets {
        let result = target.result.as_ref();
        let open_ports = result
            .map(|r| r.ports.iter().filter(|p| p.state == "open").count())
            .unwrap_or(0);
        let critical_ports = result
            .map(|r| {
                r.ports
                    .iter()
                    .filter(|p| p.state == "open" && p.risk_level == PortRisk::Critical)
                    .count()
            })
            .unwrap_or(0);
        let suspicious = result
            .map(|r| {
                r.ports
                    .iter()
                    .filter(|p| p.state == "open" && p.risk_level == PortRisk::Suspicious)
                    .count()
            })
            .unwrap_or(0);

        total_open_ports += open_ports;
        critical_findings += critical_ports;
        suspicious_findings += suspicious;

        let os = result
            .and_then(|r| r.os_guess.first())
            .map(|os| format!("{} ({}%)", os.name, os.accuracy))
            .unwrap_or_else(|| "Unknown".to_string());

        let ports_summary = result
            .map(|r| {
                r.ports
                    .iter()
                    .filter(|p| p.state == "open")
                    .map(|p| format!("{}/{}[{}]", p.port, p.protocol, p.service))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|| "No scan data".to_string());

        device_reports.push(DeviceReport {
            ip: target.ip.clone(),
            mac: target.mac.clone().unwrap_or_else(|| "Unknown".to_string()),
            vendor: target.vendor.clone().unwrap_or_else(|| "Unknown".to_string()),
            os,
            open_ports,
            critical_ports,
            risk_score: target.risk_score(),
            status: target.status.label(),
            ports_summary,
        });

        // Generate recommendations for this target
        if let Some(vuln_result) = result {
            let vuln_scan = super::vuln_correlator::correlate_vulnerabilities(&target.ip, vuln_result);
            for finding in &vuln_scan.findings {
                for vuln in &finding.vulns {
                    recommendations.push(Recommendation {
                        priority: match vuln.severity {
                            VulnSeverity::Critical => Priority::Critical,
                            VulnSeverity::High => Priority::High,
                            VulnSeverity::Medium => Priority::Medium,
                            _ => Priority::Low,
                        },
                        title: format!("{}: {}", vuln.cve_id, finding.service),
                        description: vuln.recommendation.clone(),
                        affected_ips: vec![target.ip.clone()],
                    });
                }
            }
        }
    }

    // Deduplicate recommendations by title
    recommendations.sort_by(|a, b| {
        a.priority.sort_key().cmp(&b.priority.sort_key())
    });
    recommendations.dedup_by(|a, b| a.title == b.title);

    let scanned = engine.completed_count();
    let overall_risk = engine.total_risk_score();

    ReconReport {
        generated_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_devices: engine.targets.len(),
        scanned_devices: scanned,
        total_open_ports,
        critical_findings,
        suspicious_findings,
        overall_risk_score: overall_risk,
        device_reports,
        recommendations,
    }
}

impl Priority {
    pub fn sort_key(&self) -> u8 {
        match self {
            Priority::Critical => 0,
            Priority::High => 1,
            Priority::Medium => 2,
            Priority::Low => 3,
        }
    }
}

// ── Text Report Formatting ──────────────────────────────────────────

pub fn format_text_report(report: &ReconReport) -> String {
    let mut out = String::new();

    out.push_str("═══════════════════════════════════════════════════\n");
    out.push_str("  SIX-EYE RECON REPORT\n");
    out.push_str(&format!("  {}\n", report.generated_at));
    out.push_str("═══════════════════════════════════════════════════\n\n");

    out.push_str("NETWORK OVERVIEW\n");
    out.push_str(&format!("  Total Devices:    {}\n", report.total_devices));
    out.push_str(&format!("  Scanned:          {}\n", report.scanned_devices));
    out.push_str(&format!("  Open Ports:       {}\n", report.total_open_ports));
    out.push_str(&format!("  Critical:         {}\n", report.critical_findings));
    out.push_str(&format!("  Suspicious:       {}\n", report.suspicious_findings));
    out.push_str(&format!("  Risk Score:       {}/100\n\n", report.overall_risk_score));

    out.push_str("DEVICE INVENTORY\n");
    out.push_str("  ┌─────────────────┬──────────────────┬────────────────────┬──────┐\n");
    out.push_str("  │ IP              │ MAC              │ OS                 │ Risk │\n");
    out.push_str("  ├─────────────────┼──────────────────┼────────────────────┼──────┤\n");

    for dev in &report.device_reports {
        let risk_label = match dev.risk_score {
            0..=20 => "LOW ",
            21..=50 => "MED ",
            51..=80 => "HIGH",
            _ => "CRIT",
        };
        out.push_str(&format!(
            "  │ {:<15} │ {:<16} │ {:<18} │ {}  │\n",
            truncate(&dev.ip, 15),
            truncate(&dev.mac, 16),
            truncate(&dev.os, 18),
            risk_label
        ));
    }
    out.push_str("  └─────────────────┴──────────────────┴────────────────────┴──────┘\n\n");

    if !report.recommendations.is_empty() {
        out.push_str("RECOMMENDATIONS\n");
        for (i, rec) in report.recommendations.iter().enumerate() {
            out.push_str(&format!(
                "  {}. [{}] {}\n     {}\n     Affected: {}\n\n",
                i + 1,
                rec.priority.label(),
                rec.title,
                rec.description,
                rec.affected_ips.join(", ")
            ));
        }
    }

    out.push_str("═══════════════════════════════════════════════════\n");
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

// ── JSON Export ─────────────────────────────────────────────────────

pub fn export_report_json(report: &ReconReport) -> Result<String, String> {
    serde_json::to_string_pretty(report).map_err(|e| e.to_string())
}
