use eframe::egui::{self, RichText, Stroke, Ui};

use crate::ai::AnomalySeverity;
use crate::gui::*;

pub fn draw_threats_tab(app: &mut RadarApp, ui: &mut Ui) {
    ui.add_space(8.0);

    // Overall threat summary
    let (ai_anomalies, ai_high, recon_risk, security_critical) = {
        let ai = app.ai.lock().unwrap();
        let recon = app.recon.lock().unwrap();
        let sec = app.security.lock().unwrap();
        (
            ai.total_anomalies(),
            ai.high_severity_count(),
            recon.total_risk_score(),
            sec.critical_count(),
        )
    };

    let overall_threat = calculate_overall_threat(ai_high, recon_risk, security_critical);

    egui::Frame::default()
        .fill(if overall_threat > 60 {
            tint(RISK_CRITICAL, 30)
        } else if overall_threat > 30 {
            tint(ALERT_WARNING, 25)
        } else {
            tint(SWEEP_GREEN, 15)
        })
        .rounding(10.0)
        .stroke(Stroke::new(
            1.5,
            risk_color(overall_threat),
        ))
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🛡").size(24.0));
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(format!("Overall Threat Level: {}/100", overall_threat))
                            .size(16.0)
                            .color(risk_color(overall_threat)),
                    );
                    ui.label(
                        RichText::new(threat_label(overall_threat))
                            .size(12.0)
                            .color(TEXT_SECONDARY),
                    );
                });
            });
            ui.add_space(6.0);
            ui.columns(4, |cols| {
                threat_mini_card(&mut cols[0], "🧠 AI Anomalies", &ai_anomalies.to_string(), &format!("{} high", ai_high), ACCENT_SOFT);
                threat_mini_card(&mut cols[1], "📡 Recon Risk", &format!("{}/100", recon_risk), "nmap findings", MOTION_COLOR);
                threat_mini_card(&mut cols[2], "🚨 Security", &security_critical.to_string(), "critical alerts", RISK_CRITICAL);
                threat_mini_card(&mut cols[3], "📊 Score", &format!("{}", overall_threat), "composite", risk_color(overall_threat));
            });
        });

    ui.add_space(12.0);

    // Tabs within threats
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("View:").size(11.0).color(TEXT_DIM));
        // We'll show all sections in one scrollable view for simplicity
    });

    ui.add_space(8.0);

    // ── AI Anomalies Section ──────────────────────────────────────────
    tabs::section_title(ui, "🧠 AI Behavioral Anomalies");

    let anomalies: Vec<_> = {
        let ai = app.ai.lock().unwrap();
        ai.recent_anomalies(15)
    };

    if anomalies.is_empty() {
        ui.label(
            RichText::new("No anomalies detected. Network behavior is within normal parameters.")
                .size(11.0)
                .color(TEXT_SECONDARY),
        );
    } else {
        for anomaly in &anomalies {
            let severity_color = match anomaly.severity {
                AnomalySeverity::High => RISK_CRITICAL,
                AnomalySeverity::Medium => RISK_MEDIUM,
                AnomalySeverity::Low => RISK_LOW,
                AnomalySeverity::Info => TEXT_DIM,
            };

            egui::Frame::default()
                .fill(BG_CARD)
                .rounding(8.0)
                .stroke(Stroke::new(1.0, severity_color))
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(anomaly.anomaly_type.icon()).size(14.0));
                        ui.label(
                            RichText::new(anomaly.anomaly_type.label())
                                .size(11.5)
                                .color(severity_color),
                        );
                        ui.label(
                            RichText::new(format!("score {:.1}", anomaly.behavior_score))
                                .size(10.0)
                                .color(TEXT_DIM),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(anomaly.timestamp.format("%H:%M:%S").to_string())
                                    .monospace()
                                    .size(9.5)
                                    .color(TEXT_DIM),
                            );
                        });
                    });
                    ui.label(
                        RichText::new(&anomaly.description)
                            .size(11.0)
                            .color(TEXT_SECONDARY),
                    );
                    if !anomaly.evidence.is_empty() {
                        for evidence in &anomaly.evidence {
                            ui.label(
                                RichText::new(format!("  • {}", evidence))
                                    .monospace()
                                    .size(9.5)
                                    .color(TEXT_DIM),
                            );
                        }
                    }
                });
            ui.add_space(4.0);
        }
    }

    ui.add_space(12.0);

    // ── Vulnerability Findings Section ────────────────────────────────
    tabs::section_title(ui, "🔍 Vulnerability Findings");

    let critical_ports: Vec<_> = {
        let engine = app.recon.lock().unwrap();
        engine.critical_ports()
    };

    if critical_ports.is_empty() {
        let has_completed = {
            let engine = app.recon.lock().unwrap();
            engine.completed_count() > 0
        };
        if has_completed {
            ui.label(
                RichText::new("No critical vulnerabilities found in completed scans.")
                    .size(11.0)
                    .color(SWEEP_GREEN),
            );
        } else {
            ui.label(
                RichText::new("No scans completed yet. Start a scan from the Recon tab.")
                    .size(11.0)
                    .color(TEXT_SECONDARY),
            );
        }
    } else {
        for (target, port) in &critical_ports {
            egui::Frame::default()
                .fill(tint(RISK_CRITICAL, 20))
                .rounding(8.0)
                .stroke(Stroke::new(1.0, RISK_CRITICAL))
                .inner_margin(10.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("🔴").size(14.0));
                        ui.label(
                            RichText::new(format!(
                                "{}:{} ({})",
                                target.ip, port.port, port.service
                            ))
                            .monospace()
                            .size(11.5)
                            .color(RISK_CRITICAL),
                        );
                    });
                    ui.label(
                        RichText::new(format!(
                            "{} — {} {} — {}",
                            crate::recon::port_database::port_description(port.port, &port.service),
                            port.risk_level.icon(),
                            port.risk_level.label(),
                            port.version
                        ))
                        .size(10.5)
                        .color(TEXT_SECONDARY),
                    );
                });
            ui.add_space(4.0);
        }
    }

    ui.add_space(12.0);

    // ── Network Health Summary ────────────────────────────────────────
    tabs::section_title(ui, "📊 Network Health");

    egui::Frame::default()
        .fill(BG_CARD)
        .rounding(10.0)
        .stroke(Stroke::new(1.0, GRID_LINE))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.columns(2, |cols| {
                threat_mini_card(
                    &mut cols[0],
                    "📶 Signal Health",
                    &format!("{}/100", app.monitoring_summary.signal_health.health_score),
                    app.monitoring_summary.signal_health.health_label,
                    ACCENT,
                );
                threat_mini_card(
                    &mut cols[1],
                    "📡 AP Count",
                    &app.monitoring_summary.nearby_networks.to_string(),
                    &app.monitoring_summary.dominant_band,
                    ACCENT_SOFT,
                );
            });
            ui.add_space(6.0);
            ui.columns(2, |cols| {
                threat_mini_card(
                    &mut cols[0],
                    "🏃 Motion",
                    &format!("{:.0}%", app.monitoring_summary.motion_score * 100.0),
                    app.monitoring_summary.motion_label,
                    MOTION_COLOR,
                );
                threat_mini_card(
                    &mut cols[1],
                    "👤 Presence",
                    &format!("{:.0}%", app.monitoring_summary.presence_score * 100.0),
                    app.monitoring_summary.presence_label,
                    ACCENT,
                );
            });
        });
}

fn threat_mini_card(ui: &mut Ui, title: &str, value: &str, subtitle: &str, color: eframe::egui::Color32) {
    egui::Frame::default()
        .fill(BG_CARD)
        .rounding(8.0)
        .stroke(Stroke::new(1.0, GRID_LINE))
        .inner_margin(8.0)
        .show(ui, |ui| {
            ui.label(RichText::new(title).size(10.0).color(TEXT_DIM));
            ui.label(RichText::new(value).size(18.0).color(color));
            ui.label(RichText::new(subtitle).size(10.0).color(TEXT_SECONDARY));
        });
}

fn calculate_overall_threat(ai_high: usize, recon_risk: u8, security_critical: usize) -> u8 {
    let ai_score = (ai_high as u32 * 15).min(50) as u8;
    let recon_score = (recon_risk as u32 / 2).min(30) as u8;
    let sec_score = (security_critical as u32 * 20).min(50) as u8;

    let total = ai_score.saturating_add(recon_score).saturating_add(sec_score);
    total.min(100)
}

fn threat_label(score: u8) -> &'static str {
    match score {
        0..=10 => "All clear — no significant threats detected",
        11..=30 => "Low — minor anomalies, normal operations",
        31..=60 => "Elevated — suspicious activity detected, investigate",
        61..=80 => "High — significant security concerns, action recommended",
        _ => "Critical — immediate attention required",
    }
}
