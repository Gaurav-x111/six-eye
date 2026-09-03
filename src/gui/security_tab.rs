use eframe::egui::{self, RichText, Stroke, Ui};

use crate::gui::*;
use crate::security::{AlertSeverity, AlertType};

pub fn draw_security_tab(app: &mut RadarApp, ui: &mut Ui) {
    ui.add_space(8.0);

    // Security summary
    let (alert_count, critical_count, evil_twin_count, deauth_count) = {
        let sec = app.security.lock().unwrap();
        let alert_count = sec.alerts.len();
        let critical_count = sec.critical_count();
        let evil_twin_count = sec
            .alerts
            .iter()
            .filter(|a| a.alert_type == AlertType::EvilTwin)
            .count();
        let deauth_count = sec
            .alerts
            .iter()
            .filter(|a| matches!(a.alert_type, AlertType::DeauthFlood | AlertType::Jamming))
            .count();
        (alert_count, critical_count, evil_twin_count, deauth_count)
    };

    egui::Frame::default()
        .fill(BG_CARD)
        .rounding(10.0)
        .stroke(Stroke::new(1.0, GRID_LINE))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                tabs::info_chip(
                    ui,
                    &format!("🛡 Total Alerts {}", alert_count),
                    TEXT_SECONDARY,
                );
                tabs::info_chip(
                    ui,
                    &format!("🔴 Critical {}", critical_count),
                    if critical_count > 0 {
                        RISK_CRITICAL
                    } else {
                        SWEEP_GREEN
                    },
                );
                tabs::info_chip(
                    ui,
                    &format!("👯 Evil Twin {}", evil_twin_count),
                    if evil_twin_count > 0 {
                        RISK_CRITICAL
                    } else {
                        SWEEP_GREEN
                    },
                );
                tabs::info_chip(
                    ui,
                    &format!("🚫 Deauth {}", deauth_count),
                    if deauth_count > 0 {
                        ALERT_WARNING
                    } else {
                        SWEEP_GREEN
                    },
                );
            });
        });

    ui.add_space(10.0);

    // AP Fingerprint count
    let ap_count = {
        let sec = app.security.lock().unwrap();
        sec.known_aps.len()
    };
    tabs::info_chip(
        ui,
        &format!("📡 Known APs in Database: {}", ap_count),
        ACCENT_SOFT,
    );

    ui.add_space(10.0);
    tabs::section_title(ui, &format!("🚨 Security Alerts ({})", alert_count));

    let alerts: Vec<_> = {
        let sec = app.security.lock().unwrap();
        sec.recent_alerts(50)
    };

    if alerts.is_empty() {
        egui::Frame::default()
            .fill(BG_CARD)
            .rounding(10.0)
            .stroke(Stroke::new(1.0, SWEEP_GREEN))
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🟢").size(20.0));
                    ui.label(
                        RichText::new("No security threats detected")
                            .size(13.0)
                            .color(SWEEP_GREEN),
                    );
                });
                ui.label(
                    RichText::new("All access points appear legitimate. Continuous monitoring active.")
                        .size(11.0)
                        .color(TEXT_DIM),
                );
            });
        return;
    }

    for alert in alerts {
        let (bg_color, border_color) = match alert.severity {
            AlertSeverity::Critical => (tint(RISK_CRITICAL, 25), RISK_CRITICAL),
            AlertSeverity::High => (tint(ALERT_WARNING, 25), ALERT_WARNING),
            AlertSeverity::Medium => (tint(ALERT_ATTENTION, 25), ALERT_ATTENTION),
            AlertSeverity::Low => (tint(ACCENT_SOFT, 20), ACCENT_SOFT),
            AlertSeverity::Info => (tint(TEXT_DIM, 20), GRID_LINE),
        };

        egui::Frame::default()
            .fill(bg_color)
            .rounding(8.0)
            .stroke(Stroke::new(1.0, border_color))
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(alert.alert_type.icon())
                            .size(16.0),
                    );
                    ui.label(
                        RichText::new(&alert.title)
                            .size(12.0)
                            .color(border_color),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(alert.timestamp.format("%H:%M:%S").to_string())
                                .monospace()
                                .size(10.0)
                                .color(TEXT_DIM),
                        );
                        ui.label(
                            RichText::new(alert.severity.label())
                                .size(10.0)
                                .color(border_color),
                        );
                    });
                });

                ui.add_space(4.0);
                ui.label(
                    RichText::new(&alert.description)
                        .size(11.0)
                        .color(TEXT_SECONDARY),
                );

                if !alert.evidence.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new("Evidence:").size(10.0).color(TEXT_DIM));
                    for evidence in &alert.evidence {
                        ui.label(
                            RichText::new(format!("  • {}", evidence))
                                .monospace()
                                .size(9.5)
                                .color(TEXT_DIM),
                        );
                    }
                }

                if !alert.recommendation.is_empty() {
                    ui.add_space(4.0);
                    egui::Frame::default()
                        .fill(tint(ACCENT, 15))
                        .rounding(4.0)
                        .inner_margin(6.0)
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!("💡 {}", alert.recommendation))
                                    .size(10.5)
                                    .color(ACCENT),
                            );
                        });
                }
            });
        ui.add_space(6.0);
    }
}
