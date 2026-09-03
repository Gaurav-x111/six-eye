use eframe::egui::{self, RichText, Stroke, Ui};

use crate::gui::*;
use crate::recon::nmap_runner;

pub fn draw_recon_tab(app: &mut RadarApp, ui: &mut Ui) {
    ui.add_space(8.0);

    // Manual target input
    egui::Frame::default()
        .fill(BG_CARD)
        .rounding(10.0)
        .stroke(Stroke::new(1.0, GRID_LINE))
        .inner_margin(12.0)
        .show(ui, |ui| {
            tabs::section_title(ui, "🎯 Manual Scan Target");
            ui.horizontal(|ui| {
                ui.label(RichText::new("IP:").size(11.0).color(TEXT_DIM));
                ui.text_edit_singleline(&mut app.recon_target_input);
                if ui
                    .button(RichText::new("➕ Queue").size(11.0).color(ACCENT))
                    .clicked()
                {
                    let ip = app.recon_target_input.trim().to_string();
                    if !ip.is_empty() {
                        let mut engine = app.recon.lock().unwrap();
                        engine.queue_target(ip.clone(), app.recon_scan_tier);
                        app.recon_target_input.clear();
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Tier:").size(11.0).color(TEXT_DIM));
                for tier in [
                    crate::recon::ScanTier::Fast,
                    crate::recon::ScanTier::Deep,
                    crate::recon::ScanTier::Stealth,
                ] {
                    if ui
                        .selectable_label(
                            app.recon_scan_tier == tier,
                            RichText::new(format!("{} {}", tier.icon(), tier.label())).size(11.0),
                        )
                        .clicked()
                    {
                        app.recon_scan_tier = tier;
                    }
                }
            });
        });

    ui.add_space(10.0);

    // Recon stats
    let (queued, running, completed, total) = {
        let engine = app.recon.lock().unwrap();
        let queued = engine.targets.iter().filter(|t| t.status == crate::recon::ScanStatus::Queued).count();
        let running = engine.running_count();
        let completed = engine.completed_count();
        let total = engine.targets.len();
        (queued, running, completed, total)
    };

    egui::Frame::default()
        .fill(BG_CARD)
        .rounding(10.0)
        .stroke(Stroke::new(1.0, GRID_LINE))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                tabs::info_chip(ui, &format!("📋 Queued {}", queued), ACCENT_SOFT);
                tabs::info_chip(ui, &format!("🔄 Running {}", running), MOTION_COLOR);
                tabs::info_chip(ui, &format!("✅ Done {}", completed), SWEEP_GREEN);
                tabs::info_chip(ui, &format!("📊 Total {}", total), TEXT_SECONDARY);
                if app.nmap_privileged {
                    tabs::info_chip(ui, "🔑 Privileged", SWEEP_GREEN);
                } else {
                    tabs::info_chip(
                        ui,
                        "🔓 Unprivileged — OS detect off",
                        ALERT_WARNING,
                    );
                }
            });

            if !nmap_runner::is_nmap_available() {
                ui.add_space(4.0);
                egui::Frame::default()
                    .fill(tint(ALERT_WARNING, 30))
                    .rounding(6.0)
                    .stroke(Stroke::new(1.0, ALERT_WARNING))
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("⚠ nmap not found — install with: sudo apt install nmap")
                                .size(11.0)
                                .color(ALERT_WARNING),
                        );
                    });
            }
        });

    ui.add_space(10.0);

    // Report generation
    egui::Frame::default()
        .fill(BG_CARD)
        .rounding(10.0)
        .stroke(Stroke::new(1.0, GRID_LINE))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .button(RichText::new("📄 Generate Report").size(12.0).color(ACCENT))
                    .clicked()
                {
                    let engine = app.recon.lock().unwrap();
                    let report = crate::recon::report::generate_report(&engine);
                    app.report_text = crate::recon::report::format_text_report(&report);
                    app.last_report = Some(report);
                }
                if ui
                    .button(RichText::new("💾 Export JSON").size(12.0).color(ACCENT_SOFT))
                    .clicked()
                {
                    let engine = app.recon.lock().unwrap();
                    let report = crate::recon::report::generate_report(&engine);
                    if let Ok(json) = crate::recon::report::export_report_json(&report) {
                        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
                        let filename = format!("six_eye_recon_{}.json", ts);
                        if let Err(e) = std::fs::write(&filename, json) {
                            log::warn!("Failed to write report: {e}");
                        } else {
                            app.last_export_path = Some(filename);
                        }
                    }
                }
            });
        });

    ui.add_space(10.0);

    // Target list
    tabs::section_title(ui, &format!("📡 Scan Targets ({})", total));

    let targets: Vec<_> = {
        let engine = app.recon.lock().unwrap();
        engine.targets.clone()
    };

    if targets.is_empty() {
        ui.label(
            RichText::new("No scan targets queued. Add an IP above or enable auto-scan.")
                .size(11.0)
                .color(TEXT_SECONDARY),
        );
        return;
    }

    for target in &targets {
        let is_expanded = app.recon_expanded.contains(&target.ip);

        egui::Frame::default()
            .fill(BG_CARD)
            .rounding(8.0)
            .stroke(Stroke::new(
                if is_expanded { 1.3 } else { 1.0 },
                if is_expanded { ACCENT } else { GRID_LINE },
            ))
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let status_color = match &target.status {
                        crate::recon::ScanStatus::Queued => ACCENT_SOFT,
                        crate::recon::ScanStatus::Running => MOTION_COLOR,
                        crate::recon::ScanStatus::Completed => SWEEP_GREEN,
                        crate::recon::ScanStatus::Failed(_) => ALERT_CRITICAL,
                    };
                    ui.label(
                        RichText::new(target.tier.icon())
                            .size(14.0)
                            .color(status_color),
                    );
                    ui.label(
                        RichText::new(&target.ip)
                            .monospace()
                            .size(12.0)
                            .color(TEXT_PRIMARY),
                    );
                    if let Some(vendor) = &target.vendor {
                        ui.label(
                            RichText::new(vendor)
                                .size(10.0)
                                .color(TEXT_DIM),
                        );
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let risk = target.risk_score();
                        if risk > 0 {
                            ui.label(
                                RichText::new(format!("Risk {}", risk))
                                    .size(10.0)
                                    .color(risk_color(risk)),
                            );
                        }
                        ui.label(
                            RichText::new(target.status.label())
                                .size(10.0)
                                .color(status_color),
                        );
                        if ui.button(if is_expanded { "▲" } else { "▼" }).clicked() {
                            if is_expanded {
                                app.recon_expanded.remove(&target.ip);
                            } else {
                                app.recon_expanded.insert(target.ip.clone());
                            }
                        }
                    });
                });

                if is_expanded {
                    if let Some(result) = &target.result {
                        ui.add_space(6.0);

                        // OS detection
                        if !result.os_guess.is_empty() {
                            ui.label(
                                RichText::new("Operating System:")
                                    .size(10.0)
                                    .color(TEXT_DIM),
                            );
                            for os in &result.os_guess {
                                ui.label(
                                    RichText::new(format!(
                                        "  {} ({}% accuracy)",
                                        os.name, os.accuracy
                                    ))
                                    .monospace()
                                    .size(10.0)
                                    .color(TEXT_SECONDARY),
                                );
                            }
                        }

                        // Open ports
                        if !result.ports.is_empty() {
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(format!(
                                    "Ports ({})",
                                    result.ports.iter().filter(|p| p.state == "open").count()
                                ))
                                .size(10.0)
                                .color(TEXT_DIM),
                            );
                            for port in &result.ports {
                                if port.state != "open" {
                                    continue;
                                }
                                let risk_col = match port.risk_level {
                                    crate::recon::PortRisk::Critical => RISK_CRITICAL,
                                    crate::recon::PortRisk::Suspicious => RISK_MEDIUM,
                                    crate::recon::PortRisk::Info => ACCENT_SOFT,
                                    crate::recon::PortRisk::Safe => SWEEP_GREEN,
                                };
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new(format!(
                                            "{} {}:{} [{}] {}",
                                            port.risk_level.icon(),
                                            port.port,
                                            port.protocol,
                                            port.service,
                                            port.version
                                        ))
                                        .monospace()
                                        .size(10.0)
                                        .color(risk_col),
                                    );
                                });
                            }
                        }

                        // Scripts
                        if !result.scripts.is_empty() {
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new("Script Output:").size(10.0).color(TEXT_DIM),
                            );
                            for script in &result.scripts {
                                ui.label(
                                    RichText::new(format!("  {}: {}", script.id, script.output))
                                        .monospace()
                                        .size(9.5)
                                        .color(TEXT_DIM),
                                );
                            }
                        }
                    } else if let crate::recon::ScanStatus::Failed(ref reason) = target.status {
                        ui.add_space(4.0);
                        ui.label(
                            RichText::new(format!("Error: {}", reason))
                                .size(10.0)
                                .color(ALERT_CRITICAL),
                        );
                    }
                }
            });
        ui.add_space(4.0);
    }

    // Report text display
    if !app.report_text.is_empty() {
        ui.add_space(12.0);
        tabs::section_title(ui, "📄 Generated Report");
        egui::Frame::default()
            .fill(BG_CARD)
            .rounding(10.0)
            .stroke(Stroke::new(1.0, GRID_LINE))
            .inner_margin(10.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(&app.report_text)
                                .monospace()
                                .size(10.5)
                                .color(TEXT_PRIMARY),
                        );
                    });
            });
    }
}
