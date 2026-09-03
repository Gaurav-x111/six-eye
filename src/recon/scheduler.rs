use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use super::ReconEngine;

// ── Scheduler Configuration ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconScheduler {
    pub quick_scan_interval_mins: u32,
    pub deep_scan_interval_hrs: u32,
    pub auto_export: bool,
    pub last_quick_scan: Option<DateTime<Local>>,
    pub last_deep_scan: Option<DateTime<Local>>,
    pub enabled: bool,
    pub max_auto_targets: usize,
}

impl Default for ReconScheduler {
    fn default() -> Self {
        Self {
            quick_scan_interval_mins: 30,
            deep_scan_interval_hrs: 6,
            auto_export: false,
            last_quick_scan: None,
            last_deep_scan: None,
            enabled: true,
            max_auto_targets: 20,
        }
    }
}

impl ReconScheduler {
    /// Check if a quick scan should be triggered.
    pub fn should_quick_scan(&self) -> bool {
        if !self.enabled {
            return false;
        }

        match self.last_quick_scan {
            Some(last) => {
                let elapsed = Local::now().signed_duration_since(last);
                elapsed.num_minutes() >= self.quick_scan_interval_mins as i64
            }
            None => true,
        }
    }

    /// Check if a deep scan should be triggered.
    pub fn should_deep_scan(&self) -> bool {
        if !self.enabled {
            return false;
        }

        match self.last_deep_scan {
            Some(last) => {
                let elapsed = Local::now().signed_duration_since(last);
                elapsed.num_hours() >= self.deep_scan_interval_hrs as i64
            }
            None => true,
        }
    }

    /// Called after a quick scan completes.
    pub fn record_quick_scan(&mut self) {
        self.last_quick_scan = Some(Local::now());
    }

    /// Called after a deep scan completes.
    pub fn record_deep_scan(&mut self) {
        self.last_deep_scan = Some(Local::now());
    }

    /// Auto-queue devices for scanning based on scheduler rules.
    pub fn auto_queue_pending(
        &self,
        engine: &mut ReconEngine,
        devices: &[crate::models::ConnectedDevice],
    ) {
        if !self.enabled {
            return;
        }

        if engine.targets.len() >= self.max_auto_targets {
            return;
        }

        for device in devices {
            if engine.targets.len() >= self.max_auto_targets {
                break;
            }

            let ip = device.primary_address().to_string();

            // Skip if already queued/scanned
            if engine.targets.iter().any(|t| t.ip == ip) {
                continue;
            }

            // Skip localhost/loopback
            if ip.starts_with("127.") || ip == "::1" || ip == "localhost" {
                continue;
            }

            if engine.auto_scan_new_devices {
                engine.queue_device(device);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_defaults() {
        let scheduler = ReconScheduler::default();
        assert!(scheduler.should_quick_scan());
        assert!(scheduler.should_deep_scan());
        assert!(scheduler.enabled);
    }

    #[test]
    fn test_scheduler_disabled() {
        let mut scheduler = ReconScheduler::default();
        scheduler.enabled = false;
        assert!(!scheduler.should_quick_scan());
        assert!(!scheduler.should_deep_scan());
    }

    #[test]
    fn test_scheduler_records_scan() {
        let mut scheduler = ReconScheduler::default();
        scheduler.record_quick_scan();
        assert!(!scheduler.should_quick_scan());
    }
}
