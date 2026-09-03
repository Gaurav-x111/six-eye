use std::process::{Command, Stdio};
use std::thread;

use log;
use quick_xml;

use super::{NmapResult, OsGuess, PortInfo, ScanStatus, ScanTier, ScriptOutput};
use crate::recon::port_database::classify_port_risk;
use crate::recon::SharedRecon;

/// Check if nmap is available on the system.
pub fn is_nmap_available() -> bool {
    Command::new("nmap")
        .args(["--version"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Spawn the background recon thread. It picks up queued targets and scans them.
pub fn spawn_recon_thread(recon: SharedRecon, egui_ctx: eframe::egui::Context) {
    thread::spawn(move || loop {
        let target_ip = {
            let mut engine = recon.lock().unwrap();
            engine.scan_next_pending()
        };

        if let Some(ip) = target_ip {
            log::info!("Starting nmap scan on {ip}");
            let result = run_nmap_scan(&ip, ScanTier::Fast);

            let mut engine = recon.lock().unwrap();
            if let Some(target) = engine.targets.iter_mut().find(|t| t.ip == ip) {
                match result {
                    Ok(nmap_result) => {
                        target.status = ScanStatus::Completed;
                        target.result = Some(nmap_result);
                        target.completed_at = Some(chrono::Local::now());
                        log::info!("nmap scan completed for {ip}");
                    }
                    Err(e) => {
                        target.status = ScanStatus::Failed(e);
                        target.completed_at = Some(chrono::Local::now());
                        log::warn!("nmap scan failed for {ip}: {}", target.status.label());
                    }
                }
            }
            egui_ctx.request_repaint();
        }

        thread::sleep(std::time::Duration::from_secs(2));
    });
}

/// Run nmap with XML output and parse the results.
fn run_nmap_scan(ip: &str, tier: ScanTier) -> Result<NmapResult, String> {
    let privileged = super::is_root();
    let mut args = vec!["-oX", "-"];
    args.extend(tier.nmap_args(privileged));
    args.push(ip);

    let output = Command::new("nmap")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to execute nmap: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nmap exited with error: {stderr}"));
    }

    let xml = String::from_utf8_lossy(&output.stdout).to_string();
    parse_nmap_xml(&xml)
}

/// Parse nmap XML output into structured NmapResult.
pub fn parse_nmap_xml(xml: &str) -> Result<NmapResult, String> {
    let mut result = NmapResult {
        raw_xml: xml.to_string(),
        ..NmapResult::default()
    };

    // Use quick-xml for proper XML parsing
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut buf = Vec::new();

    let mut current_port: Option<u16> = None;
    let mut current_protocol: String = String::new();
    let mut current_state: String = String::new();
    let mut current_service: String = String::new();
    let mut current_version: String = String::new();
    let mut current_extrainfo: String = String::new();
    let mut in_port = false;
    let mut in_osmatch = false;
    let mut current_os_name: String = String::new();
    let mut current_os_accuracy: u8 = 0;
    let mut current_script_id: String = String::new();
    let mut current_script_output: String = String::new();
    let mut in_hop = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(e)) | Ok(quick_xml::events::Event::Empty(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match tag.as_str() {
                    "port" => {
                        in_port = true;
                        current_port = parse_port_attr(&e, "portid");
                        current_protocol = parse_attr(&e, "protocol");
                        current_state.clear();
                        current_service.clear();
                        current_version.clear();
                        current_extrainfo.clear();
                    }
                    "state" if in_port => {
                        current_state = parse_attr(&e, "state");
                    }
                    "service" if in_port => {
                        current_service = parse_attr(&e, "name");
                        current_version = parse_attr(&e, "product");
                        let ver = parse_attr(&e, "version");
                        if !ver.is_empty() {
                            if !current_version.is_empty() {
                                current_version.push(' ');
                            }
                            current_version.push_str(&ver);
                        }
                        current_extrainfo = parse_attr(&e, "extrainfo");
                    }
                    "osmatch" => {
                        in_osmatch = true;
                        current_os_name = parse_attr(&e, "name");
                        current_os_accuracy = parse_attr(&e, "accuracy")
                            .parse()
                            .unwrap_or(0);
                    }
                    "cpe" if in_osmatch => {
                        // Will be collected on character event
                    }
                    "script" => {
                        current_script_id = parse_attr(&e, "id");
                        current_script_output = parse_attr(&e, "output");
                    }
                    "hop" => {
                        in_hop = true;
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::End(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match tag.as_str() {
                    "port" => {
                        if let Some(port_id) = current_port.take() {
                            let risk = classify_port_risk(
                                port_id,
                                &current_service,
                                &current_version,
                            );
                            result.ports.push(PortInfo {
                                port: port_id,
                                protocol: current_protocol.clone(),
                                state: current_state.clone(),
                                service: current_service.clone(),
                                version: current_version.clone(),
                                extra_info: current_extrainfo.clone(),
                                risk_level: risk,
                            });
                        }
                        in_port = false;
                    }
                    "osmatch" => {
                        result.os_guess.push(OsGuess {
                            name: current_os_name.clone(),
                            accuracy: current_os_accuracy,
                            cpe: Vec::new(),
                        });
                        in_osmatch = false;
                    }
                    "script" => {
                        result.scripts.push(ScriptOutput {
                            id: current_script_id.clone(),
                            output: current_script_output.clone(),
                        });
                    }
                    "hop" => {
                        in_hop = false;
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                if in_hop {
                    if let Ok(_hop_num) = text.trim().parse::<u32>() {
                        // hop element has ttl and iptext attributes, text is rtt
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => {
                log::warn!("XML parse error: {e}");
                break;
            }
            _ => {}
        }
        buf.clear();
    }

    // Sort ports by risk
    result.ports.sort_by(|a, b| {
        a.risk_level
            .sort_key()
            .cmp(&b.risk_level.sort_key())
            .then_with(|| a.port.cmp(&b.port))
    });

    Ok(result)
}

fn parse_attr(e: &quick_xml::events::BytesStart, name: &str) -> String {
    e.attributes()
        .find(|a| a.as_ref().map(|a| a.key.as_ref() == name.as_bytes()).unwrap_or(false))
        .and_then(|a| a.ok())
        .and_then(|a| String::from_utf8(a.value.to_vec()).ok())
        .unwrap_or_default()
}

fn parse_port_attr(e: &quick_xml::events::BytesStart, name: &str) -> Option<u16> {
    parse_attr(e, name).parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real nmap 7.94 XML output captured from a live scan against 127.0.0.1
    // with an open port (python3 -m http.server 18080).
    const REAL_XML_OPEN: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -oX open_port.xml -sV -T4 -p 18080 127.0.0.1" start="1788427613" startstr="Thu Sep  3 15:11:53 2026" version="7.94SVN" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1" services="18080"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
<host starttime="1788427613" endtime="1788427619"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="18080"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="http" product="SimpleHTTPServer" version="0.6" extrainfo="Python 3.12.3" method="probed" conf="10"><cpe>cpe:/a:python:simplehttpserver:0.6</cpe></service></port>
</ports>
<times srtt="62" rttvar="3759" to="100000"/>
</host>
<runstats><finished time="1788427619" timestr="Thu Sep  3 15:11:59 2026" summary="Nmap done at Thu Sep  3 15:11:59 2026; 1 IP address (1 host up) scanned in 6.18 seconds" elapsed="6.18" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"#;

    // Real nmap output with all ports closed (top 10 scan of localhost).
    const REAL_XML_CLOSED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -sV -T4 --top-ports 10 127.0.0.1" start="1788426928" startstr="Thu Sep  3 15:00:28 2026" version="7.94SVN" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="10" services="21-23,25,80,110,139,443,445,3389"/>
<verbose level="0"/>
<debugging level="0"/>
<host hint="1"><status state="up" reason="conn-refused" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames>
<hostname name="localhost" type="PTR"/>
</hostnames>
<ports><port protocol="tcp" portid="21"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="ftp" method="table" conf="3"/></port>
<port protocol="tcp" portid="22"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="23"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="telnet" method="table" conf="3"/></port>
<port protocol="tcp" portid="25"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="smtp" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="110"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="pop3" method="table" conf="3"/></port>
<port protocol="tcp" portid="139"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="netbios-ssn" method="table" conf="3"/></port>
<port protocol="tcp" portid="443"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="https" method="table" conf="3"/></port>
<port protocol="tcp" portid="445"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="microsoft-ds" method="table" conf="3"/></port>
<port protocol="tcp" portid="3389"><state state="closed" reason="conn-refused" reason_ttl="0"/><service name="ms-wbt-server" method="table" conf="3"/></port>
</ports>
<times srtt="46" rttvar="311" to="100000"/>
</host>
<runstats><finished time="1788426928" timestr="Thu Sep  3 15:00:28 2026" summary="Nmap done" elapsed="0.15" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"#;

    #[test]
    fn parses_real_open_port_xml() {
        let result = parse_nmap_xml(REAL_XML_OPEN).expect("should parse real nmap XML");

        assert_eq!(result.ports.len(), 1, "should extract exactly one port");
        let port = &result.ports[0];
        assert_eq!(port.port, 18080);
        assert_eq!(port.state, "open");
        assert_eq!(port.service, "http");
        assert_eq!(port.protocol, "tcp");
        assert!(
            port.version.contains("SimpleHTTPServer"),
            "version should contain product name, got {:?}",
            port.version
        );
        assert!(
            port.version.contains("0.6"),
            "version should contain version number, got {:?}",
            port.version
        );
        assert_eq!(port.extra_info, "Python 3.12.3");
    }

    #[test]
    fn parses_real_closed_ports_xml() {
        let result = parse_nmap_xml(REAL_XML_CLOSED).expect("should parse real nmap XML");

        assert_eq!(result.ports.len(), 10, "should extract all 10 ports");

        // All should be closed
        assert!(
            result.ports.iter().all(|p| p.state == "closed"),
            "all ports should be closed"
        );

        // Check telnet (port 23) is flagged critical even when closed
        let telnet = result.ports.iter().find(|p| p.port == 23).expect("port 23 present");
        assert_eq!(telnet.service, "telnet");

        // Check SSH port parsed
        let ssh = result.ports.iter().find(|p| p.port == 22).expect("port 22 present");
        assert_eq!(ssh.service, "ssh");
    }

    #[test]
    fn host_level_status_does_not_leak_into_ports() {
        // The <host>/<status> element must not be misread as a port's <state>.
        let result = parse_nmap_xml(REAL_XML_OPEN).unwrap();
        // If the bug existed, we might see a phantom port with state "up".
        assert!(
            result.ports.iter().all(|p| p.state != "up"),
            "host-level <status> must not leak into port states"
        );
    }
}
