use super::PortRisk;

/// Classify a port's risk level based on port number, service name, and version string.
pub fn classify_port_risk(port: u16, service: &str, version: &str) -> PortRisk {
    let service_lower = service.to_ascii_lowercase();
    let version_lower = version.to_ascii_lowercase();

    // ── Critical: known dangerous services ────────────────────────────
    match port {
        23 => return PortRisk::Critical,        // Telnet
        21 if is_anon_ftp(&version_lower) => return PortRisk::Critical,
        445 if has_smbv1(&version_lower) => return PortRisk::Critical,
        1433 | 3306 | 5432 if is_remote_accessible(&service_lower) => return PortRisk::Critical,
        5900 | 5901 => return PortRisk::Critical,  // VNC
        _ => {}
    }

    // ── Suspicious: unusual or risky for typical devices ──────────────
    match port {
        21 => return PortRisk::Suspicious,      // FTP
        25 if service_lower.contains("smtp") => return PortRisk::Suspicious,
        69 => return PortRisk::Suspicious,       // TFTP
        161 | 162 => return PortRisk::Suspicious, // SNMP
        1900 => return PortRisk::Suspicious,     // UPnP
        5353 => return PortRisk::Info,           // mDNS
        8080 | 8443 | 8888 => return PortRisk::Suspicious, // Admin panels
        3389 => return PortRisk::Suspicious,     // RDP
        5900..=5999 => return PortRisk::Suspicious, // VNC range
        6660..=6669 => return PortRisk::Suspicious, // IRC (botnets)
        _ => {}
    }

    // ── Info: informational services ──────────────────────────────────
    match port {
        53 => return PortRisk::Info,             // DNS
        80 | 443 => return PortRisk::Info,       // HTTP/S
        123 => return PortRisk::Info,            // NTP
        135 | 137 | 138 | 139 => return PortRisk::Info, // NetBIOS
        389 | 636 => return PortRisk::Info,      // LDAP
        1900 => return PortRisk::Info,           // SSDP
        5000 | 5001 => return PortRisk::Info,    // UPnP / admin
        _ => {}
    }

    // ── Safe: well-known benign services ──────────────────────────────
    match port {
        22 => PortRisk::Safe,                    // SSH
        5353 => PortRisk::Info,                  // mDNS
        631 => PortRisk::Info,                   // IPP (printers)
        _ => {
            // Default: classify by service name
            match service_lower.as_str() {
                "ssh" | "ssl/ssh" => PortRisk::Safe,
                "http" | "https" | "http-proxy" => PortRisk::Info,
                "domain" | "dns" => PortRisk::Info,
                "ftp" | "ftp-data" => PortRisk::Suspicious,
                "telnet" => PortRisk::Critical,
                "microsoft-ds" | "netbios-ssn" => PortRisk::Suspicious,
                "ms-wbt-server" | "rdp" => PortRisk::Suspicious,
                "vnc" => PortRisk::Critical,
                "snmp" => PortRisk::Suspicious,
                "ipp" | "printer" | "lpd" => PortRisk::Safe,
                "airplay" | "raop" => PortRisk::Safe,
                "smb" | "samba" => PortRisk::Suspicious,
                _ => PortRisk::Info,
            }
        }
    }
}

fn is_anon_ftp(version: &str) -> bool {
    version.contains("anonymous") || version.contains("vsftpd") && version.contains("anon")
}

fn has_smbv1(version: &str) -> bool {
    version.contains("smbv1") || version.contains("smb 1") || version.contains("samba 3")
}

fn is_remote_accessible(service: &str) -> bool {
    service.contains("ms-sql") || service.contains("mysql") || service.contains("postgresql")
}

/// Get a human-readable description for a port + service combination.
pub fn port_description(port: u16, service: &str) -> &'static str {
    match port {
        21 => "File Transfer Protocol — may expose files",
        22 => "Secure Shell — encrypted remote access",
        23 => "Telnet — unencrypted remote access (DANGER)",
        25 => "SMTP — email relay, may be abused for spam",
        53 => "DNS — domain name resolution",
        80 => "HTTP — web server, may host admin panels",
        110 => "POP3 — email retrieval",
        135 => "MSRPC — Microsoft RPC endpoint",
        137 | 138 | 139 => "NetBIOS — Windows file sharing",
        143 => "IMAP — email access",
        443 => "HTTPS — encrypted web",
        445 => "SMB — file sharing (ransomware vector)",
        993 | 995 => "Encrypted email (IMAPS/POP3S)",
        1433 | 1434 => "MS SQL Server",
        1723 => "PPTP VPN",
        3306 => "MySQL database",
        3389 => "RDP — remote desktop (brute-force target)",
        5432 => "PostgreSQL database",
        5900 => "VNC — remote desktop (no encryption by default)",
        631 => "IPP — printer management",
        8080 => "HTTP Proxy / Admin panel",
        8443 => "HTTPS Alt — often admin interfaces",
        _ => match service {
            "ssh" => "Secure Shell",
            "http" => "Hypertext Transfer Protocol",
            "https" => "HTTP over TLS",
            "domain" => "Domain Name System",
            "ftp" => "File Transfer Protocol",
            "telnet" => "Telnet Remote Access",
            "microsoft-ds" => "SMB File Sharing",
            "netbios-ssn" => "NetBIOS Session",
            "snmp" => "Simple Network Management Protocol",
            "ipp" => "Internet Printing Protocol",
            "upnp" => "Universal Plug and Play",
            _ => "Service detected",
        },
    }
}
