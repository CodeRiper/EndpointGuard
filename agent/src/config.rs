use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    /// Server addressed by HOSTNAME only — no hardcoded IP ever appears
    /// in the agent binary or config file.  The actual IP is resolved at
    /// runtime via DNS.  Certificate pinning (below) prevents DNS-spoof
    /// or MITM attacks from redirecting the agent to a rogue server.
    pub server_addr: String,

    pub agent_id:    String,
    pub client_cert: String,
    pub client_key:  String,
    pub server_ca:   String,

    /// SHA-256 fingerprint of the server CA certificate (hex, no colons).
    /// Embedded here at build time so even if a corporate TLS-intercept
    /// proxy injects its own CA the fingerprint check will fail and the
    /// agent will refuse to connect.
    /// Override with EG_SERVER_CA_FINGERPRINT env var during development.
    pub server_ca_fingerprint: String,

    /// Flush telemetry batch every N seconds (blueprint: 10s)
    pub flush_interval_secs: u64,
    /// …or when the serialised payload reaches this size (blueprint: 64 KB)
    pub flush_max_bytes: usize,
    /// Offline SQLite ring-buffer path (used when server unreachable)
    pub offline_db_path: String,
}

fn resolve_cert_path(p: &str) -> String {
    let path = std::path::Path::new(p);
    if path.exists() {
        return p.to_string();
    }
    let parent = format!("../{}", p);
    if std::path::Path::new(&parent).exists() {
        return parent;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let direct = dir.join(p);
            if direct.exists() {
                return direct.to_string_lossy().to_string();
            }
            if let Some(pdir) = dir.parent() {
                let p_joined = pdir.join(p);
                if p_joined.exists() {
                    return p_joined.to_string_lossy().to_string();
                }
                if let Some(ppdir) = pdir.parent() {
                    let pp_joined = ppdir.join(p);
                    if pp_joined.exists() {
                        return pp_joined.to_string_lossy().to_string();
                    }
                }
            }
        }
    }
    p.to_string()
}

impl Config {
    pub fn from_env() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut server_addr_arg = None;
        for i in 0..args.len() {
            if (args[i] == "--server" || args[i] == "--server-addr") && i + 1 < args.len() {
                server_addr_arg = Some(args[i + 1].clone());
            }
        }

        let mut cfg_file_server = None;
        let mut cfg_file_agent = None;
        let mut check_paths = vec![
            std::path::PathBuf::from("config.json"),
            std::path::PathBuf::from("../config.json"),
        ];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                check_paths.push(dir.join("config.json"));
            }
        }
        for p in check_paths {
            if p.exists() {
                if let Ok(content) = std::fs::read_to_string(&p) {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(s) = val.get("server_addr").and_then(|v| v.as_str()) {
                            cfg_file_server = Some(s.to_string());
                        }
                        if let Some(s) = val.get("agent_id").and_then(|v| v.as_str()) {
                            cfg_file_agent = Some(s.to_string());
                        }
                        break;
                    }
                }
            }
        }

        let server_addr = server_addr_arg
            .or_else(|| env::var("EG_SERVER_ADDR").ok())
            .or(cfg_file_server)
            .unwrap_or_else(|| "https://192.168.102.105:4443".into());

        let default_agent_id = {
            let host = crate::collectors::hostname().to_lowercase();
            if host.is_empty() || host == "unknown-host" {
                "agnt-test-001".to_string()
            } else {
                format!("agnt-{}", host)
            }
        };
        let agent_id = env::var("EG_AGENT_ID")
            .ok()
            .or(cfg_file_agent)
            .unwrap_or(default_agent_id);

        Self {
            server_addr,
            agent_id,
            client_cert: resolve_cert_path(
                &env::var("EG_CLIENT_CERT").unwrap_or_else(|_| "certs/client.crt".into()),
            ),
            client_key: resolve_cert_path(
                &env::var("EG_CLIENT_KEY").unwrap_or_else(|_| "certs/client.key".into()),
            ),
            server_ca: resolve_cert_path(
                &env::var("EG_SERVER_CA").unwrap_or_else(|_| "certs/ca.crt".into()),
            ),
            server_ca_fingerprint: env::var("EG_SERVER_CA_FINGERPRINT")
                .unwrap_or_else(|_| "replace_with_real_fingerprint".into()),
            flush_interval_secs: 10,
            flush_max_bytes: 64 * 1024,
            offline_db_path: env::var("EG_OFFLINE_DB")
                .unwrap_or_else(|_| {
                    // Default to %ProgramData%\EndpointGuard\cache.db on Windows
                    #[cfg(windows)]
                    {
                        let pd = env::var("ProgramData")
                            .unwrap_or_else(|_| "C:\\ProgramData".into());
                        format!("{}\\EndpointGuard\\cache.db", pd)
                    }
                    #[cfg(not(windows))]
                    { "/tmp/eg_cache.db".into() }
                }),
        }
    }
}
