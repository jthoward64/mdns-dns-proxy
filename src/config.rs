use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tracing::Level;

/// mDNS-DNS Discovery Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    #[serde(default)]
    pub server: ServerConfig,
    
    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,
    
    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,
    
    /// mDNS query configuration
    #[serde(default)]
    pub mdns: MdnsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// IP address to bind to
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,
    
    /// Port to bind to
    #[serde(default = "default_port")]
    pub port: u16,
    
    /// TCP connection timeout in seconds
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub ttl_seconds: u64,
    
    /// Enable or disable caching
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsConfig {
    /// mDNS query timeout in milliseconds
    #[serde(default = "default_query_timeout")]
    pub query_timeout_ms: u64,
    
    /// Service discovery timeout in milliseconds
    #[serde(default = "default_discovery_timeout")]
    pub discovery_timeout_ms: u64,
    
    /// Service types to query when resolving hostnames
    #[serde(default = "default_service_types")]
    pub service_types: Vec<String>,
}

// Default value functions
fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
}

fn default_port() -> u16 {
    5335
}

fn default_tcp_timeout() -> u64 {
    30
}

fn default_cache_ttl() -> u64 {
    120
}

fn default_cache_enabled() -> bool {
    true
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_query_timeout() -> u64 {
    1000
}

fn default_discovery_timeout() -> u64 {
    2000
}

fn default_service_types() -> Vec<String> {
    vec![
        "_http._tcp.local.".to_string(),
        "_ssh._tcp.local.".to_string(),
        "_device-info._tcp.local.".to_string(),
    ]
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            port: default_port(),
            tcp_timeout: default_tcp_timeout(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_cache_ttl(),
            enabled: default_cache_enabled(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            query_timeout_ms: default_query_timeout(),
            discovery_timeout_ms: default_discovery_timeout(),
            service_types: default_service_types(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            cache: CacheConfig::default(),
            logging: LoggingConfig::default(),
            mdns: MdnsConfig::default(),
        }
    }
}

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to configuration file (TOML format)
    #[arg(short, long, env = "MDNS_DNS_PROXY_CONFIG")]
    pub config: Option<PathBuf>,
    
    /// IP address to bind to
    #[arg(short, long, env = "MDNS_DNS_PROXY_BIND_ADDRESS")]
    pub bind_address: Option<IpAddr>,
    
    /// Port to bind to
    #[arg(short, long, env = "MDNS_DNS_PROXY_PORT")]
    pub port: Option<u16>,
    
    /// Cache TTL in seconds
    #[arg(long, env = "MDNS_DNS_PROXY_CACHE_TTL")]
    pub cache_ttl: Option<u64>,
    
    /// Disable caching
    #[arg(long, env = "MDNS_DNS_PROXY_NO_CACHE")]
    pub no_cache: bool,
    
    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, env = "MDNS_DNS_PROXY_LOG_LEVEL")]
    pub log_level: Option<String>,
    
    /// mDNS query timeout in milliseconds
    #[arg(long, env = "MDNS_DNS_PROXY_QUERY_TIMEOUT")]
    pub query_timeout: Option<u64>,
    
    /// Print an example configuration file with defaults and exit
    #[arg(long)]
    pub print_example_config: bool,
}

impl Config {
    /// Print an example configuration file with all defaults and comments
    pub fn print_example_config() {
        println!(r#"# mDNS-DNS Discovery Proxy Configuration
# 
# This file configures the behavior of the mDNS-DNS proxy server.
# All settings have sensible defaults and are optional.

[server]
# IP address to bind the DNS server to
# Default: 127.0.0.1 (localhost only)
# Use 0.0.0.0 to listen on all interfaces
bind_address = "127.0.0.1"

# Port to bind the DNS server to
# Default: 5335
# Note: Ports below 1024 require root/admin privileges
port = 5335

# TCP connection timeout in seconds
# Default: 30
tcp_timeout = 30

[cache]
# Cache TTL (time-to-live) in seconds
# How long to cache mDNS query results
# Default: 120 (2 minutes)
ttl_seconds = 120

# Enable or disable result caching
# Default: true
enabled = true

[logging]
# Log level for the application
# Options: trace, debug, info, warn, error
# Default: info
level = "info"

[mdns]
# Timeout for individual mDNS queries in milliseconds
# Default: 1000 (1 second)
query_timeout_ms = 1000

# Timeout for service discovery operations in milliseconds
# Default: 2000 (2 seconds)
discovery_timeout_ms = 2000

# Service types to query when resolving hostnames
# These are used to discover devices by hostname
# Default: _http._tcp.local., _ssh._tcp.local., _device-info._tcp.local.
service_types = [
    "_http._tcp.local.",
    "_ssh._tcp.local.",
    "_device-info._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
]
"#);
    }
    
    /// Load configuration from file, environment variables, and CLI arguments
    pub fn load(args: Args) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Start with default config
        let mut config = if let Some(config_path) = &args.config {
            // Load from file
            let contents = std::fs::read_to_string(config_path)?;
            toml::from_str(&contents)?
        } else {
            Config::default()
        };
        
        // Override with CLI arguments
        if let Some(bind_address) = args.bind_address {
            config.server.bind_address = bind_address;
        }
        
        if let Some(port) = args.port {
            config.server.port = port;
        }
        
        if let Some(cache_ttl) = args.cache_ttl {
            config.cache.ttl_seconds = cache_ttl;
        }
        
        if args.no_cache {
            config.cache.enabled = false;
        }
        
        if let Some(log_level) = args.log_level {
            config.logging.level = log_level;
        }
        
        if let Some(query_timeout) = args.query_timeout {
            config.mdns.query_timeout_ms = query_timeout;
        }
        
        Ok(config)
    }
    
    /// Parse log level string to tracing::Level
    pub fn parse_log_level(&self) -> Level {
        match self.logging.level.to_lowercase().as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            "error" => Level::ERROR,
            _ => {
                eprintln!("Invalid log level '{}', defaulting to INFO", self.logging.level);
                Level::INFO
            }
        }
    }
    
    /// Get cache TTL as Duration
    pub fn cache_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.cache.ttl_seconds)
    }
    
    /// Get query timeout as Duration
    #[allow(dead_code)]
    pub fn query_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.mdns.query_timeout_ms)
    }
    
    /// Get discovery timeout as Duration
    #[allow(dead_code)]
    pub fn discovery_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.mdns.discovery_timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 5335);
        assert_eq!(config.cache.ttl_seconds, 120);
        assert!(config.cache.enabled);
    }
    
    #[test]
    fn test_toml_parse() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0"
            port = 5354
            
            [cache]
            ttl_seconds = 300
            enabled = true
            
            [logging]
            level = "debug"
        "#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.port, 5354);
        assert_eq!(config.cache.ttl_seconds, 300);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_default_server_config() {
        let server = ServerConfig::default();
        assert_eq!(server.bind_address, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(server.port, 5335);
        assert_eq!(server.tcp_timeout, 30);
    }

    #[test]
    fn test_default_cache_config() {
        let cache = CacheConfig::default();
        assert_eq!(cache.ttl_seconds, 120);
        assert!(cache.enabled);
    }

    #[test]
    fn test_default_logging_config() {
        let logging = LoggingConfig::default();
        assert_eq!(logging.level, "info");
    }

    #[test]
    fn test_default_mdns_config() {
        let mdns = MdnsConfig::default();
        assert_eq!(mdns.query_timeout_ms, 1000);
        assert_eq!(mdns.discovery_timeout_ms, 2000);
        assert_eq!(mdns.service_types.len(), 3);
    }

    #[test]
    fn test_parse_log_level_valid() {
        let mut config = Config::default();
        
        config.logging.level = "trace".to_string();
        assert_eq!(config.parse_log_level(), Level::TRACE);
        
        config.logging.level = "debug".to_string();
        assert_eq!(config.parse_log_level(), Level::DEBUG);
        
        config.logging.level = "info".to_string();
        assert_eq!(config.parse_log_level(), Level::INFO);
        
        config.logging.level = "warn".to_string();
        assert_eq!(config.parse_log_level(), Level::WARN);
        
        config.logging.level = "error".to_string();
        assert_eq!(config.parse_log_level(), Level::ERROR);
    }

    #[test]
    fn test_parse_log_level_case_insensitive() {
        let mut config = Config::default();
        
        config.logging.level = "DEBUG".to_string();
        assert_eq!(config.parse_log_level(), Level::DEBUG);
        
        config.logging.level = "Info".to_string();
        assert_eq!(config.parse_log_level(), Level::INFO);
        
        config.logging.level = "WARN".to_string();
        assert_eq!(config.parse_log_level(), Level::WARN);
    }

    #[test]
    fn test_parse_log_level_invalid_defaults_to_info() {
        let mut config = Config::default();
        
        config.logging.level = "invalid".to_string();
        assert_eq!(config.parse_log_level(), Level::INFO);
        
        config.logging.level = "".to_string();
        assert_eq!(config.parse_log_level(), Level::INFO);
    }

    #[test]
    fn test_cache_ttl_conversion() {
        let mut config = Config::default();
        
        config.cache.ttl_seconds = 60;
        assert_eq!(config.cache_ttl(), Duration::from_secs(60));
        
        config.cache.ttl_seconds = 300;
        assert_eq!(config.cache_ttl(), Duration::from_secs(300));
    }

    #[test]
    fn test_query_timeout_conversion() {
        let mut config = Config::default();
        
        config.mdns.query_timeout_ms = 500;
        assert_eq!(config.query_timeout(), Duration::from_millis(500));
        
        config.mdns.query_timeout_ms = 2000;
        assert_eq!(config.query_timeout(), Duration::from_millis(2000));
    }

    #[test]
    fn test_discovery_timeout_conversion() {
        let mut config = Config::default();
        
        config.mdns.discovery_timeout_ms = 1000;
        assert_eq!(config.discovery_timeout(), Duration::from_millis(1000));
        
        config.mdns.discovery_timeout_ms = 5000;
        assert_eq!(config.discovery_timeout(), Duration::from_millis(5000));
    }

    #[test]
    fn test_toml_partial_config() {
        let toml_str = r#"
            [server]
            port = 5354
        "#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.port, 5354);
        // Other values should be defaults
        assert_eq!(config.server.bind_address, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(config.cache.ttl_seconds, 120);
    }

    #[test]
    fn test_toml_full_config() {
        let toml_str = r#"
            [server]
            bind_address = "0.0.0.0"
            port = 5354
            tcp_timeout = 60
            
            [cache]
            ttl_seconds = 300
            enabled = false
            
            [logging]
            level = "trace"
            
            [mdns]
            query_timeout_ms = 1500
            discovery_timeout_ms = 3000
            service_types = ["_http._tcp.local.", "_ssh._tcp.local."]
        "#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.bind_address, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(config.server.port, 5354);
        assert_eq!(config.server.tcp_timeout, 60);
        assert_eq!(config.cache.ttl_seconds, 300);
        assert!(!config.cache.enabled);
        assert_eq!(config.logging.level, "trace");
        assert_eq!(config.mdns.query_timeout_ms, 1500);
        assert_eq!(config.mdns.discovery_timeout_ms, 3000);
        assert_eq!(config.mdns.service_types.len(), 2);
    }

    #[test]
    fn test_toml_ipv6_address() {
        let toml_str = r#"
            [server]
            bind_address = "::"
            port = 5335
        "#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(matches!(config.server.bind_address, IpAddr::V6(_)));
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        
        // Should be valid TOML
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.server.port, config.server.port);
        assert_eq!(parsed.cache.ttl_seconds, config.cache.ttl_seconds);
    }

    #[test]
    fn test_config_clone() {
        let config = Config::default();
        let cloned = config.clone();
        
        assert_eq!(config.server.port, cloned.server.port);
        assert_eq!(config.cache.ttl_seconds, cloned.cache.ttl_seconds);
    }

    #[test]
    fn test_service_types_customization() {
        let toml_str = r#"
            [mdns]
            service_types = [
                "_http._tcp.local.",
                "_https._tcp.local.",
                "_smb._tcp.local.",
                "_printer._tcp.local.",
            ]
        "#;
        
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.mdns.service_types.len(), 4);
        assert!(config.mdns.service_types.contains(&"_smb._tcp.local.".to_string()));
    }

    #[test]
    fn test_config_load_with_defaults() {
        use std::net::Ipv4Addr;
        
        let args = Args {
            config: None,
            bind_address: None,
            port: None,
            cache_ttl: None,
            no_cache: false,
            log_level: None,
            query_timeout: None,
            print_example_config: false,
        };
        
        let config = Config::load(args).unwrap();
        assert_eq!(config.server.bind_address, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(config.server.port, 5335);
        assert_eq!(config.cache.ttl_seconds, 120);
        assert!(config.cache.enabled);
    }

    #[test]
    fn test_config_load_with_cli_overrides() {
        use std::net::Ipv4Addr;
        
        let args = Args {
            config: None,
            bind_address: Some(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            port: Some(5354),
            cache_ttl: Some(300),
            no_cache: true,
            log_level: Some("debug".to_string()),
            query_timeout: Some(2000),
            print_example_config: false,
        };
        
        let config = Config::load(args).unwrap();
        assert_eq!(config.server.bind_address, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(config.server.port, 5354);
        assert_eq!(config.cache.ttl_seconds, 300);
        assert!(!config.cache.enabled);
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.mdns.query_timeout_ms, 2000);
    }

    #[test]
    fn test_config_load_from_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;
        
        let toml_content = r#"
            [server]
            bind_address = "0.0.0.0"
            port = 5355
            
            [cache]
            ttl_seconds = 180
        "#;
        
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_content.as_bytes()).unwrap();
        let path = temp_file.path().to_path_buf();
        
        let args = Args {
            config: Some(path),
            bind_address: None,
            port: None,
            cache_ttl: None,
            no_cache: false,
            log_level: None,
            query_timeout: None,
            print_example_config: false,
        };
        
        let config = Config::load(args).unwrap();
        assert_eq!(config.server.port, 5355);
        assert_eq!(config.cache.ttl_seconds, 180);
    }

    #[test]
    fn test_config_load_file_with_cli_override() {
        use std::io::Write;
        use tempfile::NamedTempFile;
        
        let toml_content = r#"
            [server]
            port = 5355
        "#;
        
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_content.as_bytes()).unwrap();
        let path = temp_file.path().to_path_buf();
        
        let args = Args {
            config: Some(path),
            bind_address: None,
            port: Some(5356), // CLI override
            cache_ttl: None,
            no_cache: false,
            log_level: None,
            query_timeout: None,
            print_example_config: false,
        };
        
        let config = Config::load(args).unwrap();
        // CLI override should win
        assert_eq!(config.server.port, 5356);
    }

    #[test]
    fn test_config_load_invalid_file() {
        use std::path::PathBuf;
        
        let args = Args {
            config: Some(PathBuf::from("/nonexistent/file.toml")),
            bind_address: None,
            port: None,
            cache_ttl: None,
            no_cache: false,
            log_level: None,
            query_timeout: None,
            print_example_config: false,
        };
        
        let result = Config::load(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_load_partial_cli_overrides() {
        let args = Args {
            config: None,
            bind_address: None,
            port: Some(5354),
            cache_ttl: None,
            no_cache: false,
            log_level: Some("trace".to_string()),
            query_timeout: None,
            print_example_config: false,
        };
        
        let config = Config::load(args).unwrap();
        assert_eq!(config.server.port, 5354);
        assert_eq!(config.logging.level, "trace");
        // Other values should be defaults
        assert_eq!(config.cache.ttl_seconds, 120);
        assert!(config.cache.enabled);
    }
}
