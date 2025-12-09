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
    5353
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
}

impl Config {
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
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.port, 5353);
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
}
