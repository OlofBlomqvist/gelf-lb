use serde::{Deserialize, Serialize};

#[derive(Debug,serde::Deserialize)]
pub struct Configuration {
    #[serde(default = "default_ip")]
    pub listen_ip : String,
    pub listen_port: u16,
    #[serde(default)]
    pub strip_fields: Vec<String>,
    #[serde(default)]
    pub blank_fields: Vec<String>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_transparent")]
    pub transparent: bool,
    #[serde(default)]
    pub attach_source_info: bool,
    #[serde(default)]
    pub allowed_source_ips: Vec<String>,
    #[serde(default)]
    pub backends: Vec<Backend>,
    #[serde(default = "default_use_gzip")]
    pub use_gzip : Option<bool>,
    #[serde(default = "default_chunk_size")]
    pub chunk_size : u64
}

fn default_ip() -> String { "127.0.0.1".to_string() }
fn default_log_level() -> String { "info".to_string() }
const fn default_transparent() -> bool { true }
const fn default_chunk_size() -> u64 { 1024 }
const fn default_use_gzip() -> Option<bool> { Some(true) }

#[derive(Debug, Deserialize, Serialize)]
pub struct Backend {
    pub ip: String,
    pub port: u16,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            listen_ip: "".into(),
            listen_port: 0,
            strip_fields: vec![],
            blank_fields: vec![],
            log_level: default_log_level(),
            transparent: default_transparent(),
            attach_source_info: false,
            allowed_source_ips: vec![],
            backends: vec![],
            chunk_size: default_chunk_size(),
            use_gzip: default_use_gzip()
        }
    }
}