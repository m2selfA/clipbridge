use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default)]
    pub peers: Vec<String>,
    #[serde(default)]
    pub key_hex: String,
    #[serde(default)]
    pub device_id: String,
}

fn default_bind_addr() -> String {
    "0.0.0.0:45821".to_owned()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            peers: Vec::new(),
            key_hex: random_hex(32),
            device_id: random_hex(16),
        }
    }
}

pub fn path() -> PathBuf {
    let root = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    root.join("ClipBridge").join("config.toml")
}

pub fn load() -> io::Result<Config> {
    let config_path = path();
    if !config_path.exists() {
        let config = Config::default();
        save(&config)?;
        return Ok(config);
    }

    let text = fs::read_to_string(config_path)?;
    let mut config: Config = toml::from_str(&text).map_err(io::Error::other)?;
    if config.key_hex.is_empty() {
        config.key_hex = random_hex(32);
    }
    if config.device_id.is_empty() {
        config.device_id = random_hex(16);
    }
    Ok(config)
}

pub fn save(config: &Config) -> io::Result<()> {
    let config_path = path();
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(config).map_err(io::Error::other)?;
    fs::write(config_path, text)
}

pub fn parse_key(text: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(text.trim())?;
    if bytes.len() != 32 {
        return Err("共享密钥必须是 64 个十六进制字符".to_owned());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

pub fn normalize_peers(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    OsRng.fill_bytes(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("十六进制密钥长度必须为偶数".to_owned());
    }
    let mut result = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for index in (0..bytes.len()).step_by(2) {
        let high = hex_digit(bytes[index])?;
        let low = hex_digit(bytes[index + 1])?;
        result.push((high << 4) | low);
    }
    Ok(result)
}

fn hex_digit(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("共享密钥只能包含十六进制字符".to_owned()),
    }
}

#[allow(dead_code)]
fn _is_file(path: &Path) -> bool {
    path.is_file()
}
