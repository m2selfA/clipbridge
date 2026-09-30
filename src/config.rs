use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io, os::windows::ffi::OsStrExt, path::PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedPeer {
    pub id: String,
    pub name: String,
    pub addr: String,
    pub fp: String,
    #[serde(default)]
    pub key_hex: String,
    /// None 表示人工确认的直接配对；Some(id) 表示由该直接配对设备介绍。
    #[serde(default)]
    pub introduced_by: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_discovery_port")]
    pub discovery_port: u16,
    /// 手动填写的对端地址；这些地址继续使用全局 key_hex 加密。
    #[serde(default)]
    pub peers: Vec<String>,
    /// 旧版共享密钥：保留作为手动地址的传输密钥。
    #[serde(default)]
    pub key_hex: String,
    #[serde(default)]
    pub device_id: String,
    #[serde(default = "default_device_name")]
    pub device_name: String,
    /// 本机长期身份密钥（32 字节十六进制），指纹由它派生。
    #[serde(default)]
    pub identity_hex: String,
    /// 已配对设备：每个设备拥有独立会话密钥。
    #[serde(default)]
    pub paired: Vec<PairedPeer>,
}

fn default_bind_addr() -> String {
    "0.0.0.0:45821".to_owned()
}

fn default_discovery_port() -> u16 {
    45822
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Windows-PC".to_owned())
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            discovery_port: default_discovery_port(),
            peers: Vec::new(),
            key_hex: random_hex(32),
            device_id: random_hex(16),
            device_name: default_device_name(),
            identity_hex: random_hex(32),
            paired: Vec::new(),
        }
    }
}

pub fn path() -> PathBuf {
    let root = match std::env::var_os("CLIPBRIDGE_CONFIG_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".")),
    };
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
    let config: Config = toml::from_str(&text).map_err(io::Error::other)?;
    Ok(migrate(config))
}

/// 为旧版配置补齐新增字段，确保任何时点升级都能直接运行。
fn migrate(mut config: Config) -> Config {
    config.key_hex = fill_missing(config.key_hex, random_hex(32));
    config.device_id = fill_missing(config.device_id, random_hex(16));
    config.device_name = fill_missing(config.device_name, default_device_name());
    config.identity_hex = fill_missing(config.identity_hex, random_hex(32));
    config
}

fn fill_missing(value: String, replacement: String) -> String {
    if value.trim().is_empty() {
        replacement
    } else {
        value
    }
}

pub fn save(config: &Config) -> io::Result<()> {
    let config_path = path();
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(config).map_err(io::Error::other)?;
    let temp_path = config_path.with_extension("toml.tmp");
    fs::write(&temp_path, text)?;

    let source: Vec<u16> = temp_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination: Vec<u16> = config_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        .map_err(io::Error::other)
    }
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

pub fn identity_bytes(config: &Config) -> Result<[u8; 32], String> {
    let bytes = decode_hex(config.identity_hex.trim())?;
    if bytes.len() != 32 {
        return Err("身份密钥必须是 64 个十六进制字符".to_owned());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// 本机指纹：SHA256(identity) 前 8 字节的十六进制表示，用于配对确认。
pub fn fingerprint(config: &Config) -> Result<String, String> {
    Ok(crate::discovery::fingerprint(&identity_bytes(config)?))
}

pub fn paired_peer(config: &Config, device_id: &str) -> Option<PairedPeer> {
    config
        .paired
        .iter()
        .find(|peer| peer.id == device_id)
        .cloned()
}

pub fn upsert_paired(config: &mut Config, mut peer: PairedPeer) {
    peer.introduced_by = None;
    if let Some(existing) = config.paired.iter_mut().find(|p| p.id == peer.id) {
        *existing = peer;
    } else {
        config.paired.push(peer);
    }
}

/// 自动介绍设备时使用：直接配对记录永远不会被间接介绍覆盖。
pub fn upsert_introduced(config: &mut Config, mut peer: PairedPeer, introducer_id: &str) -> bool {
    peer.introduced_by = Some(introducer_id.to_owned());
    if let Some(existing) = config.paired.iter_mut().find(|p| p.id == peer.id) {
        if existing.introduced_by.is_none() {
            return false;
        }
        if existing.introduced_by.as_deref() != Some(introducer_id) {
            return false;
        }
        if *existing == peer {
            return false;
        }
        *existing = peer;
        return true;
    }
    config.paired.push(peer);
    true
}

/// 为同一介绍者下的两个直接配对设备派生稳定的共享密钥。
/// 这样重复同步介绍信息不会生成新密钥，也无需在介绍者配置中增加第三张关系表。
pub fn introduction_key(
    config: &Config,
    peer_a_id: &str,
    peer_b_id: &str,
) -> Result<[u8; 32], String> {
    let identity = identity_bytes(config)?;
    let (first, second) = if peer_a_id <= peer_b_id {
        (peer_a_id, peer_b_id)
    } else {
        (peer_b_id, peer_a_id)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"ClipBridge-auto-pair-v1");
    hasher.update(identity);
    hasher.update(first.as_bytes());
    hasher.update([0]);
    hasher.update(second.as_bytes());
    Ok(hasher.finalize().into())
}

#[cfg(test)]
pub fn remove_paired(config: &mut Config, device_id: &str) {
    config.paired.retain(|peer| peer.id != device_id);
}
/// 供调用方删除已配对设备（后续 UI「忘记设备」按钮使用）。
#[allow(dead_code)]
pub fn forget_device(config: &mut Config, device_id: &str) {
    config
        .paired
        .retain(|peer| peer.id != device_id && peer.introduced_by.as_deref() != Some(device_id));
}

pub fn normalize_peers(text: &str) -> Vec<String> {
    text.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub fn random_hex(bytes: usize) -> String {
    let mut raw = vec![0u8; bytes];
    OsRng.fill_bytes(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_paired_drops_matching_id() {
        let mut config = Config::default();
        upsert_paired(
            &mut config,
            PairedPeer {
                id: "peer-x".to_owned(),
                name: "X".to_owned(),
                addr: "127.0.0.1:45821".to_owned(),
                fp: "ff".to_owned(),
                key_hex: random_hex(32),
                introduced_by: None,
            },
        );
        assert_eq!(config.paired.len(), 1);
        remove_paired(&mut config, "peer-x");
        assert!(config.paired.is_empty());
    }

    #[test]
    fn legacy_config_without_new_fields_migrates() {
        let legacy = r#"
bind_addr = "0.0.0.0:45821"
peers = ["192.168.1.20:45821"]
key_hex = "aa11"
device_id = "abcd"
"#;
        let parsed: Config = toml::from_str(legacy).expect("legacy config must parse");
        let config = migrate(parsed);
        assert_eq!(config.peers, vec!["192.168.1.20:45821".to_owned()]);
        assert_eq!(config.discovery_port, 45822);
        assert_eq!(config.device_name, default_device_name());
        assert!(config.paired.is_empty());
        assert_eq!(config.identity_hex.len(), 64);
        assert_eq!(config.key_hex, "aa11");
    }

    #[test]
    fn paired_peer_upsert_and_remove() {
        let mut config = Config::default();
        let peer = PairedPeer {
            id: "peer-1".to_owned(),
            name: "DESK".to_owned(),
            addr: "192.168.1.20:45821".to_owned(),
            fp: "0011223344556677".to_owned(),
            key_hex: random_hex(32),
            introduced_by: None,
        };
        upsert_paired(&mut config, peer.clone());
        upsert_paired(
            &mut config,
            PairedPeer {
                name: "DESK-2".to_owned(),
                ..peer
            },
        );
        assert_eq!(config.paired.len(), 1);
        assert_eq!(config.paired[0].name, "DESK-2");
        remove_paired(&mut config, "peer-1");
        assert!(config.paired.is_empty());
    }

    #[test]
    fn fingerprint_is_sixteen_hex_chars() {
        let config = Config::default();
        let fp = fingerprint(&config).expect("fingerprint must derive");
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn introduction_key_is_stable_independent_of_peer_order() {
        let config = Config::default();
        let first = introduction_key(&config, "b", "c").expect("key must derive");
        let second = introduction_key(&config, "c", "b").expect("key must derive");
        assert_eq!(first, second);
    }

    #[test]
    fn forgetting_direct_peer_revokes_its_introductions() {
        let mut config = Config::default();
        config.paired.push(PairedPeer {
            id: "direct".to_owned(),
            name: "Direct".to_owned(),
            addr: "127.0.0.1:45821".to_owned(),
            fp: "direct".to_owned(),
            key_hex: random_hex(32),
            introduced_by: None,
        });
        config.paired.push(PairedPeer {
            id: "introduced".to_owned(),
            name: "Introduced".to_owned(),
            addr: "127.0.0.1:45821".to_owned(),
            fp: "introduced".to_owned(),
            key_hex: random_hex(32),
            introduced_by: Some("direct".to_owned()),
        });
        forget_device(&mut config, "direct");
        assert!(config.paired.is_empty());
    }

    #[test]
    fn introduced_peer_cannot_replace_direct_peer() {
        let mut config = Config::default();
        let direct = PairedPeer {
            id: "peer".to_owned(),
            name: "Direct".to_owned(),
            addr: "127.0.0.1:45821".to_owned(),
            fp: "direct".to_owned(),
            key_hex: random_hex(32),
            introduced_by: None,
        };
        upsert_paired(&mut config, direct.clone());
        let changed = upsert_introduced(&mut config, direct, "introducer");
        assert!(!changed);
        assert_eq!(config.paired[0].introduced_by, None);
    }
}
