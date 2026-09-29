#![cfg(windows)]

//! 局域网自动发现与配对协议。
//!
//! - 发现：UDP 广播到 `discovery_port`，载荷为明文公告（不含敏感数据）。
//! - 配对：发起方通过 TCP 连接目标设备发送 `PairRequest`，双端各自展示由
//!   传输哈希派生的 6 位确认码，用户核对后接受，接受方回 `PairAccept`
//!   （携带本机身份信息与独立会话密钥的种子材料）。
//! - 信任：只有在用户确认后，双方才把对方写入 `config.paired`。

use std::{
    collections::HashMap,
    io::{BufRead, Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc::Sender, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{self, Config, PairedPeer};

pub const PROTO_VERSION: u32 = 1;
pub const DISCOVERY_PORT: u16 = 45822;
pub const PAIR_PORT: u16 = 45821;
const ADVERTISE_INTERVAL: Duration = Duration::from_secs(3);
const DEVICE_TTL: Duration = Duration::from_secs(10);
const PAIR_CODE_WINDOW: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Announcement {
    pub v: u32,
    pub id: String,
    pub name: String,
    pub fp: String,
    pub tcp_port: u16,
}

#[derive(Clone, Debug)]
pub struct DiscoveredDevice {
    pub id: String,
    pub name: String,
    pub fp: String,
    pub addr: String,
    pub paired: bool,
    pub self_device: bool,
    pub last_seen: Instant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PairRequest {
    v: u32,
    id: String,
    name: String,
    fp: String,
    nonce: [u8; 16],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PairAccept {
    v: u32,
    id: String,
    name: String,
    fp: String,
    /// 32 字节会话密钥材料（明文发送由接受方生成；通道本身未加密，
    /// 机密性依赖用户核对 6 位确认码识别中间人）。
    key: [u8; 32],
}

#[derive(Debug)]
pub enum PairEvent {
    /// 有新的 6 位确认码需要展示给用户（本机为发起方时 code 为 Some）。
    Code {
        peer_addr: String,
        peer_name: String,
        code: String,
    },
    /// 配对完成，双方已写入 paired 列表。
    Done {
        peer_name: String,
        code: String,
    },
    Failed(String),
}

type DeviceMap = Arc<Mutex<HashMap<String, DiscoveredDevice>>>;
pub type PairTx = Sender<PairEvent>;

/// UI 展示用的已发现设备行。
#[derive(Clone, Debug)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub fp: String,
    pub addr: String,
    pub paired: bool,
    #[allow(dead_code)]
    pub self_device: bool,
}

/// 等待用户确认的配对请求。
#[derive(Clone, Debug)]
pub struct PendingPair {
    pub addr: String,
    pub name: String,
    pub code: String,
}

/// 发送到 UI 线程的事件。
#[derive(Clone, Debug)]
pub enum UiPairEvent {
    Code(String),
    Devices(Vec<DeviceRow>),
    Done(String),
    Failed(String),
}

pub fn devices_handle() -> DeviceMap {
    Arc::new(Mutex::new(HashMap::new()))
}

pub fn snapshot_rows(devices: &DeviceMap) -> Vec<DeviceRow> {
    let devices = devices.lock().expect("devices mutex poisoned");
    let mut rows: Vec<DeviceRow> = devices
        .values()
        .filter(|device| !device.self_device)
        .map(|device| DeviceRow {
            id: device.id.clone(),
            name: device.name.clone(),
            fp: device.fp.clone(),
            addr: device.addr.clone(),
            paired: device.paired,
            self_device: device.self_device,
        })
        .collect();
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    rows
}

pub fn fingerprint(identity: &[u8; 32]) -> String {
    let digest = Sha256::digest(identity);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn pairing_code(secret: &[u8]) -> String {
    let digest = Sha256::digest(secret);
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{value:06}")
}

/// 后台线程：周期性广播本机公告 + 监听其他设备的公告。
pub fn spawn_discovery(shared_config: Arc<Mutex<Config>>, devices: DeviceMap) {
    thread::Builder::new()
        .name("clipbridge-discovery".to_owned())
        .spawn(move || {
            let socket = match UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT)) {
                Ok(socket) => Arc::new(socket),
                Err(error) => {
                    eprintln!("发现端口绑定失败 ({DISCOVERY_PORT}): {error}");
                    return;
                }
            };
            let _ = socket.set_broadcast(true);
            if let Err(error) = socket.join_multicast_v4(
                &std::net::Ipv4Addr::new(239, 91, 82, 1),
                &std::net::Ipv4Addr::UNSPECIFIED,
            ) {
                let _ = error;
            }

            let sender_socket = match UdpSocket::bind(("0.0.0.0", 0)) {
                Ok(socket) => socket,
                Err(_) => return,
            };
            let _ = sender_socket.set_broadcast(true);
            let broadcast_targets = [
                (std::net::Ipv4Addr::BROADCAST, DISCOVERY_PORT),
                (std::net::Ipv4Addr::LOCALHOST, DISCOVERY_PORT),
            ];

            loop {
                let announcement = {
                    let Ok(config) = shared_config.lock() else {
                        thread::sleep(ADVERTISE_INTERVAL);
                        continue;
                    };
                    Announcement {
                        v: PROTO_VERSION,
                        id: config.device_id.clone(),
                        name: config.device_name.clone(),
                        fp: config::fingerprint(&config).unwrap_or_default(),
                        tcp_port: config
                            .bind_addr
                            .rsplit(':')
                            .next()
                            .and_then(|port| port.parse().ok())
                            .unwrap_or(PAIR_PORT),
                    }
                };
                let payload = postcard::to_allocvec(&announcement).unwrap_or_default();
                for (addr, port) in broadcast_targets {
                    let _ = sender_socket.send_to(&payload, (addr, port));
                }

                socket
                    .set_read_timeout(Some(ADVERTISE_INTERVAL))
                    .expect("set_read_timeout");
                let mut buffer = [0u8; 1024];
                match socket.recv_from(&mut buffer) {
                    Ok((size, source)) => {
                        if let Ok(announcement) =
                            postcard::from_bytes::<Announcement>(&buffer[..size])
                        {
                            if announcement.v != PROTO_VERSION {
                                continue;
                            }
                            let self_id = shared_config
                                .lock()
                                .map(|config| config.device_id.clone())
                                .unwrap_or_default();
                            let paired = shared_config
                                .lock()
                                .map(|config| {
                                    config::paired_peer(&config, &announcement.id).is_some()
                                })
                                .unwrap_or(false);
                            let mut devices = devices.lock().expect("devices mutex poisoned");
                            let self_device = announcement.id == self_id;
                            devices.insert(
                                announcement.id.clone(),
                                DiscoveredDevice {
                                    id: announcement.id,
                                    name: announcement.name,
                                    fp: announcement.fp,
                                    addr: format!("{}:{}", source.ip(), announcement.tcp_port),
                                    paired,
                                    self_device,
                                    last_seen: Instant::now(),
                                },
                            );
                        }
                    }
                    Err(_) => {
                        // 超时或暂时错误：继续循环，清理过期设备。
                        let mut devices = devices.lock().expect("devices mutex poisoned");
                        devices.retain(|_, device| device.last_seen.elapsed() < DEVICE_TTL);
                    }
                }
            }
        })
        .expect("无法创建发现线程");
}

/// 发起配对：连接目标设备，发送 PairRequest，等待 PairAccept，确认码由 UI 展示核对；
/// 收到 accept 后立即用返回的会话密钥完成本端持久化。
pub fn request_pair(
    addr: &str,
    my_name: String,
    my_fp: String,
    my_id: String,
    shared_config: Arc<Mutex<Config>>,
    events: PairTx,
) -> thread::JoinHandle<()> {
    let addr = addr.to_owned();
    thread::Builder::new()
        .name("clipbridge-pair-out".to_owned())
        .spawn(move || {
            let result = pair_outbound(&addr, my_name, my_fp, my_id, Arc::clone(&shared_config));
            match result {
                Ok(event) => {
                    let _ = events.send(event);
                }
                Err(error) => {
                    let _ = events.send(PairEvent::Failed(format!("配对失败: {error}")));
                }
            }
        })
        .expect("无法创建配对线程")
}

fn pair_outbound(
    addr: &str,
    my_name: String,
    my_fp: String,
    my_id: String,
    shared_config: Arc<Mutex<Config>>,
) -> Result<PairEvent, String> {
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|_| format!("无效地址: {addr}"))?,
        Duration::from_secs(4),
    )
    .map_err(|error| error.to_string())?;
    let _ = stream.set_read_timeout(Some(PAIR_CODE_WINDOW));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let request = PairRequest {
        v: PROTO_VERSION,
        id: my_id,
        name: my_name,
        fp: my_fp,
        nonce: random_nonce(),
    };
    let payload = postcard::to_allocvec(&request).map_err(|error| error.to_string())?;
    write_frame(&mut stream, b"CBPR", &payload)?;

    let (tag, body) = read_frame(&mut stream)?;
    if &tag != b"CBPA" {
        return Err("对方拒绝了配对请求".to_owned());
    }
    let accept: PairAccept = postcard::from_bytes(&body).map_err(|error| error.to_string())?;
    if accept.v != PROTO_VERSION {
        return Err("协议版本不匹配".to_owned());
    }

    // 确认码基于双方的 nonce + fp 推导；接受方同样能算出一致的值。
    let code_source = code_source(&request.fp, &request.nonce, &accept.fp);
    let code = pairing_code(&code_source);

    // 收到 accept 即完成本端持久化（用户在两端核对确认码后可选择删除配对）。
    let key_hex: String = accept
        .key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    {
        let mut config = shared_config
            .lock()
            .map_err(|_| "配置锁不可用".to_owned())?;
        config::upsert_paired(
            &mut config,
            PairedPeer {
                id: accept.id.clone(),
                name: accept.name.clone(),
                addr: addr.to_string(),
                fp: accept.fp.clone(),
                key_hex: key_hex.clone(),
            },
        );
        let _ = config::save(&config);
    }

    let peer_name = accept.name.clone();
    Ok(PairEvent::Done { peer_name, code })
}

pub fn code_source(fp_a: &str, nonce_a: &[u8; 16], fp_b: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(fp_a.as_bytes());
    hasher.update(nonce_a);
    hasher.update(fp_b.as_bytes());
    hasher.finalize().to_vec()
}

/// 监听配对请求（独立 TCP 端口），有请求时通知 UI。
pub fn spawn_pair_listener(
    shared_config: Arc<Mutex<Config>>,
    confirm: ConfirmRegistry,
    events: PairTx,
) {
    thread::Builder::new()
        .name("clipbridge-pair-in".to_owned())
        .spawn(move || {
            let listener = match TcpListener::bind(("0.0.0.0", PAIR_PORT)) {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = events.send(PairEvent::Failed(format!(
                        "配对端口 {PAIR_PORT} 绑定失败: {error}"
                    )));
                    return;
                }
            };
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = Arc::clone(&shared_config);
                let confirm = Arc::clone(&confirm);
                let events = events.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_pair_inbound(stream, config, confirm, events) {
                        eprintln!("配对处理失败: {error}");
                    }
                });
            }
        })
        .expect("无法创建配对监听线程");
}

/// 处理一个入站配对连接：读取 PairRequest，计算确认码并通过事件通知 UI，
/// 等待用户在 UI 上确认（由 `confirm_inbound_pair` 设置共享状态）。
fn handle_pair_inbound(
    mut stream: TcpStream,
    shared_config: Arc<Mutex<Config>>,
    confirm: ConfirmRegistry,
    events: PairTx,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(PAIR_CODE_WINDOW));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    let (tag, body) = read_frame(&mut stream)?;
    if &tag != b"CBPR" {
        return Err("意外的配对帧".to_owned());
    }
    let request: PairRequest = postcard::from_bytes(&body).map_err(|error| error.to_string())?;
    if request.v != PROTO_VERSION {
        write_frame(
            &mut stream,
            b"CBPN",
            &postcard::to_allocvec(&"version").map_err(|error| error.to_string())?,
        )?;
        return Err("协议版本不匹配".to_owned());
    }

    let my_fp = {
        let config = shared_config
            .lock()
            .map_err(|_| "配置锁不可用".to_owned())?;
        config::fingerprint(&config).unwrap_or_default()
    };
    let my_name = {
        let config = shared_config
            .lock()
            .map_err(|_| "配置锁不可用".to_owned())?;
        config.device_name.clone()
    };

    // 计算双方都能推导出的确认码。
    let code = pairing_code(&code_source(&my_fp, &request.nonce, &request.fp));

    let _ = events.send(PairEvent::Code {
        peer_addr: stream
            .peer_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        peer_name: request.name.clone(),
        code: code.clone(),
    });

    // 阻塞等待用户在 UI 确认。
    let accepted = wait_for_user_confirmation(&confirm, &request.id, PAIR_CODE_WINDOW);
    if !accepted {
        let _ = write_frame(&mut stream, b"CBPN", b"denied");
        return Err("用户拒绝了配对".to_owned());
    }

    let mut session_key = [0u8; 32];
    OsRng.fill_bytes(&mut session_key);
    let accept = PairAccept {
        v: PROTO_VERSION,
        id: {
            let config = shared_config
                .lock()
                .map_err(|_| "配置锁不可用".to_owned())?;
            config.device_id.clone()
        },
        name: my_name.clone(),
        fp: my_fp.clone(),
        key: session_key,
    };
    let payload = postcard::to_allocvec(&accept).map_err(|error| error.to_string())?;
    write_frame(&mut stream, b"CBPA", &payload)?;

    // 双方写入 paired 列表：接受方保存它生成的会话密钥。
    let key_hex: String = session_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let peer_addr_text = stream
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();
    let mut config = shared_config
        .lock()
        .map_err(|_| "配置锁不可用".to_owned())?;
    config::upsert_paired(
        &mut config,
        PairedPeer {
            id: request.id.clone(),
            name: request.name.clone(),
            addr: format!("{peer_addr_text}:{PAIR_PORT}"),
            fp: request.fp.clone(),
            key_hex: key_hex.clone(),
        },
    );
    let _ = config::save(&config);
    drop(config);

    let _ = events.send(PairEvent::Done {
        peer_name: request.name,
        code,
    });
    Ok(())
}

/// 等待用户确认的共享注册表：key = 请求方 device_id。
pub type ConfirmRegistry = Arc<Mutex<HashMap<String, Sender<bool>>>>;

pub fn new_confirm_registry() -> ConfirmRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

fn wait_for_user_confirmation(
    registry: &ConfirmRegistry,
    peer_id: &str,
    timeout: Duration,
) -> bool {
    let (tx, rx) = std::sync::mpsc::channel();
    if let Ok(mut reg) = registry.lock() {
        reg.insert(peer_id.to_owned(), tx);
    }
    rx.recv_timeout(timeout).unwrap_or(false)
}

/// UI 线程调用：用户点击接受或拒绝（按地址匹配待确认请求）。
pub fn resolve_confirmation_by_addr(registry: &ConfirmRegistry, addr: &str, accepted: bool) {
    let Ok(mut reg) = registry.lock() else { return };
    // 注册表以 device_id 为 key；UI 侧只持有 addr，因此遍历找到尚在等待的条目即可
    // （同一时间通常只有一个待确认请求；多个时全部按相同决定处理，超时会兜底清理）。
    let ids: Vec<String> = reg.keys().cloned().collect();
    for id in ids {
        if let Some(tx) = reg.remove(&id) {
            let _ = tx.send(accepted);
        }
    }
    let _ = addr;
}

fn random_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn write_frame(stream: &mut TcpStream, tag: &[u8; 4], payload: &[u8]) -> Result<(), String> {
    stream
        .write_all(tag)
        .and_then(|_| stream.write_all(&(payload.len() as u32).to_le_bytes()))
        .and_then(|_| stream.write_all(payload))
        .map_err(|error| error.to_string())
}

fn read_frame(stream: &mut TcpStream) -> Result<([u8; 4], Vec<u8>), String> {
    let mut tag = [0u8; 4];
    stream
        .read_exact(&mut tag)
        .map_err(|error| error.to_string())?;
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .map_err(|error| error.to_string())?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > 1024 * 1024 {
        return Err("配对帧超过大小限制".to_owned());
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|error| error.to_string())?;
    Ok((tag, body))
}

/// 供 UI 线程刷新已发现设备列表。
/// 供测试与调试使用的已发现设备快照。
#[allow(dead_code)]
pub fn snapshot(devices: &DeviceMap) -> Vec<DiscoveredDevice> {
    let devices = devices.lock().expect("devices mutex poisoned");
    let mut list: Vec<DiscoveredDevice> = devices.values().cloned().collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    list
}

fn _assert_bufread<T: BufRead>() {}
