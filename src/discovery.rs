#![cfg(windows)]

//! 局域网自动发现与配对协议。
//!
//! - 发现：UDP 广播到 `discovery_port`，载荷为明文公告（不含敏感数据）。
//! - 配对：发起方通过 TCP 连接目标设备的同步端口发送 `PairRequest`（CBPR 帧标签），
//!   双端各自展示由传输哈希派生的 6 位确认码，用户核对后接受，接受方回 `PairAccept`
//!   （携带本机身份信息与独立会话密钥的种子材料）。配对与剪贴板数据共用同一端口。
//! - 信任：直接配对只有在用户确认后写入 `config.paired`；已直接配对的设备可通过加密介绍帧互相建立一跳间接信任。

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, TcpStream, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{Sender, SyncSender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use chacha20poly1305::aead::{Aead, KeyInit};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    config::{self, Config, PairedPeer},
    status::Status,
};

pub const PROTO_VERSION: u32 = 1;
pub const DISCOVERY_PORT: u16 = 45822;
pub const PAIR_PORT: u16 = 45821;
/// 配对请求帧标签：与剪贴板数据共用同一 TCP 端口，按首 4 字节区分。
pub const PAIR_REQUEST_TAG: &[u8; 4] = b"CBPR";
/// 直接配对设备之间的自动介绍帧：使用介绍者已有的会话密钥加密。
pub const INTRODUCTION_TAG: &[u8; 4] = b"CBIN";
const ADVERTISE_INTERVAL: Duration = Duration::from_secs(3);
const INTRODUCTION_SYNC_INTERVAL: Duration = Duration::from_secs(15);
const MIN_ANNOUNCEMENT_INTERVAL: Duration = Duration::from_secs(3);
const MAX_DISCOVERY_SOURCES: usize = 128;
const MAX_DISCOVERED_DEVICES: usize = 256;
const MAX_PENDING_PAIRINGS: usize = 2;
const DEVICE_TTL: Duration = Duration::from_secs(10);
pub const PAIR_CODE_WINDOW: Duration = Duration::from_secs(120);
static INTRODUCTION_SYNC_ACTIVE: AtomicBool = AtomicBool::new(false);
static PENDING_PAIRINGS: AtomicUsize = AtomicUsize::new(0);

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
    pub introduced_by: Option<String>,
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
    #[serde(default)]
    tcp_port: u16,
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

/// 由已经互相信任的设备介绍第三方设备。
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerIntroduction {
    v: u32,
    introducer_id: String,
    recipient_id: String,
    peer_id: String,
    peer_name: String,
    peer_addr: String,
    peer_fp: String,
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
    Failed(Status),
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
    pub introduced_by: Option<String>,
    #[allow(dead_code)]
    pub self_device: bool,
}

/// 等待用户确认的配对请求。
#[derive(Clone, Debug)]
pub struct PendingPair {
    pub addr: String,
    pub name: String,
}

/// 发送到 UI 线程的事件。
#[derive(Clone, Debug)]
pub enum UiPairEvent {
    Code {
        peer_name: String,
        peer_addr: String,
        code: String,
    },
    Devices(Vec<DeviceRow>),
    Done {
        peer_name: String,
        code: String,
    },
    Failed(Status),
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
            introduced_by: device.introduced_by.clone(),
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

fn refresh_paired_peer(config: &mut Config, id: &str, name: &str, fp: &str, addr: &str) -> bool {
    let Some(peer) = config.paired.iter_mut().find(|peer| peer.id == id) else {
        return false;
    };
    let changed = peer.addr != addr || peer.name != name || peer.fp != fp;
    if changed {
        peer.addr = addr.to_owned();
        peer.name = name.to_owned();
        peer.fp = fp.to_owned();
    }
    changed
}

fn prune_discovered_devices(devices: &mut HashMap<String, DiscoveredDevice>) {
    while devices.len() > MAX_DISCOVERED_DEVICES {
        let Some(oldest) = devices
            .iter()
            .min_by_key(|(_, device)| device.last_seen)
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        devices.remove(&oldest);
    }
}

fn admit_announcement(
    source: IpAddr,
    now: Instant,
    last_packet_by_source: &mut HashMap<IpAddr, Instant>,
) -> bool {
    let admitted = last_packet_by_source
        .get(&source)
        .is_none_or(|last| now.duration_since(*last) >= MIN_ANNOUNCEMENT_INTERVAL);
    if admitted {
        if !last_packet_by_source.contains_key(&source)
            && last_packet_by_source.len() >= MAX_DISCOVERY_SOURCES
        {
            if let Some(oldest) = last_packet_by_source
                .iter()
                .min_by_key(|(_, timestamp)| **timestamp)
                .map(|(source, _)| *source)
            {
                last_packet_by_source.remove(&oldest);
            }
        }
        last_packet_by_source.insert(source, now);
        last_packet_by_source.retain(|_, last| now.duration_since(*last) < DEVICE_TTL);
    }
    admitted
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
            // 广播只按固定周期发送。不能在每次收到公告后立即再次广播，否则两台
            // ClipBridge 会互相触发发送，形成 UDP 广播风暴；发送到 localhost 还会
            // 让本机收到自己的公告并在单机上进入 100% CPU 的自激循环。
            let broadcast_target = (std::net::Ipv4Addr::BROADCAST, DISCOVERY_PORT);
            let (introduction_status, _introduction_status_rx) = std::sync::mpsc::sync_channel(16);
            let mut last_introduction_sync = Instant::now() - INTRODUCTION_SYNC_INTERVAL;
            let mut next_advertise = Instant::now();
            let mut last_packet_by_source = HashMap::<IpAddr, Instant>::new();

            loop {
                let now = Instant::now();
                if now >= next_advertise {
                    if last_introduction_sync.elapsed() >= INTRODUCTION_SYNC_INTERVAL {
                        sync_introductions(Arc::clone(&shared_config), introduction_status.clone());
                        last_introduction_sync = Instant::now();
                    }
                    let announcement = {
                        let Ok(config) = shared_config.lock() else {
                            thread::sleep(Duration::from_millis(100));
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
                    let _ = sender_socket.send_to(&payload, broadcast_target);
                    next_advertise = Instant::now() + ADVERTISE_INTERVAL;
                }

                let wait = next_advertise.saturating_duration_since(Instant::now());
                socket
                    .set_read_timeout(Some(wait.max(Duration::from_millis(10))))
                    .expect("set_read_timeout");
                let mut buffer = [0u8; 1024];
                match socket.recv_from(&mut buffer) {
                    Ok((size, source)) => {
                        // A stale/old peer may still be broadcasting in a feedback loop. The
                        // protocol only needs one announcement per advertisement interval per source, so cap
                        // processing before deserializing the payload or taking config locks.
                        if !admit_announcement(
                            source.ip(),
                            Instant::now(),
                            &mut last_packet_by_source,
                        ) {
                            // Yield when draining a duplicate/flooded socket so a noisy peer
                            // cannot turn the receive loop back into a CPU spin.
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        if let Ok(announcement) =
                            postcard::from_bytes::<Announcement>(&buffer[..size])
                        {
                            if announcement.v != PROTO_VERSION {
                                continue;
                            }
                            let announced_addr =
                                format!("{}:{}", source.ip(), announcement.tcp_port);
                            let (self_id, paired_peer) = match shared_config.lock() {
                                Ok(mut config) => {
                                    let self_id = config.device_id.clone();
                                    let updated = refresh_paired_peer(
                                        &mut config,
                                        &announcement.id,
                                        &announcement.name,
                                        &announcement.fp,
                                        &announced_addr,
                                    );
                                    if updated {
                                        let _ = config::save(&config);
                                    }
                                    (self_id, config::paired_peer(&config, &announcement.id))
                                }
                                Err(_) => continue,
                            };
                            // Windows may loop a local broadcast back to the sender. Ignore it
                            // before touching the device cache; periodic sending above still
                            // keeps discovery available without a self-triggered feedback loop.
                            if announcement.id == self_id {
                                continue;
                            }
                            let paired = paired_peer.is_some();
                            let introduced_by = paired_peer.and_then(|peer| peer.introduced_by);
                            let mut devices = devices.lock().expect("devices mutex poisoned");
                            devices.insert(
                                announcement.id.clone(),
                                DiscoveredDevice {
                                    id: announcement.id,
                                    name: announcement.name,
                                    fp: announcement.fp,
                                    addr: announced_addr,
                                    paired,
                                    introduced_by,
                                    self_device: false,
                                    last_seen: Instant::now(),
                                },
                            );
                            prune_discovered_devices(&mut devices);
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) =>
                    {
                        // The timeout is the periodic advertisement deadline.
                    }
                    Err(_) => {
                        // A persistent socket error must not become a tight retry loop.
                        thread::sleep(Duration::from_millis(100));
                    }
                }

                let mut devices = devices.lock().expect("devices mutex poisoned");
                devices.retain(|_, device| device.last_seen.elapsed() < DEVICE_TTL);
            }
        })
        .expect("无法创建发现线程");
}

/// 发起配对：连接目标设备，发送 PairRequest，等待 PairAccept，确认码由 UI 展示核对；
/// 收到 accept 后立即用返回的会话密钥完成本端持久化。
#[derive(Clone, Debug)]
pub struct PairTarget {
    pub addr: String,
    pub id: String,
    pub fp: String,
}

#[derive(Clone, Debug)]
pub struct PairIdentity {
    pub name: String,
    pub fp: String,
    pub id: String,
    pub tcp_port: u16,
}

pub fn request_pair(
    target: PairTarget,
    local: PairIdentity,
    shared_config: Arc<Mutex<Config>>,
    events: PairTx,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("clipbridge-pair-out".to_owned())
        .spawn(move || {
            let result = pair_outbound(&target, &local, Arc::clone(&shared_config));
            match result {
                Ok(event) => {
                    let _ = events.send(event);
                }
                Err(error) => {
                    let _ = events.send(PairEvent::Failed(Status::PairingFailed { detail: error }));
                }
            }
        })
        .expect("无法创建配对线程")
}

fn pair_outbound(
    target: &PairTarget,
    local: &PairIdentity,
    shared_config: Arc<Mutex<Config>>,
) -> Result<PairEvent, String> {
    let mut stream = TcpStream::connect_timeout(
        &target
            .addr
            .parse()
            .map_err(|_| format!("无效地址: {}", target.addr))?,
        Duration::from_secs(4),
    )
    .map_err(|error| error.to_string())?;
    let _ = stream.set_read_timeout(Some(PAIR_CODE_WINDOW));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let request = PairRequest {
        v: PROTO_VERSION,
        id: local.id.clone(),
        name: local.name.clone(),
        fp: local.fp.clone(),
        tcp_port: local.tcp_port,
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
    if accept.id != target.id {
        return Err("配对设备身份不匹配".to_owned());
    }
    if accept.fp != target.fp {
        return Err("配对设备指纹不匹配".to_owned());
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
                addr: target.addr.clone(),
                fp: accept.fp.clone(),
                key_hex: key_hex.clone(),
                introduced_by: None,
            },
        );
        let _ = config::save(&config);
    }

    let peer_name = accept.name.clone();
    Ok(PairEvent::Done { peer_name, code })
}

struct PairingPermit;

impl Drop for PairingPermit {
    fn drop(&mut self) {
        PENDING_PAIRINGS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_pairing() -> Option<PairingPermit> {
    let mut current = PENDING_PAIRINGS.load(Ordering::Acquire);
    loop {
        if current >= MAX_PENDING_PAIRINGS {
            return None;
        }
        match PENDING_PAIRINGS.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(PairingPermit),
            Err(observed) => current = observed,
        }
    }
}

struct IntroductionSyncGuard;

impl Drop for IntroductionSyncGuard {
    fn drop(&mut self) {
        INTRODUCTION_SYNC_ACTIVE.store(false, Ordering::Release);
    }
}

/// 当本机拥有两个或以上直接配对设备时，把它们互相介绍给对方。
/// 介绍密钥由本机长期身份和两个设备 ID 稳定派生，重复运行不会更换密钥。
pub fn sync_introductions(shared_config: Arc<Mutex<Config>>, status: SyncSender<Status>) {
    if INTRODUCTION_SYNC_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let spawn_result = thread::Builder::new()
        .name("clipbridge-introductions".to_owned())
        .spawn(move || {
            let _active_guard = IntroductionSyncGuard;
            let Ok(config) = shared_config.lock().map(|config| config.clone()) else {
                return;
            };
            let direct: Vec<PairedPeer> = config
                .paired
                .iter()
                .filter(|peer| peer.introduced_by.is_none())
                .cloned()
                .collect();
            if direct.len() < 2 {
                return;
            }

            for left in 0..direct.len() {
                for right in (left + 1)..direct.len() {
                    let first = &direct[left];
                    let second = &direct[right];
                    let Ok(key) = config::introduction_key(&config, &first.id, &second.id) else {
                        continue;
                    };
                    let first_message = PeerIntroduction {
                        v: PROTO_VERSION,
                        introducer_id: config.device_id.clone(),
                        recipient_id: first.id.clone(),
                        peer_id: second.id.clone(),
                        peer_name: second.name.clone(),
                        peer_addr: second.addr.clone(),
                        peer_fp: second.fp.clone(),
                        key,
                    };
                    let second_message = PeerIntroduction {
                        v: PROTO_VERSION,
                        introducer_id: config.device_id.clone(),
                        recipient_id: second.id.clone(),
                        peer_id: first.id.clone(),
                        peer_name: first.name.clone(),
                        peer_addr: first.addr.clone(),
                        peer_fp: first.fp.clone(),
                        key,
                    };

                    if let Err(error) =
                        send_introduction(&first.addr, &first.key_hex, &first_message)
                    {
                        let _ = status.send(Status::IntroductionFailed {
                            detail: format!("{}: {error}", first.name),
                        });
                    }
                    if let Err(error) =
                        send_introduction(&second.addr, &second.key_hex, &second_message)
                    {
                        let _ = status.send(Status::IntroductionFailed {
                            detail: format!("{}: {error}", second.name),
                        });
                    }
                }
            }
        });
    if spawn_result.is_err() {
        INTRODUCTION_SYNC_ACTIVE.store(false, Ordering::Release);
    }
}

fn send_introduction(
    addr: &str,
    direct_key_hex: &str,
    introduction: &PeerIntroduction,
) -> Result<(), String> {
    let key = config::parse_key(direct_key_hex)?;
    let plaintext = postcard::to_allocvec(introduction).map_err(|error| error.to_string())?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            chacha20poly1305::Nonce::from_slice(&nonce),
            plaintext.as_ref(),
        )
        .map_err(|_| "加密自动配对介绍失败".to_owned())?;
    let frame_len = nonce.len() + ciphertext.len();
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|_| format!("无效地址: {addr}"))?,
        Duration::from_secs(4),
    )
    .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(INTRODUCTION_TAG)
        .and_then(|_| stream.write_all(&(frame_len as u64).to_le_bytes()))
        .and_then(|_| stream.write_all(&nonce))
        .and_then(|_| stream.write_all(&ciphertext))
        .map_err(|error| error.to_string())
}

fn apply_introduction(
    config: &mut Config,
    introduction: PeerIntroduction,
    introducer_id: &str,
) -> Result<Option<String>, String> {
    if introduction.recipient_id != config.device_id {
        return Err("自动配对介绍的接收设备不匹配".to_owned());
    }
    if introduction.peer_id == config.device_id {
        return Err("自动配对介绍指向本机".to_owned());
    }

    let key_hex: String = introduction
        .key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let peer_name = introduction.peer_name.clone();
    let peer = PairedPeer {
        id: introduction.peer_id,
        name: peer_name.clone(),
        addr: introduction.peer_addr,
        fp: introduction.peer_fp,
        key_hex,
        introduced_by: Some(introducer_id.to_owned()),
    };
    if config::upsert_introduced(config, peer, introducer_id) {
        Ok(Some(peer_name))
    } else {
        Ok(None)
    }
}

/// 处理已配对设备发来的自动介绍帧。
pub fn handle_introduction_conn(
    mut stream: TcpStream,
    shared_config: Arc<Mutex<Config>>,
    status: SyncSender<Status>,
) -> Result<(), String> {
    let mut len_bytes = [0u8; 8];
    stream
        .read_exact(&mut len_bytes)
        .map_err(|error| error.to_string())?;
    let frame_len = u64::from_le_bytes(len_bytes) as usize;
    if !(12..=1024 * 1024).contains(&frame_len) {
        return Err("自动配对介绍帧大小无效".to_owned());
    }
    let mut frame = vec![0u8; frame_len];
    stream
        .read_exact(&mut frame)
        .map_err(|error| error.to_string())?;

    let candidates = {
        let config = shared_config
            .lock()
            .map_err(|_| "配置锁不可用".to_owned())?;
        config
            .paired
            .iter()
            .filter(|peer| peer.introduced_by.is_none())
            .filter_map(|peer| {
                config::parse_key(&peer.key_hex)
                    .ok()
                    .map(|key| (peer.id.clone(), key))
            })
            .collect::<Vec<_>>()
    };

    let mut introduction = None;
    let mut introducer_id = None;
    for (candidate_id, key) in candidates {
        let cipher =
            chacha20poly1305::ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key));
        let Ok(plaintext) = cipher.decrypt(
            chacha20poly1305::Nonce::from_slice(&frame[..12]),
            &frame[12..],
        ) else {
            continue;
        };
        let Ok(candidate) = postcard::from_bytes::<PeerIntroduction>(&plaintext) else {
            continue;
        };
        if candidate.v == PROTO_VERSION && candidate.introducer_id == candidate_id {
            introduction = Some(candidate);
            introducer_id = Some(candidate_id);
            break;
        }
    }

    let introduction = introduction.ok_or_else(|| "自动配对介绍认证失败".to_owned())?;
    let introducer_id = introducer_id.expect("introducer exists with introduction");
    let mut config = shared_config
        .lock()
        .map_err(|_| "配置锁不可用".to_owned())?;
    if let Some(peer_name) = apply_introduction(&mut config, introduction, &introducer_id)? {
        config::save(&config).map_err(|error| error.to_string())?;
        let _ = status.send(Status::AutoPaired {
            via: introducer_id,
            peer: peer_name,
        });
    }
    Ok(())
}

pub fn code_source(fp_a: &str, nonce_a: &[u8; 16], fp_b: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(fp_a.as_bytes());
    hasher.update(nonce_a);
    hasher.update(fp_b.as_bytes());
    hasher.finalize().to_vec()
}

/// 处理一个入站配对连接（由 network::server_loop 在收到 CBPR 标签后调用；
/// 标签已被读取，直接从长度字段开始）。
pub fn handle_pair_conn(
    stream: TcpStream,
    shared_config: Arc<Mutex<Config>>,
    events: PairTx,
) -> Result<(), String> {
    handle_pair_inbound_inner(stream, shared_config, events)
}

fn handle_pair_inbound_inner(
    mut stream: TcpStream,
    shared_config: Arc<Mutex<Config>>,
    events: PairTx,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(PAIR_CODE_WINDOW));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

    // network::receive_one 已读取 4 字节标签（CBPR）；这里继续读长度和载荷。
    let body = read_payload(&mut stream)?;

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

    let Some(_pairing_permit) = try_acquire_pairing() else {
        let _ = write_frame(&mut stream, b"CBPN", b"busy");
        return Err("配对请求数量已达到上限".to_owned());
    };

    // 计算双方都能推导出的确认码。
    let code = pairing_code(&code_source(&my_fp, &request.nonce, &request.fp));
    let peer_addr = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_default();

    // 先注册等待通道，再通知 UI，避免用户快速点击时发生事件竞态。
    let confirmation = shared_confirm_registry().map(|registry| {
        let (key, receiver) = register_user_confirmation(&registry, &request.id, &peer_addr);
        (registry, key, receiver)
    });
    let _ = events.send(PairEvent::Code {
        peer_addr: peer_addr.clone(),
        peer_name: request.name.clone(),
        code: code.clone(),
    });

    // 阻塞等待用户在 UI 确认（共享注册表在 main 启动时初始化）。
    let accepted = confirmation
        .as_ref()
        .map(|(_, _, receiver)| receiver.recv_timeout(PAIR_CODE_WINDOW).unwrap_or(false))
        .unwrap_or(false);
    if let Some((registry, key, _)) = confirmation {
        remove_user_confirmation(&registry, &key);
    }
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
    let peer_port = if request.tcp_port == 0 {
        PAIR_PORT
    } else {
        request.tcp_port
    };
    let mut config = shared_config
        .lock()
        .map_err(|_| "配置锁不可用".to_owned())?;
    config::upsert_paired(
        &mut config,
        PairedPeer {
            id: request.id.clone(),
            name: request.name.clone(),
            addr: format!("{peer_addr_text}:{peer_port}"),
            fp: request.fp.clone(),
            key_hex: key_hex.clone(),
            introduced_by: None,
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
pub struct PendingConfirmation {
    addr: String,
    tx: Sender<bool>,
}

pub type ConfirmRegistry = Arc<Mutex<HashMap<String, PendingConfirmation>>>;

static CONFIRM_REGISTRY: std::sync::OnceLock<ConfirmRegistry> = std::sync::OnceLock::new();

/// 进程级单例；main 在启动时调用一次。
pub fn init_confirm_registry() -> ConfirmRegistry {
    CONFIRM_REGISTRY
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn shared_confirm_registry() -> Option<ConfirmRegistry> {
    CONFIRM_REGISTRY.get().cloned()
}

fn confirmation_key(peer_id: &str, addr: &str) -> String {
    format!("{peer_id}\n{addr}")
}

fn register_user_confirmation(
    registry: &ConfirmRegistry,
    peer_id: &str,
    addr: &str,
) -> (String, std::sync::mpsc::Receiver<bool>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let key = confirmation_key(peer_id, addr);
    if let Ok(mut reg) = registry.lock() {
        reg.insert(
            key.clone(),
            PendingConfirmation {
                addr: addr.to_owned(),
                tx,
            },
        );
    }
    (key, rx)
}

fn remove_user_confirmation(registry: &ConfirmRegistry, key: &str) {
    if let Ok(mut reg) = registry.lock() {
        reg.remove(key);
    }
}

/// UI 线程调用：用户点击接受或拒绝，只处理当前展示地址对应的请求。
pub fn resolve_confirmation_by_addr(
    registry: &ConfirmRegistry,
    addr: &str,
    accepted: bool,
) -> usize {
    let Ok(mut reg) = registry.lock() else {
        return 0;
    };
    let keys: Vec<String> = reg
        .iter()
        .filter(|(_, pending)| pending.addr == addr)
        .map(|(key, _)| key.clone())
        .collect();
    let mut resolved = 0;
    for key in keys {
        if let Some(pending) = reg.remove(&key) {
            let _ = pending.tx.send(accepted);
            resolved += 1;
        }
    }
    resolved
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

#[allow(dead_code)]
fn read_frame(stream: &mut TcpStream) -> Result<([u8; 4], Vec<u8>), String> {
    let mut tag = [0u8; 4];
    stream
        .read_exact(&mut tag)
        .map_err(|error| error.to_string())?;
    let body = read_payload(stream)?;
    Ok((tag, body))
}

/// 读取帧载荷（4 字节长度 + body）。标签由调用方按需读取或已读取。
fn read_payload(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
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
    Ok(body)
}

/// 供测试与调试使用的已发现设备快照。
#[allow(dead_code)]
pub fn snapshot(devices: &DeviceMap) -> Vec<DiscoveredDevice> {
    let devices = devices.lock().expect("devices mutex poisoned");
    let mut list: Vec<DiscoveredDevice> = devices.values().cloned().collect();
    list.sort_by(|a, b| a.name.cmp(&b.name));
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_decision_reaches_waiting_pair() {
        let registry: ConfirmRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (_, receiver) = register_user_confirmation(&registry, "peer-1", "192.0.2.1:45821");

        assert_eq!(
            resolve_confirmation_by_addr(&registry, "192.0.2.1:45821", true),
            1
        );
        assert_eq!(receiver.recv_timeout(Duration::from_millis(50)), Ok(true));
    }

    #[test]
    fn confirmation_decision_does_not_resolve_another_address() {
        let registry: ConfirmRegistry = Arc::new(Mutex::new(HashMap::new()));
        let (_, first) = register_user_confirmation(&registry, "peer-1", "192.0.2.1:45821");
        let (_, second) = register_user_confirmation(&registry, "peer-2", "192.0.2.2:45821");

        assert_eq!(
            resolve_confirmation_by_addr(&registry, "192.0.2.1:45821", true),
            1
        );
        assert_eq!(first.recv_timeout(Duration::from_millis(50)), Ok(true));
        assert!(second.try_recv().is_err());
    }

    #[test]
    fn announcement_rate_limit_drops_floods_but_allows_periodic_packets() {
        let source = "192.0.2.10".parse().expect("valid source address");
        let first = Instant::now();
        let mut last = HashMap::new();
        assert!(admit_announcement(source, first, &mut last));
        assert!(!admit_announcement(
            source,
            first + Duration::from_millis(500),
            &mut last
        ));
        assert!(admit_announcement(
            source,
            first + MIN_ANNOUNCEMENT_INTERVAL,
            &mut last
        ));
    }

    #[test]
    fn paired_peer_address_refreshes_after_discovery_announcement() {
        let mut config = Config::default();
        config.paired.push(PairedPeer {
            id: "peer".to_owned(),
            name: "Old name".to_owned(),
            addr: "192.0.2.10:45821".to_owned(),
            fp: "old-fp".to_owned(),
            key_hex: config::random_hex(32),
            introduced_by: None,
        });
        assert!(refresh_paired_peer(
            &mut config,
            "peer",
            "New name",
            "new-fp",
            "192.0.2.20:49000"
        ));
        assert_eq!(config.paired[0].addr, "192.0.2.20:49000");
        assert_eq!(config.paired[0].name, "New name");
        assert!(!refresh_paired_peer(
            &mut config,
            "peer",
            "New name",
            "new-fp",
            "192.0.2.20:49000"
        ));
    }

    #[test]
    fn announcement_source_cache_has_a_hard_bound() {
        let first = Instant::now();
        let mut last = HashMap::new();
        for index in 0..(MAX_DISCOVERY_SOURCES + 32) {
            let source = IpAddr::V4(std::net::Ipv4Addr::new(
                198,
                51,
                100,
                (index % 250 + 1) as u8,
            ));
            let _ = admit_announcement(source, first, &mut last);
        }
        assert!(last.len() <= MAX_DISCOVERY_SOURCES);
    }

    #[test]
    fn pending_pairing_limit_is_bounded() {
        let first = try_acquire_pairing().expect("first pairing permit");
        let second = try_acquire_pairing().expect("second pairing permit");
        assert!(try_acquire_pairing().is_none());
        drop(second);
        drop(first);
        assert!(try_acquire_pairing().is_some());
    }

    #[test]
    fn introduction_adds_peer_with_introducer_marker() {
        let mut config = Config {
            device_id: "device-b".to_owned(),
            ..Config::default()
        };
        let direct_key = config::random_hex(32);
        config.paired.push(PairedPeer {
            id: "device-a".to_owned(),
            name: "A".to_owned(),
            addr: "127.0.0.1:45821".to_owned(),
            fp: "a".to_owned(),
            key_hex: direct_key,
            introduced_by: None,
        });
        let introduction = PeerIntroduction {
            v: PROTO_VERSION,
            introducer_id: "device-a".to_owned(),
            recipient_id: "device-b".to_owned(),
            peer_id: "device-c".to_owned(),
            peer_name: "C".to_owned(),
            peer_addr: "127.0.0.1:45822".to_owned(),
            peer_fp: "c".to_owned(),
            key: [7u8; 32],
        };

        let result = apply_introduction(&mut config, introduction, "device-a")
            .expect("introduction should validate");
        assert_eq!(result.as_deref(), Some("C"));
        assert_eq!(config.paired.len(), 2);
        assert_eq!(config.paired[1].introduced_by.as_deref(), Some("device-a"));
    }
}
