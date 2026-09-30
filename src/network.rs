#![cfg(windows)]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{clipboard, config, discovery, status::Status};

const MAGIC: &[u8; 4] = b"CB01";
const ACK_MAGIC: &[u8; 4] = b"CBOK";
const NONCE_BYTES: usize = 12;
const MAX_FRAME_BYTES: usize = clipboard::MAX_CLIPBOARD_BYTES + 1024 * 1024;
const MAX_INBOUND_CONNECTIONS: usize = 8;
const MAX_RECENT_REMOTE_IMAGES: usize = 256;
const MAX_REPLAY_ENTRIES: usize = 4096;
const DUPLICATE_WINDOW: Duration = Duration::from_secs(5);
const REPLAY_WINDOW: Duration = Duration::from_secs(15 * 60);
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ImageEnvelope {
    origin: String,
    sequence: u64,
    image: clipboard::ClipboardImage,
    /// Random sender-process epoch; sequence ordering is enforced only within one epoch.
    #[serde(default)]
    session: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DeliveryAck {
    sequence: u64,
    accepted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayState {
    InFlight,
    Accepted,
}

type SharedConfig = Arc<Mutex<config::Config>>;
type RecentImages = Arc<Mutex<HashMap<[u8; 32], Instant>>>;
type ReplayId = ([u8; 32], u64, u64);
type ReplayEpoch = ([u8; 32], u64);

#[derive(Default)]
struct ReplayCacheState {
    entries: HashMap<ReplayId, (ReplayState, Instant)>,
    last_accepted: HashMap<ReplayEpoch, u64>,
}

type ReplayCache = Arc<Mutex<ReplayCacheState>>;

struct ConnectionPermit(Arc<AtomicUsize>);

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_connection(limiter: &Arc<AtomicUsize>) -> Option<ConnectionPermit> {
    let mut current = limiter.load(Ordering::Acquire);
    loop {
        if current >= MAX_INBOUND_CONNECTIONS {
            return None;
        }
        match limiter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(ConnectionPermit(Arc::clone(limiter))),
            Err(observed) => current = observed,
        }
    }
}

pub fn spawn(
    local_images: Receiver<clipboard::ClipboardImage>,
    shared_config: SharedConfig,
    status: SyncSender<Status>,
    pair_events: discovery::PairTx,
) {
    let recent_remote: RecentImages = Arc::new(Mutex::new(HashMap::new()));
    let replay_cache: ReplayCache = Arc::new(Mutex::new(ReplayCacheState::default()));
    let server_config = Arc::clone(&shared_config);
    let server_remote = Arc::clone(&recent_remote);
    let server_replay = Arc::clone(&replay_cache);
    let server_status = status.clone();
    thread::Builder::new()
        .name("clipbridge-server".to_owned())
        .spawn(move || {
            server_loop(
                server_config,
                server_remote,
                server_replay,
                server_status,
                pair_events,
            )
        })
        .expect("无法创建剪贴板同步服务线程");

    let sender_config = Arc::clone(&shared_config);
    let sender_status = status;
    thread::Builder::new()
        .name("clipbridge-sender".to_owned())
        .spawn(move || sender_loop(local_images, sender_config, recent_remote, sender_status))
        .expect("无法创建剪贴板发送线程");
}

fn server_loop(
    shared_config: SharedConfig,
    recent_remote: RecentImages,
    replay_cache: ReplayCache,
    status: SyncSender<Status>,
    pair_events: discovery::PairTx,
) {
    let bind_addr = shared_config
        .lock()
        .map(|config| config.bind_addr.clone())
        .unwrap_or_else(|_| "0.0.0.0:45821".to_owned());
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = status.send(Status::ListenFailed {
                addr: bind_addr.clone(),
                detail: error.to_string(),
            });
            return;
        }
    };
    let _ = status.send(Status::Listening {
        addr: bind_addr.clone(),
    });
    let connection_limiter = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let Some(permit) = try_acquire_connection(&connection_limiter) else {
                    // Drop excess connections immediately instead of allowing a LAN peer
                    // to create unbounded threads or memory allocations.
                    continue;
                };
                let client_config = Arc::clone(&shared_config);
                let client_remote = Arc::clone(&recent_remote);
                let client_replay = Arc::clone(&replay_cache);
                let client_status = status.clone();
                let client_pair_events = pair_events.clone();
                thread::Builder::new()
                    .name("clipbridge-connection".to_owned())
                    .spawn(move || {
                        let _permit = permit;
                        receive_one(
                            stream,
                            client_config,
                            client_remote,
                            client_replay,
                            client_status,
                            client_pair_events,
                        )
                    })
                    .ok();
            }
            Err(error) => {
                let _ = status.send(Status::AcceptFailed {
                    detail: error.to_string(),
                });
            }
        }
    }
}

fn sender_loop(
    local_images: Receiver<clipboard::ClipboardImage>,
    shared_config: SharedConfig,
    recent_remote: RecentImages,
    status: SyncSender<Status>,
) {
    // 每个目标设备记住最近一次成功发送的图片哈希。
    // 与固定时间窗口不同，这能稳定过滤 Win+V 对同一历史图片产生的重复通知，
    // 同时允许向后来加入的设备发送同一张图片。
    let mut last_synced = HashMap::<String, [u8; 32]>::new();
    let session = OsRng.next_u64();
    let mut next_sequence = 0u64;

    while let Ok(image) = local_images.recv() {
        let image_hash = digest(&image);
        let is_remote = {
            let mut remote = recent_remote.lock().expect("remote image mutex poisoned");
            prune_recent(&mut remote);
            remote.remove(&image_hash).is_some()
        };

        if is_remote {
            continue;
        }

        let (manual_peers, manual_key_hex, origin, paired) = match shared_config.lock() {
            Ok(config) => (
                config.peers.clone(),
                config.key_hex.clone(),
                config.device_id.clone(),
                config.paired.clone(),
            ),
            Err(_) => continue,
        };
        let manual_key = match config::parse_key(&manual_key_hex) {
            Ok(key) => Some(key),
            Err(error) => {
                let _ = status.send(Status::SharedKeyInvalid { detail: error });
                None
            }
        };
        let envelope = ImageEnvelope {
            origin,
            sequence: next_sequence,
            image,
            session,
        };
        next_sequence = next_sequence.wrapping_add(1);

        let mut delivered = 0usize;
        for peer in paired {
            let Ok(key) = config::parse_key(&peer.key_hex) else {
                let _ = status.send(Status::SessionKeyInvalid {
                    peer: peer.name.clone(),
                });
                continue;
            };
            let addr = peer.addr.clone();
            let target = format!("paired:{}:{addr}", peer.id);
            if !should_sync(&target, image_hash, &last_synced) {
                continue;
            }
            match send_one_with_retry(&addr, &key, &envelope) {
                Ok(()) => {
                    delivered += 1;
                    last_synced.insert(target, image_hash);
                }
                Err(error) => {
                    let _ = status.send(Status::SendFailed {
                        peer: peer.name.clone(),
                        detail: error,
                    });
                }
            }
        }
        if let Some(key) = manual_key {
            for peer in manual_peers {
                let target = format!("manual:{peer}");
                if !should_sync(&target, image_hash, &last_synced) {
                    continue;
                }
                match send_one_with_retry(&peer, &key, &envelope) {
                    Ok(()) => {
                        delivered += 1;
                        last_synced.insert(target, image_hash);
                    }
                    Err(error) => {
                        let _ = status.send(Status::SendFailed {
                            peer: peer.clone(),
                            detail: error,
                        });
                    }
                }
            }
        }
        if delivered > 0 {
            let _ = status.send(Status::SyncComplete { count: delivered });
        }
    }
}

fn receive_one(
    mut stream: TcpStream,
    shared_config: SharedConfig,
    recent_remote: RecentImages,
    replay_cache: ReplayCache,
    status: SyncSender<Status>,
    pair_events: discovery::PairTx,
) {
    let _ = configure_receive_timeouts(&stream);
    let mut magic = [0u8; 4];
    if stream.read_exact(&mut magic).is_err() {
        return;
    }

    // 同端口协议复用：CB01 = 剪贴板数据；CBPR = 配对请求，交给 discovery 模块处理。
    // 注意：handle_pair_conn 约定标签已被读取，直接从 4 字节长度字段开始。
    if &magic == discovery::PAIR_REQUEST_TAG {
        let _ = status.send(Status::PairRequestWaiting);
        let _ = stream.set_read_timeout(Some(discovery::PAIR_CODE_WINDOW));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
        if let Err(error) = discovery::handle_pair_conn(stream, shared_config, pair_events) {
            eprintln!("配对处理失败: {error}");
        }
        return;
    }
    if &magic == discovery::INTRODUCTION_TAG {
        if let Err(error) =
            discovery::handle_introduction_conn(stream, shared_config, status.clone())
        {
            let _ = status.send(Status::IntroductionFailed { detail: error });
        }
        return;
    }
    if &magic != MAGIC {
        return;
    }

    let mut len_bytes = [0u8; 8];
    if stream.read_exact(&mut len_bytes).is_err() {
        return;
    }
    let frame_len = u64::from_le_bytes(len_bytes) as usize;
    if !valid_frame_len(frame_len) {
        let _ = status.send(Status::FrameInvalid);
        return;
    }

    let mut frame = vec![0u8; frame_len];
    if stream.read_exact(&mut frame).is_err() {
        return;
    }

    let candidate_keys = {
        let config = match shared_config.lock() {
            Ok(config) => config,
            Err(_) => return,
        };
        // 发送方如果是已配对设备，使用该设备的会话密钥；否则回退到手动模式的全局密钥。
        // 由于尚未解密前无法知道发送者，先尝试 paired 密钥，失败后回退全局密钥。
        let mut candidate_keys = Vec::<[u8; 32]>::new();
        for peer in &config.paired {
            if let Ok(key) = config::parse_key(&peer.key_hex) {
                candidate_keys.push(key);
            }
        }
        if let Ok(global) = config::parse_key(&config.key_hex) {
            candidate_keys.push(global);
        }
        candidate_keys
    };
    let mut plaintext = None;
    let mut matched_key = None;
    for key in &candidate_keys {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        if let Ok(candidate) = cipher.decrypt(
            Nonce::from_slice(&frame[..NONCE_BYTES]),
            &frame[NONCE_BYTES..],
        ) {
            plaintext = Some(candidate);
            matched_key = Some(*key);
            break;
        }
    }
    let Some(plaintext) = plaintext else {
        let _ = status.send(Status::AuthenticationFailed);
        return;
    };
    let envelope: ImageEnvelope = match postcard::from_bytes(&plaintext) {
        Ok(envelope) => envelope,
        Err(_) => return,
    };
    if envelope.image.dib.len() > clipboard::MAX_CLIPBOARD_BYTES {
        return;
    }
    let Some(matched_key) = matched_key else {
        return;
    };
    let replay_id = (matched_key, envelope.session, envelope.sequence);
    match replay_begin(&replay_cache, replay_id) {
        ReplayDecision::Accepted => {
            let _ = send_ack(&mut stream, &matched_key, envelope.sequence, true);
            return;
        }
        ReplayDecision::InFlight => return,
        ReplayDecision::Stale => {
            let _ = send_ack(&mut stream, &matched_key, envelope.sequence, false);
            return;
        }
        ReplayDecision::New => {}
    }

    if let Err(error) = clipboard::write_image(&envelope.image) {
        replay_finish(&replay_cache, replay_id, false);
        let _ = send_ack(&mut stream, &matched_key, envelope.sequence, false);
        let _ = status.send(Status::ClipboardWriteFailed { detail: error });
        return;
    }
    // 只有成功写入系统剪贴板后才标记为远端图片，避免失败时吞掉下一次重试机会。
    replay_finish(&replay_cache, replay_id, true);
    {
        let mut recent = recent_remote.lock().expect("remote image mutex poisoned");
        prune_recent(&mut recent);
        recent.insert(digest(&envelope.image), Instant::now());
        prune_recent(&mut recent);
    }
    let _ = send_ack(&mut stream, &matched_key, envelope.sequence, true);
    let _ = status.send(Status::ReceivedImage {
        origin: envelope.origin,
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayDecision {
    New,
    InFlight,
    Accepted,
    Stale,
}

fn replay_begin(cache: &ReplayCache, id: ReplayId) -> ReplayDecision {
    let mut cache = cache.lock().expect("replay cache mutex poisoned");
    prune_replay(&mut cache);
    if let Some((state, _)) = cache.entries.get(&id) {
        return match state {
            ReplayState::InFlight => ReplayDecision::InFlight,
            ReplayState::Accepted => ReplayDecision::Accepted,
        };
    }
    let epoch = (id.0, id.1);
    if cache
        .last_accepted
        .get(&epoch)
        .is_some_and(|last| id.2 <= *last)
    {
        return ReplayDecision::Stale;
    }
    cache
        .entries
        .insert(id, (ReplayState::InFlight, Instant::now()));
    ReplayDecision::New
}

fn replay_finish(cache: &ReplayCache, id: ReplayId, accepted: bool) {
    let mut cache = cache.lock().expect("replay cache mutex poisoned");
    if accepted {
        cache
            .entries
            .insert(id, (ReplayState::Accepted, Instant::now()));
        cache.last_accepted.insert((id.0, id.1), id.2);
    } else {
        cache.entries.remove(&id);
    }
    prune_replay(&mut cache);
}

fn prune_replay(cache: &mut ReplayCacheState) {
    let now = Instant::now();
    cache
        .entries
        .retain(|_, (_, timestamp)| now.duration_since(*timestamp) < REPLAY_WINDOW);
    while cache.entries.len() > MAX_REPLAY_ENTRIES {
        let Some(oldest) = cache
            .entries
            .iter()
            .min_by_key(|(_, (_, timestamp))| *timestamp)
            .map(|(id, _)| *id)
        else {
            break;
        };
        cache.entries.remove(&oldest);
    }
    while cache.last_accepted.len() > MAX_REPLAY_ENTRIES {
        let Some(oldest_epoch) = cache.last_accepted.keys().next().copied() else {
            break;
        };
        cache.last_accepted.remove(&oldest_epoch);
    }
}

fn configure_receive_timeouts(stream: &TcpStream) -> Result<(), String> {
    configure_stream_timeouts(stream, Duration::from_secs(10), ACK_TIMEOUT)
}

fn configure_stream_timeouts(
    stream: &TcpStream,
    read_timeout: Duration,
    write_timeout: Duration,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(read_timeout))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(write_timeout))
        .map_err(|error| error.to_string())
}

fn valid_frame_len(frame_len: usize) -> bool {
    (NONCE_BYTES..=MAX_FRAME_BYTES).contains(&frame_len)
}

fn send_ack(
    stream: &mut TcpStream,
    key: &[u8; 32],
    sequence: u64,
    accepted: bool,
) -> Result<(), String> {
    let payload = postcard::to_allocvec(&DeliveryAck { sequence, accepted })
        .map_err(|error| error.to_string())?;
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
        .map_err(|_| "加密传输确认失败".to_owned())?;
    let frame_len = nonce.len() + ciphertext.len();
    stream
        .write_all(ACK_MAGIC)
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&(frame_len as u32).to_le_bytes())
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&nonce)
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&ciphertext)
        .map_err(|error| error.to_string())
}

fn read_ack(stream: &mut TcpStream, key: &[u8; 32], sequence: u64) -> Result<(), String> {
    stream
        .set_read_timeout(Some(ACK_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let mut magic = [0u8; 4];
    stream
        .read_exact(&mut magic)
        .map_err(|error| format!("未收到远端写入确认: {error}"))?;
    if &magic != ACK_MAGIC {
        return Err("远端返回了未知确认帧".to_owned());
    }
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .map_err(|error| error.to_string())?;
    let frame_len = u32::from_le_bytes(len_bytes) as usize;
    if !(NONCE_BYTES..=4096).contains(&frame_len) {
        return Err("远端确认帧大小无效".to_owned());
    }
    let mut frame = vec![0u8; frame_len];
    stream
        .read_exact(&mut frame)
        .map_err(|error| error.to_string())?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&frame[..NONCE_BYTES]),
            &frame[NONCE_BYTES..],
        )
        .map_err(|_| "远端确认帧认证失败".to_owned())?;
    let ack: DeliveryAck = postcard::from_bytes(&plaintext).map_err(|error| error.to_string())?;
    if ack.sequence != sequence {
        return Err("远端确认序列号不匹配".to_owned());
    }
    if !ack.accepted {
        return Err("远端写入剪贴板失败".to_owned());
    }
    Ok(())
}

fn send_one_with_retry(peer: &str, key: &[u8; 32], envelope: &ImageEnvelope) -> Result<(), String> {
    let mut last_error = None;
    for attempt in 0..2 {
        match send_one(peer, key, envelope) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt == 0 {
                    thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| "远端写入失败".to_owned()))
}

fn send_one(peer: &str, key: &[u8; 32], envelope: &ImageEnvelope) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(
        &peer.parse().map_err(|_| format!("无效地址: {peer}"))?,
        Duration::from_secs(3),
    )
    .map_err(|error| error.to_string())?;
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));

    let plaintext = postcard::to_allocvec(envelope).map_err(|error| error.to_string())?;
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|_| "加密剪贴板数据失败".to_owned())?;

    let frame_len = nonce_bytes.len() + ciphertext.len();
    if frame_len > MAX_FRAME_BYTES {
        return Err("剪贴板数据超过传输限制".to_owned());
    }
    stream.write_all(MAGIC).map_err(|error| error.to_string())?;
    stream
        .write_all(&(frame_len as u64).to_le_bytes())
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&nonce_bytes)
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&ciphertext)
        .map_err(|error| error.to_string())?;
    read_ack(&mut stream, key, envelope.sequence)
}

/// 图片内容哈希不包含剪贴板格式标签：Win+V 可能以不同 DIB 格式重新发布同一图片，
/// 但相同的 DIB 数据仍应被视为同一张图片。
fn should_sync(
    target: &str,
    image_hash: [u8; 32],
    last_synced: &HashMap<String, [u8; 32]>,
) -> bool {
    last_synced
        .get(target)
        .is_none_or(|previous| *previous != image_hash)
}

fn digest(image: &clipboard::ClipboardImage) -> [u8; 32] {
    Sha256::digest(&image.dib).into()
}

fn prune_recent(map: &mut HashMap<[u8; 32], Instant>) {
    let now = Instant::now();
    map.retain(|_, time| now.duration_since(*time) < DUPLICATE_WINDOW);
    while map.len() > MAX_RECENT_REMOTE_IMAGES {
        let Some(oldest) = map
            .iter()
            .min_by_key(|(_, timestamp)| **timestamp)
            .map(|(digest, _)| *digest)
        else {
            break;
        };
        map.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_dib_hash_ignores_clipboard_format() {
        let dib = vec![1, 2, 3, 4];
        let first = ClipboardImageForTest::new(clipboard::CF_DIB, dib.clone());
        let second = ClipboardImageForTest::new(clipboard::CF_DIBV5, dib);
        assert_eq!(digest(&first.0), digest(&second.0));
    }

    #[test]
    fn successful_hash_is_skipped_for_same_target() {
        let mut sent = HashMap::new();
        let hash = [9u8; 32];
        assert!(should_sync("paired:peer-a:127.0.0.1:45821", hash, &sent));
        sent.insert("paired:peer-a:127.0.0.1:45821".to_owned(), hash);
        assert!(!should_sync("paired:peer-a:127.0.0.1:45821", hash, &sent));
        assert!(should_sync("paired:peer-b:127.0.0.1:45821", hash, &sent));
    }

    #[test]
    fn oversized_and_truncated_frame_lengths_are_rejected() {
        assert!(!valid_frame_len(NONCE_BYTES - 1));
        assert!(valid_frame_len(NONCE_BYTES));
        assert!(valid_frame_len(MAX_FRAME_BYTES));
        assert!(!valid_frame_len(MAX_FRAME_BYTES + 1));
    }

    #[test]
    fn replay_cache_accepts_once_and_rejects_in_flight_duplicates() {
        let cache = Arc::new(Mutex::new(ReplayCacheState::default()));
        let id = ([3u8; 32], 7u64, 42u64);
        assert_eq!(replay_begin(&cache, id), ReplayDecision::New);
        assert_eq!(replay_begin(&cache, id), ReplayDecision::InFlight);
        replay_finish(&cache, id, true);
        assert_eq!(replay_begin(&cache, id), ReplayDecision::Accepted);
    }

    #[test]
    fn replay_cache_rejects_out_of_order_sequence_in_same_session() {
        let cache = Arc::new(Mutex::new(ReplayCacheState::default()));
        let key = [4u8; 32];
        let newer = (key, 9u64, 10u64);
        let older = (key, 9u64, 9u64);
        assert_eq!(replay_begin(&cache, newer), ReplayDecision::New);
        replay_finish(&cache, newer, true);
        assert_eq!(replay_begin(&cache, older), ReplayDecision::Stale);
    }

    #[test]
    fn receive_connection_timeout_is_configurable() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept timeout client");
            configure_stream_timeouts(
                &stream,
                Duration::from_millis(20),
                Duration::from_millis(20),
            )
            .expect("set short timeout");
            let mut byte = [0u8; 1];
            let error = stream
                .read_exact(&mut byte)
                .expect_err("read must time out");
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ));
        });
        let _client = TcpStream::connect(addr).expect("connect timeout server");
        server.join().expect("timeout server thread");
    }

    #[test]
    fn negative_delivery_ack_is_reported_to_sender() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");
        let key = [6u8; 32];
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept ack client");
            send_ack(&mut stream, &key, 77, false).expect("send negative encrypted ack");
        });
        let mut client = TcpStream::connect(addr).expect("connect ack server");
        assert!(read_ack(&mut client, &key, 77).is_err());
        server.join().expect("ack server thread");
    }

    #[test]
    fn connection_limiter_is_bounded() {
        let limiter = Arc::new(AtomicUsize::new(0));
        let mut permits = Vec::new();
        for _ in 0..MAX_INBOUND_CONNECTIONS {
            permits.push(try_acquire_connection(&limiter).expect("permit available"));
        }
        assert!(try_acquire_connection(&limiter).is_none());
        drop(permits.pop());
        assert!(try_acquire_connection(&limiter).is_some());
    }

    #[test]
    fn negative_ack_causes_sender_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind retry listener");
        let addr = listener.local_addr().expect("listener address");
        let key = [8u8; 32];
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept retry client");
                let mut magic = [0u8; 4];
                stream.read_exact(&mut magic).expect("read image magic");
                assert_eq!(&magic, MAGIC);
                let mut length = [0u8; 8];
                stream.read_exact(&mut length).expect("read image length");
                let frame_len = u64::from_le_bytes(length) as usize;
                assert!(valid_frame_len(frame_len));
                let mut frame = vec![0u8; frame_len];
                stream.read_exact(&mut frame).expect("read image frame");
                send_ack(&mut stream, &key, 0, false).expect("send retry NACK");
            }
        });
        let envelope = ImageEnvelope {
            origin: "test".to_owned(),
            sequence: 0,
            image: clipboard::ClipboardImage {
                format: clipboard::CF_DIB,
                dib: vec![1, 2, 3],
            },
            session: 1,
        };
        assert!(send_one_with_retry(&addr.to_string(), &key, &envelope).is_err());
        server.join().expect("retry server thread");
    }

    #[test]
    fn encrypted_delivery_ack_round_trips() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener address");
        let key = [5u8; 32];
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept ack client");
            send_ack(&mut stream, &key, 77, true).expect("send encrypted ack");
        });
        let mut client = TcpStream::connect(addr).expect("connect ack server");
        read_ack(&mut client, &key, 77).expect("read encrypted ack");
        server.join().expect("ack server thread");
    }

    struct ClipboardImageForTest(clipboard::ClipboardImage);

    impl ClipboardImageForTest {
        fn new(format: u32, dib: Vec<u8>) -> Self {
            Self(clipboard::ClipboardImage { format, dib })
        }
    }
}
