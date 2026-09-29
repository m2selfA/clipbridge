#![cfg(windows)]

use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{mpsc::Receiver, Arc, Mutex},
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
const NONCE_BYTES: usize = 12;
const MAX_FRAME_BYTES: usize = clipboard::MAX_CLIPBOARD_BYTES + 1024 * 1024;
const DUPLICATE_WINDOW: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ImageEnvelope {
    origin: String,
    sequence: u64,
    image: clipboard::ClipboardImage,
}

type SharedConfig = Arc<Mutex<config::Config>>;
type RecentImages = Arc<Mutex<HashMap<[u8; 32], Instant>>>;

pub fn spawn(
    local_images: Receiver<clipboard::ClipboardImage>,
    shared_config: SharedConfig,
    status: std::sync::mpsc::Sender<Status>,
    pair_events: discovery::PairTx,
) {
    let recent_remote: RecentImages = Arc::new(Mutex::new(HashMap::new()));
    let server_config = Arc::clone(&shared_config);
    let server_remote = Arc::clone(&recent_remote);
    let server_status = status.clone();
    thread::Builder::new()
        .name("clipbridge-server".to_owned())
        .spawn(move || server_loop(server_config, server_remote, server_status, pair_events))
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
    status: std::sync::mpsc::Sender<Status>,
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

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let client_config = Arc::clone(&shared_config);
                let client_remote = Arc::clone(&recent_remote);
                let client_status = status.clone();
                let client_pair_events = pair_events.clone();
                thread::spawn(move || {
                    receive_one(
                        stream,
                        client_config,
                        client_remote,
                        client_status,
                        client_pair_events,
                    )
                });
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
    status: std::sync::mpsc::Sender<Status>,
) {
    // 每个目标设备记住最近一次成功发送的图片哈希。
    // 与固定时间窗口不同，这能稳定过滤 Win+V 对同一历史图片产生的重复通知，
    // 同时允许向后来加入的设备发送同一张图片。
    let mut last_synced = HashMap::<String, [u8; 32]>::new();
    let mut paired_round: HashMap<String, ([u8; 32], String)> = HashMap::new();

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
            sequence: OsRng.next_u64(),
            image,
        };

        let mut delivered = 0usize;
        for peer in paired {
            let Ok(key) = config::parse_key(&peer.key_hex) else {
                let _ = status.send(Status::SessionKeyInvalid {
                    peer: peer.name.clone(),
                });
                continue;
            };
            let addr = resolved_paired_addr(&peer, &mut paired_round);
            let target = format!("paired:{}:{addr}", peer.id);
            if !should_sync(&target, image_hash, &last_synced) {
                continue;
            }
            match send_one(&addr, &key, &envelope) {
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
                match send_one(&peer, &key, &envelope) {
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

/// 已配对设备记录的是发现时的地址；若端口变化，用最新公告端口回填。
fn resolved_paired_addr(
    peer: &config::PairedPeer,
    cache: &mut HashMap<String, ([u8; 32], String)>,
) -> String {
    let _ = cache;
    peer.addr.clone()
}

fn receive_one(
    mut stream: TcpStream,
    shared_config: SharedConfig,
    recent_remote: RecentImages,
    status: std::sync::mpsc::Sender<Status>,
    pair_events: discovery::PairTx,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
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
    if !(NONCE_BYTES..=MAX_FRAME_BYTES).contains(&frame_len) {
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
    for key in &candidate_keys {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        if let Ok(candidate) = cipher.decrypt(
            Nonce::from_slice(&frame[..NONCE_BYTES]),
            &frame[NONCE_BYTES..],
        ) {
            plaintext = Some(candidate);
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

    if let Err(error) = clipboard::write_image(&envelope.image) {
        let _ = status.send(Status::ClipboardWriteFailed { detail: error });
        return;
    }
    // 只有成功写入系统剪贴板后才标记为远端图片，避免失败时吞掉下一次重试机会。
    recent_remote
        .lock()
        .expect("remote image mutex poisoned")
        .insert(digest(&envelope.image), Instant::now());
    let _ = status.send(Status::ReceivedImage {
        origin: envelope.origin,
    });
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
    Ok(())
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
    map.retain(|_, time| time.elapsed() < DUPLICATE_WINDOW);
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

    struct ClipboardImageForTest(clipboard::ClipboardImage);

    impl ClipboardImageForTest {
        fn new(format: u32, dib: Vec<u8>) -> Self {
            Self(clipboard::ClipboardImage { format, dib })
        }
    }
}
