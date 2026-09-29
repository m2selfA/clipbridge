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

use crate::{clipboard, config};

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
    status: std::sync::mpsc::Sender<String>,
) {
    let recent_remote: RecentImages = Arc::new(Mutex::new(HashMap::new()));
    let server_config = Arc::clone(&shared_config);
    let server_remote = Arc::clone(&recent_remote);
    let server_status = status.clone();
    thread::Builder::new()
        .name("clipbridge-server".to_owned())
        .spawn(move || server_loop(server_config, server_remote, server_status))
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
    status: std::sync::mpsc::Sender<String>,
) {
    let bind_addr = shared_config
        .lock()
        .map(|config| config.bind_addr.clone())
        .unwrap_or_else(|_| "0.0.0.0:45821".to_owned());
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = status.send(format!("监听失败 {bind_addr}: {error}"));
            return;
        }
    };
    let _ = status.send(format!("监听 {bind_addr}"));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let client_config = Arc::clone(&shared_config);
                let client_remote = Arc::clone(&recent_remote);
                let client_status = status.clone();
                thread::spawn(move || {
                    receive_one(stream, client_config, client_remote, client_status)
                });
            }
            Err(error) => {
                let _ = status.send(format!("接受连接失败: {error}"));
            }
        }
    }
}

fn sender_loop(
    local_images: Receiver<clipboard::ClipboardImage>,
    shared_config: SharedConfig,
    recent_remote: RecentImages,
    status: std::sync::mpsc::Sender<String>,
) {
    let mut recent_local = HashMap::<[u8; 32], Instant>::new();
    let mut paired_round: HashMap<String, ([u8; 32], String)> = HashMap::new();

    while let Ok(image) = local_images.recv() {
        let digest = digest(&image);
        prune_recent(&mut recent_local);
        let is_remote = {
            let mut remote = recent_remote.lock().expect("remote image mutex poisoned");
            prune_recent(&mut remote);
            remote.remove(&digest).is_some()
        };

        if is_remote {
            continue;
        }
        if recent_local
            .get(&digest)
            .is_some_and(|time| time.elapsed() < DUPLICATE_WINDOW)
        {
            continue;
        }
        recent_local.insert(digest, Instant::now());

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
                let _ = status.send(format!("共享密钥无效: {error}"));
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
                let _ = status.send(format!("设备 {} 的会话密钥无效", peer.name));
                continue;
            };
            let addr = resolved_paired_addr(&peer, &mut paired_round);
            match send_one(&addr, &key, &envelope) {
                Ok(()) => delivered += 1,
                Err(error) => {
                    let _ = status.send(format!("发送到 {} 失败: {error}", peer.name));
                }
            }
        }
        if let Some(key) = manual_key {
            for peer in manual_peers {
                match send_one(&peer, &key, &envelope) {
                    Ok(()) => delivered += 1,
                    Err(error) => {
                        let _ = status.send(format!("发送到 {peer} 失败: {error}"));
                    }
                }
            }
        }
        if delivered > 0 {
            let _ = status.send(format!("图片已同步到 {delivered} 台设备"));
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
    status: std::sync::mpsc::Sender<String>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut magic = [0u8; 4];
    if stream.read_exact(&mut magic).is_err() || &magic != MAGIC {
        return;
    }

    let mut len_bytes = [0u8; 8];
    if stream.read_exact(&mut len_bytes).is_err() {
        return;
    }
    let frame_len = u64::from_le_bytes(len_bytes) as usize;
    if !(NONCE_BYTES..=MAX_FRAME_BYTES).contains(&frame_len) {
        let _ = status.send("收到超限或损坏的数据帧".to_owned());
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
        let _ = status.send("收到无法验证的剪贴板数据（密钥不匹配）".to_owned());
        return;
    };
    let envelope: ImageEnvelope = match postcard::from_bytes(&plaintext) {
        Ok(envelope) => envelope,
        Err(_) => return,
    };
    if envelope.image.dib.len() > clipboard::MAX_CLIPBOARD_BYTES {
        return;
    }

    recent_remote
        .lock()
        .expect("remote image mutex poisoned")
        .insert(digest(&envelope.image), Instant::now());
    if let Err(error) = clipboard::write_image(&envelope.image) {
        let _ = status.send(format!("写入远端剪贴板失败: {error}"));
        return;
    }
    let _ = status.send(format!("已接收来自 {} 的图片", envelope.origin));
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

fn digest(image: &clipboard::ClipboardImage) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(image.format.to_le_bytes());
    hasher.update(&image.dib);
    hasher.finalize().into()
}

fn prune_recent(map: &mut HashMap<[u8; 32], Instant>) {
    map.retain(|_, time| time.elapsed() < DUPLICATE_WINDOW);
}
