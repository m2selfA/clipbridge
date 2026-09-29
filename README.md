# ClipBridge

一个 Windows 优先的轻量局域网图片剪贴板同步器，使用 Rust + `windui`。

## 当前 MVP

- 使用 Windows 自带 `Win+Shift+S` 截图，不依赖 ShareX。
- 监听系统剪贴板中的 `CF_DIB` / `CF_DIBV5` 图片。
- 自动同步到已配置的局域网设备。
- 对端收到后直接写入本机剪贴板，可立即 `Ctrl+V`。
- 系统托盘、启动隐藏、关闭到托盘、`Ctrl+Shift+V` 唤起窗口。
- 传输内容使用共享密钥进行 ChaCha20-Poly1305 加密。
- 使用图片哈希和远端标记防止设备之间互相回环同步。

## 构建

```powershell
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Release 构建产物位于 `target/release/clipbridge.exe`。

## 图标

- `assets/clipbridge-generated.png`：Agnes 生成的原始图稿。
- `assets/clipbridge.ico`：包含多种尺寸的 Windows 程序图标，由 `build.rs` 嵌入 EXE 资源。
- `assets/clipbridge-icon.png`：窗口图标运行时资源。
- `assets/clipbridge-icon-32.png`：托盘图标运行时资源。

窗口标题栏、任务栏/资源管理器中的程序图标，以及系统托盘图标均使用同一套 ClipBridge 图标。

## 界面设计

主窗口参考 `wind-ui-rust` 的 `settings`、`theming`、`tray` 示例进行了重构：

- 无边框自绘标题栏，保留窗口拖动、最小化、最大化和关闭。
- 使用 `Theme` / `Role` 角色色，统一浅色主题的背景、卡片、边框和强调色。
- 采用「页面标题 → 卡片分区 → 底部操作栏」层次，分别组织局域网同步、设备安全、使用方式和运行状态。
- 使用状态徽章、步骤卡片和语义色，避免把网络状态埋在普通文本中。
- 标题栏和托盘统一使用 ClipBridge 品牌图标，并支持标题栏明暗主题切换。

## 自动发现与配对

借鉴 Clipboard Remote / LocalSend / KDE Connect / DecentPaste 的交互模式，实现了无需手动填地址的配对流程：

- **自动发现**：后台通过 UDP 广播（端口 `45822`）周期性公告本机设备名与指纹，同网段设备自动出现在「附近设备」列表。
- **信任式配对**：在一侧点击「配对」后，另一侧会显示配对请求与 6 位确认码；双方核对确认码后点击「接受配对」即完成。
- **独立会话密钥**：每次配对生成独立的 32 字节会话密钥，双方持久化到本地配置；后续图片同步使用该密钥加密。
- **兼容旧模式**：手动填写的地址仍使用共享密钥（`key_hex`），旧配置文件自动迁移。

状态流转：`Discovered → Pairing → Awaiting confirmation → Trusted`；确认码由双方身份指纹与随机 nonce 推导，超时未确认自动失败。

## 首次配对

1. 在每台机器上运行一次程序；同网段设备会自动出现在「附近设备」。
2. 在其中一台点击「配对」，另一台核对 6 位确认码后点击「接受配对」。
3. 配对完成后截图即可自动同步。

也可以继续使用手动方式：

4. 打开 `%APPDATA%\\ClipBridge\\config.toml`。
5. 将所有机器的 `key_hex` 设置为同一个 64 位十六进制密钥，并在 `peers` 中填写其他机器地址：

```toml
bind_addr = "0.0.0.0:45821"
peers = ["192.168.1.20:45821"]
key_hex = "替换为同一组 64 位十六进制密钥"
```

6. 允许 Windows 防火墙放行 TCP `45821` 与 UDP `45822`。
7. 截图后，其他机器可以直接粘贴图片。

配置窗口中的“设备地址”和“共享密钥”也可以直接修改并保存。

## 当前边界

- 第一版仅支持 Windows。
- 只支持同一局域网或已有 VPN/虚拟局域网；没有云端中继。
- 当前同步图片，不同步文本和文件。
- 当前直接传输 Windows DIB 数据，后续可增加压缩、历史记录和自有区域截图。
- 发现广播未加密（仅含设备名/指纹/端口），配对确认码通道未做加密握手；对高安全场景建议在可信网络使用，后续可升级 Noise XX 握手。
- 目前已在本机验证进程启动、TCP/UDP 端口监听、全局热键、关闭到托盘、配置生成与发现/配对界面渲染；两台真实机器之间的发现/配对/同步闭环仍需现场验证。

## 本地验证记录

- `cargo fmt --check`：通过。
- `cargo clippy --all-targets -- -D warnings`：通过。
- `cargo test --all-targets`：通过（含配置迁移、配对列表增删、指纹长度等 4 项单元测试）。
- `cargo build --release`：通过。
- 运行时验证：UDP `45822`（发现）与 TCP `45821`（同步）均成功监听。
- 「附近设备」卡片、接受/拒绝按钮已在运行截图验证。
