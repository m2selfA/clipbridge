#![cfg_attr(windows, windows_subsystem = "windows")]
#![cfg_attr(not(windows), allow(unused))]

#[cfg(not(windows))]
compile_error!("ClipBridge MVP 当前只支持 Windows");

#[cfg(windows)]
use std::thread;

#[cfg(windows)]
mod clipboard;
#[cfg(windows)]
mod config;
#[cfg(windows)]
mod discovery;
#[cfg(windows)]
mod firewall;
#[cfg(windows)]
mod network;
#[cfg(windows)]
mod status;

#[cfg(windows)]
use std::sync::{mpsc, Arc, Mutex};

#[cfg(windows)]
use windui::{
    core::EventCtx,
    icon::{IconSource, WindowIcon},
    prelude::*,
    render::Image,
};

#[cfg(windows)]
const APP_ICON_PNG: &[u8] = include_bytes!("../assets/clipbridge-icon.png");
#[cfg(windows)]
const TRAY_ICON_PNG: &[u8] = include_bytes!("../assets/clipbridge-icon-32.png");

#[cfg(windows)]
const CLIPBRIDGE_THEME: &str = r##"
[palette]
accent       = "#1684F6"
accent_hover = "#0D73E5"
bg           = "#F4F8FC"
surface      = "#FFFFFF"
surface_alt  = "#E8F1FB"
text         = "#102A43"
text_muted   = "#627D98"
border       = "#CFDCEB"

[metrics]
corner_md = 12.0
"##;

#[cfg(windows)]
fn embedded_icon(bytes: &[u8]) -> WindowIcon {
    let image = Image::from_png_bytes(bytes).expect("embedded ClipBridge icon must be valid PNG");
    WindowIcon::from_image(&image).expect("embedded ClipBridge icon must contain RGBA pixels")
}

#[cfg(windows)]
fn app_icon() -> IconSource {
    embedded_icon(APP_ICON_PNG).into()
}

#[cfg(windows)]
fn brand_logo(size: i32) -> Element {
    let icon = embedded_icon(TRAY_ICON_PNG);
    Element::image_rgba(icon.width(), icon.height(), icon.rgba())
        .fit(Fit::Contain)
        .size(size, size)
}

#[cfg(windows)]
fn card(body: Element) -> Element {
    Element::col()
        .width_match()
        .bg_role(Role::Surface)
        .corner(14.0)
        .border_role(Role::Border, 1)
        .padding(18)
        .spacing(12)
        .child(body)
}

#[cfg(windows)]
fn section_title(title: Element) -> Element {
    Element::row()
        .cross(Align::Center)
        .spacing(9)
        .child(
            Element::leaf()
                .size(4, 18)
                .corner(2.0)
                .bg_role(Role::Accent),
        )
        .child(title.font_size(15.0).font_weight(700).fg_role(Role::Text))
}

#[cfg(windows)]
fn setting_row_i18n(label: Element, desc: Element, control: Element) -> Element {
    Element::row()
        .width_match()
        .cross(Align::Center)
        .spacing(16)
        .child(
            Element::col()
                .spacing(3)
                .weight(1.0)
                .child(label.font_size(13.0).font_weight(600).fg_role(Role::Text))
                .child(desc.font_size(11.5).fg_role(Role::TextMuted)),
        )
        .child(control)
}

#[cfg(windows)]
fn advanced_toggle(expanded: Signal<bool>) -> Element {
    Element::row()
        .width_match()
        .cross(Align::Center)
        .spacing(10)
        .padding_xy(2, 4)
        .clickable()
        .on_click(move |_| expanded.set(!expanded.get()))
        .child(
            Element::label(t!("app.advanced_title"))
                .font_size(14.0)
                .font_weight(700)
                .fg_role(Role::Text),
        )
        .child(
            Element::label(t!("app.advanced_desc"))
                .font_size(11.5)
                .fg_role(Role::TextMuted)
                .weight(1.0),
        )
        .child(Element::label("⌄").font_size(16.0).fg_role(Role::TextMuted))
}

#[cfg(windows)]
fn theme_toggle(theme_handle: ThemeHandle, dark: Signal<bool>) -> Element {
    Element::stack()
        .width(44)
        .height_match()
        .clickable()
        .tooltip(tr!("app.theme_tooltip"))
        .on_click(move |_| {
            let next = !dark.get();
            dark.set(next);
            theme_handle.set(if next {
                Theme::dark()
            } else {
                Theme::from_toml(CLIPBRIDGE_THEME).expect("ClipBridge theme must parse")
            });
        })
        .child(
            Element::label("◐")
                .font_size(15.0)
                .fg_role(Role::Text)
                .align(Align::Center),
        )
}

#[cfg(windows)]
fn titlebar(
    theme_handle: ThemeHandle,
    dark: Signal<bool>,
    locale_handle: LocaleHandle,
    status_state: Signal<status::Status>,
    status_text: Signal<String>,
) -> Element {
    Element::row()
        .width_match()
        .height(42)
        .cross(Align::Stretch)
        .bg_role(Role::SurfaceAlt)
        .window_drag()
        .child(
            Element::row()
                .cross(Align::Center)
                .padding_xy(14, 0)
                .spacing(9)
                .child(brand_logo(22))
                .child(
                    Element::row()
                        .cross(Align::Center)
                        .spacing(5)
                        .child(
                            Element::label("ClipBridge")
                                .font_size(13.0)
                                .font_weight(700)
                                .fg_role(Role::Text),
                        )
                        .child(
                            Element::label("·")
                                .font_size(13.0)
                                .fg_role(Role::TextDisabled),
                        )
                        .child(
                            Element::label(t!("app.titlebar_subtitle"))
                                .font_size(12.0)
                                .fg_role(Role::TextMuted),
                        ),
                ),
        )
        .child(Element::leaf().weight(1.0))
        .child(
            Element::button(t!("app.switch_language"))
                .small()
                .outline()
                .neutral()
                .on_click(move |_| {
                    let next = if locale_handle.language() == "en" {
                        "zh-CN"
                    } else {
                        "en"
                    };
                    locale_handle.set(next);
                    status_text.set(render_status(&status_state.get()));
                }),
        )
        .child(theme_toggle(theme_handle, dark))
        .child(Element::window_button(WindowButtonKind::Minimize).fg_role(Role::Text))
        .child(Element::window_button(WindowButtonKind::Maximize).fg_role(Role::Text))
        .child(Element::window_button(WindowButtonKind::Close).fg_role(Role::Text))
}

#[cfg(windows)]
fn workflow_step(number: &str, title: Element, detail: Element) -> Element {
    Element::row()
        .weight(1.0)
        .cross(Align::Center)
        .spacing(10)
        .child(
            Element::stack()
                .size(30, 30)
                .corner(15.0)
                .bg_role_alpha(Role::Accent, 0.14)
                .child(
                    Element::label(number)
                        .font_size(13.0)
                        .font_weight(700)
                        .fg_role(Role::Accent)
                        .align(Align::Center),
                ),
        )
        .child(
            Element::col()
                .spacing(3)
                .child(title.font_size(13.0).font_weight(600).fg_role(Role::Text))
                .child(detail.font_size(11.5).fg_role(Role::TextMuted).max_lines(2)),
        )
}

#[cfg(windows)]
fn localize_detail(detail: &str) -> String {
    let mut text = detail.to_owned();
    for (source, translated) in [
        (
            "剪贴板被其他程序占用或拒绝访问",
            tr!("app.detail_clipboard_busy"),
        ),
        ("打开剪贴板失败", tr!("app.detail_open_clipboard")),
        ("写入剪贴板失败", tr!("app.detail_write_clipboard")),
        ("清空剪贴板失败", tr!("app.detail_clear_clipboard")),
        ("剪贴板图片大小无效", tr!("app.detail_clipboard_size")),
        (
            "剪贴板宿主窗口尚未准备好",
            tr!("app.detail_clipboard_owner"),
        ),
        (
            "共享密钥必须是 64 个十六进制字符",
            tr!("app.detail_key_length"),
        ),
        ("十六进制密钥长度必须为偶数", tr!("app.detail_invalid_key")),
        (
            "共享密钥只能包含十六进制字符",
            tr!("app.detail_invalid_key"),
        ),
        (
            "身份密钥必须是 64 个十六进制字符",
            tr!("app.detail_identity_key"),
        ),
        ("对方拒绝了配对请求", tr!("app.detail_pair_rejected")),
        ("协议版本不匹配", tr!("app.detail_protocol_mismatch")),
        ("配置锁不可用", tr!("app.detail_config_lock")),
        ("无效地址", tr!("app.detail_invalid_address")),
        ("加密剪贴板数据失败", tr!("app.detail_encryption")),
        ("加密自动配对介绍失败", tr!("app.detail_encryption")),
        ("剪贴板数据超过传输限制", tr!("app.detail_data_limit")),
        ("自动配对介绍认证失败", tr!("app.detail_introduction_auth")),
        (
            "自动配对介绍的接收设备不匹配",
            tr!("app.detail_recipient_mismatch"),
        ),
        ("自动配对介绍指向本机", tr!("app.detail_self_introduction")),
        ("自动配对介绍帧大小无效", tr!("app.detail_intro_frame")),
        ("UAC 请求被取消或防火墙命令失败", tr!("app.detail_uac")),
    ] {
        text = text.replace(source, &translated);
    }
    text
}

#[cfg(windows)]
fn render_status(message: &status::Status) -> String {
    use status::Status;

    match message {
        Status::FirewallReady { tcp, udp } => {
            tr!("app.status_firewall_ready", tcp = *tcp, udp = *udp)
        }
        Status::FirewallAuthorized { tcp, udp } => {
            tr!("app.status_firewall_authorized", tcp = *tcp, udp = *udp)
        }
        Status::FirewallPending { tcp, udp } => {
            tr!("app.status_firewall_pending", tcp = *tcp, udp = *udp)
        }
        Status::FirewallFailed { tcp, udp, detail } => {
            let detail = localize_detail(detail);
            tr!(
                "app.status_firewall_failed",
                tcp = *tcp,
                udp = *udp,
                detail = detail
            )
        }
        Status::Listening { addr } => tr!("app.status_listening", addr = addr),
        Status::ListenFailed { addr, detail } => {
            let detail = localize_detail(detail);
            tr!("app.status_listen_failed", addr = addr, detail = detail)
        }
        Status::AcceptFailed { detail } => {
            let detail = localize_detail(detail);
            tr!("app.status_accept_failed", detail = detail)
        }
        Status::SharedKeyInvalid { detail } => {
            let detail = localize_detail(detail);
            tr!("app.status_shared_key_invalid", detail = detail)
        }
        Status::SessionKeyInvalid { peer } => tr!("app.status_session_key_invalid", peer = peer),
        Status::SendFailed { peer, detail } => {
            let detail = localize_detail(detail);
            tr!("app.status_send_failed", peer = peer, detail = detail)
        }
        Status::SyncComplete { count } => tr!("app.status_sync_complete", count = *count),
        Status::PairRequestWaiting => tr!("app.status_pair_request_waiting"),
        Status::FrameInvalid => tr!("app.status_frame_invalid"),
        Status::AuthenticationFailed => tr!("app.status_authentication_failed"),
        Status::ClipboardWriteFailed { detail } => {
            let detail = localize_detail(detail);
            tr!("app.status_clipboard_write_failed", detail = detail)
        }
        Status::ReceivedImage { origin } => tr!("app.status_received_image", origin = origin),
        Status::IntroductionFailed { detail } => {
            let detail = localize_detail(detail);
            tr!("app.status_introduction_failed", detail = detail)
        }
        Status::AutoPaired { via, peer } => tr!("app.status_auto_paired", via = via, peer = peer),
        Status::PairingRequestReceived => tr!("app.request_received"),
        Status::PairingFailed { detail } => {
            let detail = localize_detail(detail);
            tr!("app.status_pairing_failed", detail = detail)
        }
        Status::PairingComplete { name, code } => {
            tr!("app.pairing_complete", name = name, code = code)
        }
        Status::PairingAccepted { name } => tr!("app.pairing_accepted", name = name),
        Status::PairingRejected => tr!("app.pairing_rejected"),
        Status::PairingTimeout => tr!("app.pairing_timeout"),
        Status::NoPendingPair => tr!("app.no_pending_pair"),
        Status::SettingsSaved => tr!("app.settings_saved"),
    }
}

#[cfg(windows)]
fn set_status(state: Signal<status::Status>, text: Signal<String>, message: status::Status) {
    text.set(render_status(&message));
    state.set(message);
}

#[cfg(windows)]
fn resolve_pending(
    confirm: &discovery::ConfirmRegistry,
    pending: &Arc<Mutex<Option<discovery::PendingPair>>>,
    accepted: bool,
) -> (Option<String>, usize) {
    let slot = pending.lock().ok().and_then(|mut p| p.take());
    match slot {
        Some(info) => {
            let resolved = discovery::resolve_confirmation_by_addr(confirm, &info.addr, accepted);
            (Some(info.name.clone()), resolved)
        }
        None => (None, 0),
    }
}

#[cfg(windows)]
fn main() {
    let initial_config = match config::load() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("读取配置失败，使用临时默认配置: {error}");
            config::Config::default()
        }
    };
    let shared_config = Arc::new(Mutex::new(initial_config.clone()));
    let tcp_port = initial_config
        .bind_addr
        .rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(45821);
    let firewall_status = firewall::ensure_rules(tcp_port, discovery::DISCOVERY_PORT);

    let peers = signal(initial_config.peers.join(", "));
    let key = signal(initial_config.key_hex.clone());
    let status_state = signal(firewall_status.clone());
    let status_text = signal(String::new());
    let dark = signal(false);
    let advanced_open = signal(false);
    let devices = discovery::devices_handle();
    let device_list = signal(Vec::<discovery::DeviceRow>::new());
    let pair_peer_name = signal(String::new());
    let pair_peer_addr = signal(String::new());
    let pair_code = signal(String::new());
    let pending_available = signal(false);
    let confirm_registry = discovery::init_confirm_registry();
    let pending_pair: Arc<Mutex<Option<discovery::PendingPair>>> = Arc::new(Mutex::new(None));
    let (local_tx, local_rx) = mpsc::channel();
    let (status_tx, status_rx) = mpsc::channel::<status::Status>();
    let (pair_event_tx, pair_event_rx) = mpsc::channel::<discovery::PairEvent>();

    let locales = Locales::builder()
        .embed(include_str!("../locales/en.toml"))
        .embed(include_str!("../locales/zh-CN.toml"))
        .fallback("en")
        .initial(Initial::Fixed("en".to_owned()))
        .build();
    let mut app = App::new("ClipBridge", 720, 540)
        .locales(locales)
        .icon(app_icon())
        .frameless()
        .theme(Theme::from_toml(CLIPBRIDGE_THEME).expect("ClipBridge theme must parse"))
        .start_hidden()
        .hide_on_close();
    let theme_handle = app.theme_handle();
    let locale_handle = app.locale_handle();
    status_text.set(render_status(&firewall_status));

    let status_state_for_channel = status_state;
    let status_text_for_channel = status_text;
    let ui_status_tx = app.channel::<status::Status>(move |_ctx, message| {
        set_status(status_state_for_channel, status_text_for_channel, message);
    });

    let _clipboard_thread = clipboard::spawn_listener(local_tx);
    let introduction_status_tx = status_tx.clone();
    network::spawn(
        local_rx,
        Arc::clone(&shared_config),
        status_tx,
        pair_event_tx.clone(),
    );
    discovery::spawn_discovery(Arc::clone(&shared_config), devices.clone());
    std::thread::spawn(move || {
        while let Ok(message) = status_rx.recv() {
            if ui_status_tx.send(message).is_err() {
                break;
            }
        }
    });
    // 转发发现/配对事件到 UI 线程。
    let ui_pair_tx = app.channel::<discovery::UiPairEvent>(move |ctx, event| match event {
        discovery::UiPairEvent::Code {
            peer_name,
            peer_addr,
            code,
        } => {
            pending_available.set(true);
            pair_peer_name.set(peer_name);
            pair_peer_addr.set(peer_addr);
            pair_code.set(code);
            set_status(
                status_state,
                status_text,
                status::Status::PairingRequestReceived,
            );
        }
        discovery::UiPairEvent::Devices(rows) => {
            device_list.set(rows);
        }
        discovery::UiPairEvent::Done { peer_name, code } => {
            pending_available.set(false);
            set_status(
                status_state,
                status_text,
                status::Status::PairingComplete {
                    name: peer_name,
                    code,
                },
            );
            ctx.toast_ok(tr!("app.paired"));
        }
        discovery::UiPairEvent::Failed(message) => {
            pending_available.set(false);
            set_status(status_state, status_text, message);
        }
    });
    std::thread::spawn({
        let ui_pair_tx = ui_pair_tx.clone();
        let pending_pair = Arc::clone(&pending_pair);
        let introduction_config = Arc::clone(&shared_config);
        let introduction_status = introduction_status_tx.clone();
        move || {
            while let Ok(event) = pair_event_rx.recv() {
                match event {
                    discovery::PairEvent::Code {
                        peer_addr,
                        peer_name,
                        code,
                    } => {
                        // 保存待确认信息，等待用户决定。
                        if let Ok(mut pending) = pending_pair.lock() {
                            *pending = Some(discovery::PendingPair {
                                addr: peer_addr.clone(),
                                name: peer_name.clone(),
                            });
                        }
                        let _ = ui_pair_tx.send(discovery::UiPairEvent::Code {
                            peer_name,
                            peer_addr,
                            code,
                        });
                    }
                    discovery::PairEvent::Done { peer_name, code } => {
                        discovery::sync_introductions(
                            Arc::clone(&introduction_config),
                            introduction_status.clone(),
                        );
                        let _ = ui_pair_tx.send(discovery::UiPairEvent::Done { peer_name, code });
                    }
                    discovery::PairEvent::Failed(message) => {
                        let _ = ui_pair_tx.send(discovery::UiPairEvent::Failed(message));
                    }
                }
            }
        }
    });
    // 定期刷新已发现设备列表。
    {
        let devices = devices.clone();
        let ui_pair_tx = ui_pair_tx.clone();
        std::thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_secs(3));
            let rows = discovery::snapshot_rows(&devices);
            if ui_pair_tx
                .send(discovery::UiPairEvent::Devices(rows))
                .is_err()
            {
                break;
            }
        });
    }

    let save_config = {
        let shared_config = Arc::clone(&shared_config);
        let peers_signal = peers;
        let key_signal = key;
        let status_state_signal = status_state;
        let status_text_signal = status_text;
        move |ctx: &mut EventCtx<'_>| {
            let peers_value = config::normalize_peers(&peers_signal.get());
            let key_value = key_signal.get();
            if let Err(error) = config::parse_key(&key_value) {
                ctx.toast_err(error);
                return;
            }
            let result = match shared_config.lock() {
                Ok(mut current) => {
                    current.peers = peers_value;
                    current.key_hex = key_value;
                    let result = config::save(&current);
                    if result.is_ok() {
                        set_status(
                            status_state_signal,
                            status_text_signal,
                            status::Status::SettingsSaved,
                        );
                    }
                    result
                }
                Err(_) => Err(std::io::Error::other("配置锁不可用")),
            };
            match result {
                Ok(()) => ctx.toast_ok(tr!("app.save_settings")),
                Err(error) => ctx.toast_err(format!("保存失败: {error}")),
            }
        }
    };

    let tray_icon = embedded_icon(TRAY_ICON_PNG);
    let tray = Tray::new()
        .icon_rgba(tray_icon.width(), tray_icon.height(), tray_icon.rgba())
        .tooltip(tr!("app.tray_tooltip"))
        .on_left_click(|ctx| ctx.show_window())
        .on_double_click(|ctx| ctx.show_window())
        .menu(vec![
            TrayMenuItem::item(t!("app.show_window"), |ctx| ctx.show_window()),
            TrayMenuItem::item(t!("app.hide_tray"), |ctx| ctx.hide_window()),
            TrayMenuItem::separator(),
            TrayMenuItem::item(t!("app.quit"), |ctx| ctx.quit()),
        ]);

    let connection_card = card(
        Element::col()
            .width_match()
            .spacing(11)
            .child(section_title(Element::label(t!("app.connection_title"))))
            .child(
                Element::label(t!("app.connection_desc"))
                    .font_size(12.0)
                    .fg_role(Role::TextMuted)
                    .width_match(),
            )
            .child(setting_row_i18n(
                Element::label(t!("app.device_address")),
                Element::label(t!("app.device_address_desc")),
                Element::text_input(peers, t!("app.manual_address_hint"))
                    .width(300)
                    .height(34),
            ))
            .child(setting_row_i18n(
                Element::label(t!("app.listen_port")),
                Element::label(t!("app.listen_port_desc")),
                Element::label(t!("app.tcp_port"))
                    .font_size(12.0)
                    .fg_role(Role::Accent),
            )),
    );

    // 「附近设备」卡片：展示发现到的设备，可发起配对；配对请求到达时展示确认码。
    let shared_for_devices = Arc::clone(&shared_config);
    let pair_events_for_rows = pair_event_tx.clone();
    let confirm_for_ui = Arc::clone(&confirm_registry);
    let pending_for_ui = Arc::clone(&pending_pair);
    let devices_card = card(
        Element::col()
            .width_match()
            .spacing(11)
            .child(section_title(Element::label(t!("app.devices_title"))))
            .child(
                Element::label(t!("app.devices_desc"))
                    .font_size(12.0)
                    .fg_role(Role::TextMuted)
                    .width_match(),
            )
            .child(
                Element::label(t!(
                    "app.pair_request",
                    name = pair_peer_name,
                    addr = pair_peer_addr,
                    code = pair_code
                ))
                .font_size(12.5)
                .font_weight(600)
                .fg_role(Role::Accent)
                .width_match()
                .visible_signal(pending_available),
            )
            .child(
                Element::label(t!("app.pair_action_hint"))
                    .font_size(11.5)
                    .fg_role(Role::TextMuted)
                    .width_match()
                    .visible_when(move || !pending_available.get()),
            )
            .child(
                Element::row()
                    .spacing(8)
                    .child(
                        Element::button(t!("app.accept_pairing"))
                            .small()
                            .enabled_signal(pending_available)
                            .on_click({
                                let confirm = Arc::clone(&confirm_for_ui);
                                let pending = Arc::clone(&pending_for_ui);
                                move |ctx| {
                                    let (peer_name, resolved) =
                                        resolve_pending(&confirm, &pending, true);
                                    match (peer_name, resolved) {
                                        (Some(name), count) if count > 0 => {
                                            pending_available.set(false);
                                            set_status(
                                                status_state,
                                                status_text,
                                                status::Status::PairingAccepted { name },
                                            );
                                        }
                                        (Some(_), _) => {
                                            set_status(
                                                status_state,
                                                status_text,
                                                status::Status::PairingTimeout,
                                            );
                                        }
                                        (None, _) => {
                                            set_status(
                                                status_state,
                                                status_text,
                                                status::Status::NoPendingPair,
                                            );
                                        }
                                    }
                                    let _ = ctx;
                                }
                            }),
                    )
                    .child(
                        Element::button(t!("app.reject"))
                            .small()
                            .outline()
                            .neutral()
                            .enabled_signal(pending_available)
                            .on_click({
                                let confirm = Arc::clone(&confirm_for_ui);
                                let pending = Arc::clone(&pending_for_ui);
                                move |ctx| {
                                    let (peer_name, resolved) =
                                        resolve_pending(&confirm, &pending, false);
                                    if peer_name.is_some() && resolved > 0 {
                                        pending_available.set(false);
                                        set_status(
                                            status_state,
                                            status_text,
                                            status::Status::PairingRejected,
                                        );
                                    } else {
                                        set_status(
                                            status_state,
                                            status_text,
                                            status::Status::NoPendingPair,
                                        );
                                    }
                                    let _ = ctx;
                                }
                            }),
                    ),
            )
            .child(Element::list_signal(
                device_list,
                |row: &discovery::DeviceRow| row.id.clone(),
                move |row| {
                    let shared = Arc::clone(&shared_for_devices);
                    let ui_tx_for_rows = pair_events_for_rows.clone();
                    let addr = row.addr.clone();
                    let button_addr = addr.clone();
                    let name = row.name.clone();
                    let fp = row.fp.clone();
                    let paired = row.paired;
                    let display_name = if let Some(via) = row.introduced_by.clone() {
                        Element::label(t!("app.device_paired_via", name = name, via = via))
                    } else if paired {
                        Element::label(t!("app.device_paired", name = name))
                    } else {
                        Element::label(name)
                    };
                    Element::row()
                        .width_match()
                        .cross(Align::Center)
                        .spacing(10)
                        .child(
                            Element::col()
                                .spacing(2)
                                .weight(1.0)
                                .child(
                                    display_name
                                        .font_size(13.0)
                                        .font_weight(600)
                                        .fg_role(Role::Text),
                                )
                                .child(
                                    Element::label(t!("app.device_details", addr = addr, fp = fp))
                                        .font_size(11.0)
                                        .fg_role(Role::TextMuted),
                                ),
                        )
                        .child(
                            Element::button(if paired {
                                t!("app.paired")
                            } else {
                                t!("app.pair")
                            })
                            .small()
                            .outline()
                            .neutral()
                            .enabled(!paired)
                            .on_click(move |ctx| {
                                let shared = Arc::clone(&shared);
                                let ui_tx = ui_tx_for_rows.clone();
                                let addr = button_addr.clone();
                                std::thread::spawn(move || {
                                    let (name_cfg, fp, id) = match shared.lock() {
                                        Ok(config) => (
                                            config.device_name.clone(),
                                            config::fingerprint(&config).unwrap_or_default(),
                                            config.device_id.clone(),
                                        ),
                                        Err(_) => return,
                                    };
                                    discovery::request_pair(
                                        &addr,
                                        name_cfg,
                                        fp,
                                        id,
                                        Arc::clone(&shared),
                                        ui_tx,
                                    );
                                });
                                let _ = ctx;
                            }),
                        )
                },
            )),
    );

    let security_card = card(
        Element::col()
            .width_match()
            .spacing(11)
            .child(section_title(Element::label(t!("app.security_title"))))
            .child(
                Element::label(t!("app.security_desc"))
                    .font_size(12.0)
                    .fg_role(Role::TextMuted)
                    .width_match(),
            )
            .child(setting_row_i18n(
                Element::label(t!("app.shared_key")),
                Element::label(t!("app.shared_key_desc")),
                Element::text_input(key, "64 hex characters")
                    .password()
                    .width(300)
                    .height(34),
            ))
            .child(
                Element::row()
                    .width_match()
                    .cross(Align::Center)
                    .spacing(8)
                    .child(Element::badge_intent("ChaCha20-Poly1305", Intent::Success))
                    .child(
                        Element::label(t!("app.encryption_detail"))
                            .font_size(11.5)
                            .fg_role(Role::TextMuted),
                    ),
            ),
    );

    let workflow_card = card(
        Element::col()
            .width_match()
            .spacing(10)
            .child(section_title(Element::label(t!("app.workflow_title"))))
            .child(
                Element::row()
                    .width_match()
                    .spacing(12)
                    .child(workflow_step(
                        "1",
                        Element::label(t!("app.step_capture")),
                        Element::label(t!("app.step_capture_desc")),
                    ))
                    .child(workflow_step(
                        "2",
                        Element::label(t!("app.step_sync")),
                        Element::label(t!("app.step_sync_desc")),
                    ))
                    .child(workflow_step(
                        "3",
                        Element::label(t!("app.step_paste")),
                        Element::label(t!("app.step_paste_desc")),
                    )),
            ),
    );

    let status_card = card(
        Element::col()
            .width_match()
            .spacing(8)
            .child(section_title(Element::label(t!("app.runtime_title"))))
            .child(
                Element::row()
                    .width_match()
                    .cross(Align::Center)
                    .spacing(10)
                    .child(
                        Element::stack()
                            .size(14, 14)
                            .corner(7.0)
                            .bg_role_alpha(Role::Success, 0.20)
                            .child(
                                Element::leaf()
                                    .size(7, 7)
                                    .corner(4.0)
                                    .bg_role(Role::Success)
                                    .align(Align::Center),
                            ),
                    )
                    .child(
                        Element::col()
                            .spacing(2)
                            .weight(1.0)
                            .child(
                                Element::label(t!("app.status_message", message = status_text))
                                    .font_size(13.0)
                                    .fg_role(Role::Text),
                            )
                            .child(
                                Element::label(t!("app.runtime_running"))
                                    .font_size(11.5)
                                    .fg_role(Role::TextMuted),
                            ),
                    )
                    .child(Element::badge_intent(t!("app.auto_sync"), Intent::Success)),
            ),
    );

    let header = Element::row()
        .width_match()
        .cross(Align::Center)
        .spacing(12)
        .child(
            Element::col()
                .spacing(3)
                .weight(1.0)
                .child(
                    Element::label("ClipBridge")
                        .font_size(24.0)
                        .font_weight(700)
                        .fg_role(Role::Text),
                )
                .child(
                    Element::label(t!("app.tagline"))
                        .font_size(13.0)
                        .fg_role(Role::TextMuted),
                ),
        )
        .child(Element::badge(t!("app.platform_badge")));

    let advanced_body = Element::col()
        .width_match()
        .spacing(12)
        .child(connection_card)
        .child(security_card);
    let advanced_section = card(
        Element::col()
            .width_match()
            .spacing(10)
            .child(advanced_toggle(advanced_open))
            .child(advanced_body.visible_signal(advanced_open)),
    );

    // Keep the high-frequency status and workflow above the scroll region. The
    // low-frequency network/security settings stay collapsed by default.
    let content = Element::col()
        .fill()
        .padding_xy(20, 14)
        .spacing(10)
        .child(header)
        .child(status_card)
        .child(workflow_card)
        .child(
            Element::scroll()
                .fill()
                .child(
                    Element::col()
                        .width_match()
                        .spacing(12)
                        .child(devices_card)
                        .child(advanced_section),
                )
                .weight(1.0),
        );

    let footer = Element::row()
        .width_match()
        .height(50)
        .cross(Align::Center)
        .padding_xy(16, 0)
        .spacing(10)
        .bg_role(Role::SurfaceAlt)
        .child(
            Element::label(t!("app.settings_path"))
                .font_size(11.5)
                .fg_role(Role::TextMuted),
        )
        .child(Element::flex_spacer())
        .child(
            Element::button(t!("app.hide_tray"))
                .small()
                .outline()
                .neutral()
                .on_click(|ctx| ctx.hide_window()),
        )
        .child(
            Element::button(t!("app.save_settings"))
                .small()
                .on_click(save_config),
        );

    let body = Element::col()
        .fill()
        .child(titlebar(
            theme_handle,
            dark,
            locale_handle,
            status_state,
            status_text,
        ))
        .child(Element::divider())
        .child(content.weight(1.0))
        .child(Element::divider())
        .child(footer);

    app.tray(tray)
        .hotkey(Hotkey::new(Key::Char('V')).ctrl().shift(), |ctx| {
            ctx.show_window();
        })
        .content(body)
        .run();
}
