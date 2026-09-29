#![cfg_attr(windows, windows_subsystem = "windows")]
#![cfg_attr(not(windows), allow(unused))]

#[cfg(not(windows))]
compile_error!("ClipBridge MVP 当前只支持 Windows");

#[cfg(windows)]
mod clipboard;
#[cfg(windows)]
mod config;
#[cfg(windows)]
mod network;

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
fn section_title(title: &str) -> Element {
    Element::row()
        .cross(Align::Center)
        .spacing(9)
        .child(
            Element::leaf()
                .size(4, 18)
                .corner(2.0)
                .bg_role(Role::Accent),
        )
        .child(
            Element::label(title)
                .font_size(15.0)
                .font_weight(700)
                .fg_role(Role::Text),
        )
}

#[cfg(windows)]
fn theme_toggle(theme_handle: ThemeHandle, dark: Signal<bool>) -> Element {
    Element::stack()
        .width(44)
        .height_match()
        .clickable()
        .tooltip("切换明暗主题")
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
fn titlebar(theme_handle: ThemeHandle, dark: Signal<bool>) -> Element {
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
                            Element::label("局域网图片剪贴板")
                                .font_size(12.0)
                                .fg_role(Role::TextMuted),
                        ),
                ),
        )
        .child(Element::leaf().weight(1.0))
        .child(theme_toggle(theme_handle, dark))
        .child(Element::window_button(WindowButtonKind::Minimize).fg_role(Role::Text))
        .child(Element::window_button(WindowButtonKind::Maximize).fg_role(Role::Text))
        .child(Element::window_button(WindowButtonKind::Close).fg_role(Role::Text))
}

#[cfg(windows)]
fn workflow_step(number: &str, title: &str, detail: &str) -> Element {
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
                .child(
                    Element::label(title)
                        .font_size(13.0)
                        .font_weight(600)
                        .fg_role(Role::Text),
                )
                .child(
                    Element::label(detail)
                        .font_size(11.5)
                        .fg_role(Role::TextMuted)
                        .max_lines(2),
                ),
        )
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

    let peers = signal(initial_config.peers.join(", "));
    let key = signal(initial_config.key_hex.clone());
    let status = signal("正在启动…".to_owned());
    let dark = signal(false);
    let (local_tx, local_rx) = mpsc::channel();
    let (status_tx, status_rx) = mpsc::channel::<String>();

    let mut app = App::new("ClipBridge", 720, 590)
        .icon(app_icon())
        .frameless()
        .theme(Theme::from_toml(CLIPBRIDGE_THEME).expect("ClipBridge theme must parse"))
        .start_hidden()
        .hide_on_close();
    let theme_handle = app.theme_handle();

    let status_for_channel = status;
    let ui_status_tx = app.channel::<String>(move |_ctx, message| {
        status_for_channel.set(message);
    });

    let _clipboard_thread = clipboard::spawn_listener(local_tx);
    network::spawn(local_rx, Arc::clone(&shared_config), status_tx);
    std::thread::spawn(move || {
        while let Ok(message) = status_rx.recv() {
            if ui_status_tx.send(message).is_err() {
                break;
            }
        }
    });

    let save_config = {
        let shared_config = Arc::clone(&shared_config);
        let peers_signal = peers;
        let key_signal = key;
        let status_signal = status;
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
                        status_signal.set("设置已保存；新连接会立即使用新配置".to_owned());
                    }
                    result
                }
                Err(_) => Err(std::io::Error::other("配置锁不可用")),
            };
            match result {
                Ok(()) => ctx.toast_ok("设置已保存"),
                Err(error) => ctx.toast_err(format!("保存失败: {error}")),
            }
        }
    };

    let tray_icon = embedded_icon(TRAY_ICON_PNG);
    let tray = Tray::new()
        .icon_rgba(tray_icon.width(), tray_icon.height(), tray_icon.rgba())
        .tooltip("ClipBridge · 局域网图片剪贴板")
        .on_left_click(|ctx| ctx.show_window())
        .on_double_click(|ctx| ctx.show_window())
        .menu(vec![
            TrayMenuItem::item("显示设置", |ctx| ctx.show_window()),
            TrayMenuItem::item("隐藏到托盘", |ctx| ctx.hide_window()),
            TrayMenuItem::separator(),
            TrayMenuItem::item("退出", |ctx| ctx.quit()),
        ]);

    let connection_card = card(
        Element::col()
            .width_match()
            .spacing(13)
            .child(section_title("局域网同步"))
            .child(
                Element::label("在可信的局域网或 VPN 设备之间自动发送和接收图片剪贴板。")
                    .font_size(12.5)
                    .fg_role(Role::TextMuted)
                    .width_match(),
            )
            .child(Element::setting_row_desc(
                "设备地址",
                "多个地址用逗号或空格分隔，例如 192.168.1.20:45821",
                Element::text_input(peers, "192.168.1.20:45821")
                    .width(300)
                    .height(34),
            ))
            .child(Element::setting_row_desc(
                "监听端口",
                "其他设备连接到本机时使用的 TCP 端口",
                Element::badge("TCP 45821"),
            )),
    );

    let security_card = card(
        Element::col()
            .width_match()
            .spacing(13)
            .child(section_title("设备安全"))
            .child(
                Element::label("所有已配对设备必须使用相同的共享密钥；密钥只保存在本地配置文件。")
                    .font_size(12.5)
                    .fg_role(Role::TextMuted)
                    .width_match(),
            )
            .child(Element::setting_row_desc(
                "共享密钥",
                "64 位十六进制字符，建议仅在可信设备之间传递",
                Element::text_input(key, "64 位十六进制字符")
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
                        Element::label("传输内容经过认证加密")
                            .font_size(11.5)
                            .fg_role(Role::TextMuted),
                    ),
            ),
    );

    let workflow_card = card(
        Element::col()
            .width_match()
            .spacing(13)
            .child(section_title("使用方式"))
            .child(
                Element::row()
                    .width_match()
                    .spacing(12)
                    .child(workflow_step("1", "截图", "使用 Win+Shift+S 截取区域"))
                    .child(workflow_step("2", "同步", "图片自动加密发送"))
                    .child(workflow_step("3", "粘贴", "其他设备直接 Ctrl+V")),
            ),
    );

    let status_card = card(
        Element::col()
            .width_match()
            .spacing(12)
            .child(section_title("运行状态"))
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
                                Element::label_signal(status)
                                    .font_size(13.0)
                                    .fg_role(Role::Text),
                            )
                            .child(
                                Element::label("剪贴板监听与网络服务在后台持续运行")
                                    .font_size(11.5)
                                    .fg_role(Role::TextMuted),
                            ),
                    )
                    .child(Element::badge_intent("自动同步", Intent::Success)),
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
                    Element::label("轻量、直连、无需云端的图片剪贴板同步")
                        .font_size(13.0)
                        .fg_role(Role::TextMuted),
                ),
        )
        .child(Element::badge("Windows · LAN"));

    let content = Element::scroll().fill().child(
        Element::col()
            .width_match()
            .padding(24)
            .spacing(16)
            .child(header)
            .child(connection_card)
            .child(security_card)
            .child(workflow_card)
            .child(status_card),
    );

    let footer = Element::row()
        .width_match()
        .height(54)
        .cross(Align::Center)
        .padding_xy(16, 0)
        .spacing(10)
        .bg_role(Role::SurfaceAlt)
        .child(
            Element::label("配置保存在 %APPDATA%\\ClipBridge")
                .font_size(11.5)
                .fg_role(Role::TextMuted),
        )
        .child(Element::flex_spacer())
        .child(theme_toggle(theme_handle.clone(), dark))
        .child(
            Element::button("隐藏到托盘")
                .small()
                .outline()
                .neutral()
                .on_click(|ctx| ctx.hide_window()),
        )
        .child(Element::button("保存设置").small().on_click(save_config));

    let body = Element::col()
        .fill()
        .child(titlebar(theme_handle, dark))
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
