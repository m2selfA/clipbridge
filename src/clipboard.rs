#![cfg(windows)]

use std::{
    ffi::c_void,
    sync::{
        atomic::{AtomicPtr, Ordering},
        mpsc::SyncSender,
        Mutex,
    },
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use windows::core::w;
use windows::Win32::Foundation::{
    GlobalFree, HANDLE, HGLOBAL, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, CloseClipboard, EmptyClipboard, EnumClipboardFormats,
    GetClipboardData, GetClipboardFormatNameW, GetOpenClipboardWindow, IsClipboardFormatAvailable,
    OpenClipboard, RemoveClipboardFormatListener, SetClipboardData,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowLongPtrW,
    GetWindowThreadProcessId, RegisterClassExW, SetWindowLongPtrW, TranslateMessage, CREATESTRUCTW,
    GWLP_USERDATA, HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLIPBOARDUPDATE,
    WM_NCCREATE, WM_NCDESTROY, WNDCLASSEXW,
};

pub const CF_DIB: u32 = 8;
pub const CF_DIBV5: u32 = 17;
const CF_TEXT: u32 = 1;
const CF_OEMTEXT: u32 = 7;
const CF_UNICODETEXT: u32 = 13;
const CF_HDROP: u32 = 15;
pub const MAX_CLIPBOARD_BYTES: usize = 32 * 1024 * 1024;
const CLIPBOARD_RETRY_ATTEMPTS: usize = 100;
const CLIPBOARD_RETRY_DELAY: Duration = Duration::from_millis(50);

// EmptyClipboard assigns ownership to the HWND passed to OpenClipboard. Passing
// NULL makes SetClipboardData fail according to the Win32 contract, so writes
// use the message-only listener window as the process-owned clipboard owner.
static CLIPBOARD_OWNER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static CLIPBOARD_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClipboardImage {
    pub format: u32,
    pub dib: Vec<u8>,
}

pub fn spawn_listener(tx: SyncSender<ClipboardImage>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("clipbridge-clipboard".to_owned())
        .spawn(move || unsafe {
            let Ok(module) = GetModuleHandleW(None) else {
                eprintln!("无法取得当前模块句柄");
                return;
            };
            let hinstance = HINSTANCE(module.0);
            let class_name = w!("ClipBridgeClipboardListener");
            let class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(listener_proc),
                hInstance: hinstance,
                lpszClassName: class_name,
                ..Default::default()
            };
            let _ = RegisterClassExW(&class);

            let tx_ptr = Box::into_raw(Box::new(tx));
            let hwnd = match CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                class_name,
                w!("ClipBridge clipboard listener"),
                WINDOW_STYLE::default(),
                0,
                0,
                0,
                0,
                Some(HWND_MESSAGE),
                None,
                Some(hinstance),
                Some(tx_ptr.cast()),
            ) {
                Ok(hwnd) => hwnd,
                Err(error) => {
                    drop(Box::from_raw(tx_ptr));
                    eprintln!("创建剪贴板监听窗口失败: {error:?}");
                    return;
                }
            };

            CLIPBOARD_OWNER.store(hwnd.0, Ordering::Release);

            if let Err(error) = AddClipboardFormatListener(hwnd) {
                eprintln!("注册剪贴板监听失败: {error:?}");
                CLIPBOARD_OWNER.store(std::ptr::null_mut(), Ordering::Release);
                let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd);
                return;
            }

            let mut message = MSG::default();
            loop {
                let result = GetMessageW(&mut message, None, 0, 0);
                if !result.as_bool() {
                    break;
                }
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }

            let _ = RemoveClipboardFormatListener(hwnd);
            CLIPBOARD_OWNER.store(std::ptr::null_mut(), Ordering::Release);
            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd);
        })
        .expect("无法创建剪贴板监听线程")
}

pub fn read_image() -> Option<ClipboardImage> {
    let _clipboard_lock = CLIPBOARD_LOCK.lock().ok()?;
    for attempt in 0..CLIPBOARD_RETRY_ATTEMPTS {
        let opened = unsafe { OpenClipboard(None).is_ok() };
        if opened {
            let result = unsafe { read_image_open().ok() };
            unsafe {
                let _ = CloseClipboard();
            }
            return result;
        }
        if attempt + 1 < CLIPBOARD_RETRY_ATTEMPTS {
            thread::sleep(CLIPBOARD_RETRY_DELAY);
        }
    }
    None
}

fn clipboard_owner() -> Option<HWND> {
    let pointer = CLIPBOARD_OWNER.load(Ordering::Acquire);
    (!pointer.is_null()).then_some(HWND(pointer))
}

pub fn write_image(image: &ClipboardImage) -> Result<(), String> {
    if image.dib.is_empty() || image.dib.len() > MAX_CLIPBOARD_BYTES {
        return Err("剪贴板图片大小无效".to_owned());
    }
    validate_dib(&image.dib)?;

    let _clipboard_lock = CLIPBOARD_LOCK
        .lock()
        .map_err(|_| "剪贴板内部同步锁不可用".to_owned())?;
    let backup = clipboard_owner().and_then(|_| unsafe {
        if OpenClipboard(None).is_err() {
            return None;
        }
        let result = read_image_open().ok();
        let _ = CloseClipboard();
        result
    });
    let mut last_error = None;
    for attempt in 0..CLIPBOARD_RETRY_ATTEMPTS {
        let Some(owner) = clipboard_owner() else {
            last_error = Some("剪贴板宿主窗口尚未准备好".to_owned());
            if attempt + 1 < CLIPBOARD_RETRY_ATTEMPTS {
                thread::sleep(CLIPBOARD_RETRY_DELAY);
            }
            continue;
        };

        unsafe {
            match OpenClipboard(Some(owner)) {
                Ok(()) => {
                    let result = write_image_open(image, backup.as_ref());
                    let _ = CloseClipboard();
                    match result {
                        Ok(()) => return Ok(()),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => {
                    last_error = Some(format!("打开剪贴板失败: {error:?}"));
                }
            }
        }
        if attempt + 1 < CLIPBOARD_RETRY_ATTEMPTS {
            thread::sleep(CLIPBOARD_RETRY_DELAY);
        }
    }

    Err(format!(
        "剪贴板被其他程序占用或拒绝访问，已重试 {CLIPBOARD_RETRY_ATTEMPTS} 次: {}; {}",
        last_error.unwrap_or_else(|| "未知错误".to_owned()),
        open_clipboard_diagnostic()
    ))
}

fn open_clipboard_diagnostic() -> String {
    unsafe {
        let Ok(hwnd) = GetOpenClipboardWindow() else {
            return "未能取得当前占用窗口（可能在查询前已释放）".to_owned();
        };
        if hwnd.0.is_null() {
            return "未能取得当前占用窗口（可能在查询前已释放）".to_owned();
        }
        let mut process_id = 0u32;
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut process_id));
        format!(
            "当前占用窗口 HWND=0x{:X}, PID={process_id}",
            hwnd.0 as usize
        )
    }
}

unsafe fn read_image_open() -> Result<ClipboardImage, String> {
    let format = if IsClipboardFormatAvailable(CF_DIBV5).is_ok() {
        CF_DIBV5
    } else if IsClipboardFormatAvailable(CF_DIB).is_ok() {
        CF_DIB
    } else {
        return Err("当前剪贴板没有 DIB 图片".to_owned());
    };

    // Many text, file, Office, and OLE objects publish a bitmap preview alongside
    // their real payload. Treating any DIB as an image would turn a normal text or
    // object copy into an image sync and would replace the remote clipboard with
    // that preview. Only image-only clipboard contents are eligible for syncing.
    if clipboard_has_non_image_payload() {
        return Err("剪贴板同时包含文字或其他对象数据".to_owned());
    }

    let handle = GetClipboardData(format).map_err(|error| format!("读取剪贴板失败: {error:?}"))?;
    if handle.0.is_null() {
        return Err("剪贴板图片句柄为空".to_owned());
    }

    let global = HGLOBAL(handle.0);
    let size = GlobalSize(global);
    if size == 0 || size > MAX_CLIPBOARD_BYTES {
        return Err("剪贴板图片超过大小限制".to_owned());
    }
    let pointer = GlobalLock(global) as *const u8;
    if pointer.is_null() {
        return Err("锁定剪贴板图片失败".to_owned());
    }
    let data = std::slice::from_raw_parts(pointer, size).to_vec();
    let _ = GlobalUnlock(global);
    validate_dib(&data)?;
    Ok(ClipboardImage { format, dib: data })
}

unsafe fn clipboard_has_non_image_payload() -> bool {
    let mut format = 0u32;
    loop {
        format = EnumClipboardFormats(format);
        if format == 0 {
            break;
        }
        if is_non_image_standard_format(format) {
            return true;
        }
        if format >= 0xC000 {
            let mut name = [0u16; 256];
            let length = GetClipboardFormatNameW(format, &mut name);
            if length > 0 {
                let name = String::from_utf16_lossy(&name[..length as usize]);
                if is_non_image_registered_format(&name) {
                    return true;
                }
            } else {
                // An unknown registered format is safer to treat as an object payload
                // than to risk synchronizing a bitmap preview from it.
                return true;
            }
        }
    }
    false
}

fn is_non_image_standard_format(format: u32) -> bool {
    matches!(format, CF_TEXT | CF_OEMTEXT | CF_UNICODETEXT | CF_HDROP)
}

fn is_non_image_registered_format(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    !(normalized.starts_with("image/")
        || matches!(
            normalized.as_str(),
            "png" | "jfif" | "jpeg" | "jpg" | "gif" | "tiff" | "bitmap" | "deviceindependentbitmap"
        ))
}

fn validate_dib(data: &[u8]) -> Result<(), String> {
    const HEADER_MIN: usize = 40;
    const BI_RGB: u32 = 0;
    const BI_RLE8: u32 = 1;
    const BI_RLE4: u32 = 2;
    const BI_BITFIELDS: u32 = 3;
    const BI_JPEG: u32 = 4;
    const BI_PNG: u32 = 5;
    const BI_ALPHABITFIELDS: u32 = 6;

    if data.len() < HEADER_MIN {
        return Err("剪贴板 DIB 头部不完整".to_owned());
    }
    let read_u16 = |offset: usize| -> u16 { u16::from_le_bytes([data[offset], data[offset + 1]]) };
    let read_u32 = |offset: usize| -> u32 {
        u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ])
    };
    let header_size = read_u32(0) as usize;
    if !(HEADER_MIN..=data.len()).contains(&header_size) {
        return Err("剪贴板 DIB 头部大小无效".to_owned());
    }
    let width = i32::from_le_bytes([data[4], data[5], data[6], data[7]]) as i64;
    let height = i32::from_le_bytes([data[8], data[9], data[10], data[11]]) as i64;
    if width == 0 || height == 0 || width.abs() > 32_768 || height.abs() > 32_768 {
        return Err("剪贴板 DIB 尺寸无效".to_owned());
    }
    if read_u16(12) != 1 {
        return Err("剪贴板 DIB 平面数无效".to_owned());
    }
    let bit_count = read_u16(14);
    if !matches!(bit_count, 1 | 4 | 8 | 16 | 24 | 32) {
        return Err("剪贴板 DIB 位深无效".to_owned());
    }
    let compression = read_u32(16);
    if !matches!(
        compression,
        BI_RGB | BI_RLE8 | BI_RLE4 | BI_BITFIELDS | BI_JPEG | BI_PNG | BI_ALPHABITFIELDS
    ) {
        return Err("剪贴板 DIB 压缩格式无效".to_owned());
    }
    let image_size = read_u32(20) as usize;
    if image_size > data.len() {
        return Err("剪贴板 DIB 图像大小无效".to_owned());
    }
    Ok(())
}

fn commit_with_restore<F, R>(
    image: &ClipboardImage,
    backup: Option<&ClipboardImage>,
    mut set_data: F,
    mut restore: R,
) -> Result<(), String>
where
    F: FnMut(&ClipboardImage) -> Result<(), String>,
    R: FnMut(&ClipboardImage) -> Result<(), String>,
{
    if let Err(first_error) = set_data(image) {
        if set_data(image).is_err() {
            if let Some(backup) = backup {
                let _ = restore(backup);
            }
            return Err(first_error);
        }
    }
    Ok(())
}

unsafe fn write_image_open(
    image: &ClipboardImage,
    backup: Option<&ClipboardImage>,
) -> Result<(), String> {
    let memory = GlobalAlloc(GMEM_MOVEABLE, image.dib.len())
        .map_err(|error| format!("分配剪贴板内存失败: {error:?}"))?;
    let pointer = GlobalLock(memory) as *mut u8;
    if pointer.is_null() {
        let _ = GlobalFree(Some(memory));
        return Err("锁定剪贴板内存失败".to_owned());
    }
    std::ptr::copy_nonoverlapping(image.dib.as_ptr(), pointer, image.dib.len());
    let _ = GlobalUnlock(memory);

    if let Err(error) = EmptyClipboard() {
        let _ = GlobalFree(Some(memory));
        return Err(format!("清空剪贴板失败: {error:?}"));
    }

    // SetClipboardData 成功后，所有权转移给系统，不能再次 GlobalFree。
    // A transient SetClipboardData failure can occur immediately after EmptyClipboard;
    // retry once and restore the previous image before reporting a failed delivery.
    let result = commit_with_restore(
        image,
        backup,
        |image| {
            SetClipboardData(image.format, Some(HANDLE(memory.0)))
                .map(|_| ())
                .map_err(|error| format!("写入剪贴板失败: {error:?}"))
        },
        |backup| restore_image_open(backup),
    );
    if let Err(error) = result {
        let _ = GlobalFree(Some(memory));
        return Err(error);
    }
    Ok(())
}

unsafe fn restore_image_open(image: &ClipboardImage) -> Result<(), String> {
    let memory = GlobalAlloc(GMEM_MOVEABLE, image.dib.len())
        .map_err(|error| format!("恢复剪贴板内存分配失败: {error:?}"))?;
    let pointer = GlobalLock(memory) as *mut u8;
    if pointer.is_null() {
        let _ = GlobalFree(Some(memory));
        return Err("恢复剪贴板时锁定内存失败".to_owned());
    }
    std::ptr::copy_nonoverlapping(image.dib.as_ptr(), pointer, image.dib.len());
    let _ = GlobalUnlock(memory);
    if let Err(error) = SetClipboardData(image.format, Some(HANDLE(memory.0))) {
        let _ = GlobalFree(Some(memory));
        return Err(format!("恢复剪贴板失败: {error:?}"));
    }
    Ok(())
}

unsafe extern "system" fn listener_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_NCCREATE => {
            let create = lparam.0 as *const CREATESTRUCTW;
            if !create.is_null() {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*create).lpCreateParams as isize);
            }
            DefWindowProcW(hwnd, message, wparam, lparam)
        }
        WM_CLIPBOARDUPDATE => {
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut SyncSender<ClipboardImage>;
            if !ptr.is_null() {
                if let Some(image) = read_image() {
                    let _ = (*ptr).try_send(image);
                }
            }
            LRESULT(0)
        }
        WM_NCDESTROY => {
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut SyncSender<ClipboardImage>;
            if !ptr.is_null() {
                let _ = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                drop(Box::from_raw(ptr));
            }
            DefWindowProcW(hwnd, message, wparam, lparam)
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        commit_with_restore, is_non_image_registered_format, is_non_image_standard_format,
        validate_dib, ClipboardImage, CF_DIB,
    };

    #[test]
    fn standard_text_and_file_formats_are_rejected() {
        assert!(is_non_image_standard_format(super::CF_TEXT));
        assert!(is_non_image_standard_format(super::CF_OEMTEXT));
        assert!(is_non_image_standard_format(super::CF_UNICODETEXT));
        assert!(is_non_image_standard_format(super::CF_HDROP));
        assert!(!is_non_image_standard_format(super::CF_DIB));
        assert!(!is_non_image_standard_format(super::CF_DIBV5));
    }

    #[test]
    fn registered_text_and_object_formats_are_rejected() {
        assert!(is_non_image_registered_format("HTML Format"));
        assert!(is_non_image_registered_format("DataObject"));
        assert!(is_non_image_registered_format(
            "Chromium internal source URL"
        ));
        assert!(!is_non_image_registered_format("PNG"));
        assert!(!is_non_image_registered_format("image/png"));
    }

    #[test]
    fn dib_header_validation_rejects_malformed_data() {
        assert!(validate_dib(&[0u8; 39]).is_err());
        let mut dib = vec![0u8; 40];
        dib[0..4].copy_from_slice(&40u32.to_le_bytes());
        dib[4..8].copy_from_slice(&1920i32.to_le_bytes());
        dib[8..12].copy_from_slice(&1080i32.to_le_bytes());
        dib[12..14].copy_from_slice(&1u16.to_le_bytes());
        dib[14..16].copy_from_slice(&32u16.to_le_bytes());
        assert!(validate_dib(&dib).is_ok());
        dib[4..8].copy_from_slice(&0i32.to_le_bytes());
        assert!(validate_dib(&dib).is_err());
    }

    #[test]
    fn failed_clipboard_commit_invokes_backup_restore() {
        let image = ClipboardImage {
            format: CF_DIB,
            dib: vec![1, 2, 3],
        };
        let backup = ClipboardImage {
            format: CF_DIB,
            dib: vec![4, 5, 6],
        };
        let mut attempts = 0;
        let mut restored = None;
        let result = commit_with_restore(
            &image,
            Some(&backup),
            |_| {
                attempts += 1;
                Err("injected SetClipboardData failure".to_owned())
            },
            |previous| {
                restored = Some(previous.dib.clone());
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(attempts, 2);
        assert_eq!(restored, Some(vec![4, 5, 6]));
    }
}
