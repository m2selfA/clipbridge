#![cfg(windows)]

use std::{sync::mpsc::Sender, thread};

use serde::{Deserialize, Serialize};
use windows::core::w;
use windows::Win32::Foundation::{
    GlobalFree, HANDLE, HGLOBAL, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::DataExchange::{
    AddClipboardFormatListener, CloseClipboard, EmptyClipboard, GetClipboardData,
    IsClipboardFormatAvailable, OpenClipboard, RemoveClipboardFormatListener, SetClipboardData,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, GetWindowLongPtrW,
    RegisterClassExW, SetWindowLongPtrW, TranslateMessage, CREATESTRUCTW, GWLP_USERDATA,
    HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLIPBOARDUPDATE, WM_NCCREATE,
    WM_NCDESTROY, WNDCLASSEXW,
};

pub const CF_DIB: u32 = 8;
pub const CF_DIBV5: u32 = 17;
pub const MAX_CLIPBOARD_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClipboardImage {
    pub format: u32,
    pub dib: Vec<u8>,
}

pub fn spawn_listener(tx: Sender<ClipboardImage>) -> thread::JoinHandle<()> {
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

            if let Err(error) = AddClipboardFormatListener(hwnd) {
                eprintln!("注册剪贴板监听失败: {error:?}");
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
            let _ = windows::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd);
        })
        .expect("无法创建剪贴板监听线程")
}

pub fn read_image() -> Option<ClipboardImage> {
    unsafe {
        OpenClipboard(None).ok()?;
        let result = read_image_open().ok();
        let _ = CloseClipboard();
        result
    }
}

pub fn write_image(image: &ClipboardImage) -> Result<(), String> {
    if image.dib.is_empty() || image.dib.len() > MAX_CLIPBOARD_BYTES {
        return Err("剪贴板图片大小无效".to_owned());
    }

    unsafe {
        OpenClipboard(None).map_err(|error| format!("打开剪贴板失败: {error:?}"))?;
        let result = write_image_open(image);
        let _ = CloseClipboard();
        result
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
    Ok(ClipboardImage { format, dib: data })
}

unsafe fn write_image_open(image: &ClipboardImage) -> Result<(), String> {
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
    if let Err(error) = SetClipboardData(image.format, Some(HANDLE(memory.0))) {
        let _ = GlobalFree(Some(memory));
        return Err(format!("写入剪贴板失败: {error:?}"));
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
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Sender<ClipboardImage>;
            if !ptr.is_null() {
                if let Some(image) = read_image() {
                    let _ = (*ptr).send(image);
                }
            }
            LRESULT(0)
        }
        WM_NCDESTROY => {
            let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Sender<ClipboardImage>;
            if !ptr.is_null() {
                let _ = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                drop(Box::from_raw(ptr));
            }
            DefWindowProcW(hwnd, message, wparam, lparam)
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}
