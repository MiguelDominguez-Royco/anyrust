use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::UdpSocket;

pub const DEFAULT_PORT: u16 = 7890;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetPacket {
    AuthRequest {
        pin: String,
        #[serde(default)]
        totp_code: String,
        client_name: String,
        scale_div: u32,
    },
    AuthResponse {
        accepted: bool,
        message: String,
        screen_width: u32,
        screen_height: u32,
        host_name: String,
    },
    VideoFrame {
        width: u32,
        height: u32,
        compressed_rgba: Vec<u8>,
    },
    MouseMove {
        norm_x: f32,
        norm_y: f32,
    },
    MouseClick {
        norm_x: f32,
        norm_y: f32,
        button: u8, // 0 = Izquierdo, 1 = Derecho, 2 = Central
        pressed: bool,
    },
    MouseWheel {
        delta_y: i32,
    },
    KeyPress {
        vk: u16,
    },
    KeyEvent {
        vk: u16,
        pressed: bool,
    },
    TextInput {
        text: String,
    },
    ChatMessage {
        sender: String,
        text: String,
        time: String,
    },
    ClipboardSync {
        text: String,
    },
    SetQuality {
        scale_div: u32,
    },
}

/// Obtiene la IP local de la red (ej. 192.168.x.x) y genera un ID numérico de 9 dígitos estilo AnyDesk
pub fn get_local_ip_and_id() -> (String, String) {
    let ip = UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    // Generar un ID estilo AnyDesk (XXX XXX XXX) basado en los octetos de la IP
    let parts: Vec<&str> = ip.split('.').collect();
    let id = if parts.len() == 4 {
        let a: u32 = parts[1].parse().unwrap_or(168);
        let b: u32 = parts[2].parse().unwrap_or(100);
        let c: u32 = parts[3].parse().unwrap_or(101);
        format!("{:03} {:03} {:03}", a, b, c)
    } else {
        "127 000 001".to_string()
    };

    (ip, id)
}

/// Convierte una entrada del usuario (ID de 9 dígitos o IP) en una dirección `IP:PUERTO`
pub fn resolve_target_address(input: &str, local_ip: &str) -> String {
    let trimmed = input.trim();
    if trimmed.contains(':') {
        return trimmed.to_string();
    }
    // Si escribió punto decimal (ej. 192.168.1.50 o localhost)
    if trimmed.contains('.') || trimmed.eq_ignore_ascii_case("localhost") {
        let host = if trimmed.eq_ignore_ascii_case("localhost") {
            "127.0.0.1"
        } else {
            trimmed
        };
        return format!("{}:{}", host, DEFAULT_PORT);
    }

    // Si escribió los 9 dígitos estilo AnyDesk (ej. "168 160 237" o "168160237")
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 9 {
        let first_octet = local_ip.split('.').next().unwrap_or("192");
        let o2: u32 = digits[0..3].parse().unwrap_or(168);
        let o3: u32 = digits[3..6].parse().unwrap_or(1);
        let o4: u32 = digits[6..9].parse().unwrap_or(1);
        return format!("{}.{}.{}.{}:{}", first_octet, o2, o3, o4, DEFAULT_PORT);
    }

    format!("{}:{}", trimmed, DEFAULT_PORT)
}

pub fn compress_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

pub fn decompress_bytes(compressed: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

#[cfg(windows)]
pub mod win_io {
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
        GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS,
        SRCCOPY,
    };
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        keybd_event, mouse_event, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT,
        KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
        MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP,
        MOUSEEVENTF_WHEEL,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetCursorPos, GetSystemMetrics, SetCursorPos, SM_CXSCREEN, SM_CYSCREEN,
    };
    use windows_sys::Win32::Foundation::POINT;

    pub fn get_screen_size() -> (u32, u32) {
        unsafe {
            let w = GetSystemMetrics(SM_CXSCREEN).max(1) as u32;
            let h = GetSystemMetrics(SM_CYSCREEN).max(1) as u32;
            (w, h)
        }
    }

    /// Captura la pantalla completa de Windows usando GDI `BitBlt` y la escala según `scale_div`
    pub fn capture_screen_rgba(scale_div: u32) -> Option<(u32, u32, Vec<u8>)> {
        let div = scale_div.clamp(1, 4);
        unsafe {
            let src_w = GetSystemMetrics(SM_CXSCREEN);
            let src_h = GetSystemMetrics(SM_CYSCREEN);
            if src_w <= 0 || src_h <= 0 {
                return None;
            }

            let hdc_screen = GetDC(0);
            if hdc_screen == 0 {
                return None;
            }
            let hdc_mem = CreateCompatibleDC(hdc_screen);
            let hbm = CreateCompatibleBitmap(hdc_screen, src_w, src_h);
            let old_obj = SelectObject(hdc_mem, hbm);

            let ok = BitBlt(hdc_mem, 0, 0, src_w, src_h, hdc_screen, 0, 0, SRCCOPY);
            if ok == 0 {
                SelectObject(hdc_mem, old_obj);
                DeleteObject(hbm);
                DeleteDC(hdc_mem);
                ReleaseDC(0, hdc_screen);
                return None;
            }

            let mut bmi = BITMAPINFO {
                bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: src_w,
                    biHeight: -src_h, // Top-down bitmap
                    biPlanes: 1,
                    biBitCount: 32,
                    biCompression: BI_RGB,
                    biSizeImage: 0,
                    biXPelsPerMeter: 0,
                    biYPelsPerMeter: 0,
                    biClrUsed: 0,
                    biClrImportant: 0,
                },
                bmiColors: [ std::mem::zeroed() ],
            };

            let total_pixels = (src_w as usize) * (src_h as usize);
            let mut bgra = vec![0u8; total_pixels * 4];

            GetDIBits(
                hdc_mem,
                hbm,
                0,
                src_h as u32,
                bgra.as_mut_ptr() as *mut _,
                &mut bmi,
                DIB_RGB_COLORS,
            );

            // Dibujar un pequeño indicador rojo/blanco donde está el cursor actual del host
            let mut cursor_pt = POINT { x: 0, y: 0 };
            if GetCursorPos(&mut cursor_pt) != 0 {
                let cx = cursor_pt.x;
                let cy = cursor_pt.y;
                for dy in -6..=6i32 {
                    for dx in -6..=6i32 {
                        if dx * dx + dy * dy <= 36 {
                            let px = cx + dx;
                            let py = cy + dy;
                            if px >= 0 && px < src_w && py >= 0 && py < src_h {
                                let idx = ((py as usize) * (src_w as usize) + (px as usize)) * 4;
                                bgra[idx] = 80;      // B
                                bgra[idx + 1] = 80;  // G
                                bgra[idx + 2] = 255; // R
                                bgra[idx + 3] = 255;
                            }
                        }
                    }
                }
            }

            SelectObject(hdc_mem, old_obj);
            DeleteObject(hbm);
            DeleteDC(hdc_mem);
            ReleaseDC(0, hdc_screen);

            let dst_w = (src_w as u32) / div;
            let dst_h = (src_h as u32) / div;
            let mut rgba = Vec::with_capacity((dst_w * dst_h * 4) as usize);

            for y in 0..dst_h {
                let sy = (y * div) as usize;
                let row_offset = sy * (src_w as usize) * 4;
                for x in 0..dst_w {
                    let sx = (x * div) as usize;
                    let idx = row_offset + sx * 4;
                    rgba.push(bgra[idx + 2]); // R
                    rgba.push(bgra[idx + 1]); // G
                    rgba.push(bgra[idx]);     // B
                    rgba.push(255);           // A
                }
            }

            Some((dst_w, dst_h, rgba))
        }
    }

    pub fn inject_mouse_move(norm_x: f32, norm_y: f32) {
        unsafe {
            let w = GetSystemMetrics(SM_CXSCREEN).max(1);
            let h = GetSystemMetrics(SM_CYSCREEN).max(1);
            let x = (norm_x.clamp(0.0, 1.0) * (w as f32)) as i32;
            let y = (norm_y.clamp(0.0, 1.0) * (h as f32)) as i32;
            SetCursorPos(x, y);
        }
    }

    pub fn inject_mouse_click(norm_x: f32, norm_y: f32, button: u8, pressed: bool) {
        inject_mouse_move(norm_x, norm_y);
        unsafe {
            let flag = match (button, pressed) {
                (0, true) => MOUSEEVENTF_LEFTDOWN,
                (0, false) => MOUSEEVENTF_LEFTUP,
                (1, true) => MOUSEEVENTF_RIGHTDOWN,
                (1, false) => MOUSEEVENTF_RIGHTUP,
                (2, true) => MOUSEEVENTF_MIDDLEDOWN,
                (2, false) => MOUSEEVENTF_MIDDLEUP,
                _ => return,
            };
            mouse_event(flag, 0, 0, 0, 0);
        }
    }

    pub fn inject_mouse_wheel(delta_y: i32) {
        unsafe {
            // En Windows, cada clic de rueda son 120 unidades (i32)
            mouse_event(MOUSEEVENTF_WHEEL, 0, 0, delta_y * 120, 0);
        }
    }

    pub fn inject_key_press(vk: u16) {
        unsafe {
            keybd_event(vk as u8, 0, 0, 0);
            keybd_event(vk as u8, 0, KEYEVENTF_KEYUP, 0);
        }
    }

    pub fn inject_key_event(vk: u16, pressed: bool) {
        unsafe {
            let flags = if pressed { 0 } else { KEYEVENTF_KEYUP };
            keybd_event(vk as u8, 0, flags, 0);
        }
    }

    pub fn inject_text(text: &str) {
        for c in text.encode_utf16() {
            unsafe {
                let mut inputs = [
                    INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wVk: 0,
                                wScan: c,
                                dwFlags: KEYEVENTF_UNICODE,
                                time: 0,
                                dwExtraInfo: 0,
                            },
                        },
                    },
                    INPUT {
                        r#type: INPUT_KEYBOARD,
                        Anonymous: INPUT_0 {
                            ki: KEYBDINPUT {
                                wVk: 0,
                                wScan: c,
                                dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                                time: 0,
                                dwExtraInfo: 0,
                            },
                        },
                    },
                ];
                SendInput(
                    inputs.len() as u32,
                    inputs.as_mut_ptr(),
                    std::mem::size_of::<INPUT>() as i32,
                );
            }
        }
    }
}

#[cfg(not(windows))]
pub mod win_io {
    pub fn get_screen_size() -> (u32, u32) {
        (1280, 720)
    }

    pub fn capture_screen_rgba(scale_div: u32) -> Option<(u32, u32, Vec<u8>)> {
        let div = scale_div.clamp(1, 4);
        let w = 1280 / div;
        let h = 720 / div;
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for y in 0..h {
            for x in 0..w {
                rgba.push(((x * 255) / w.max(1)) as u8);
                rgba.push(((y * 255) / h.max(1)) as u8);
                rgba.push(46);
                rgba.push(255);
            }
        }
        Some((w, h, rgba))
    }

    pub fn inject_mouse_move(_norm_x: f32, _norm_y: f32) {}
    pub fn inject_mouse_click(_norm_x: f32, _norm_y: f32, _button: u8, _pressed: bool) {}
    pub fn inject_mouse_wheel(_delta_y: i32) {}
    pub fn inject_key_press(_vk: u16) {}
    pub fn inject_key_event(_vk: u16, _pressed: bool) {}
    pub fn inject_text(_text: &str) {}
}

