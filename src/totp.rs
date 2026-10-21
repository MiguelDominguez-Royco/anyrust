//! Implementación nativa y ligera de TOTP (RFC 6238 / RFC 4226)
//! Compatible con Google Authenticator, Microsoft Authenticator, Authy y 1Password.

use std::time::SystemTime;

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha1(key);
        k[..20].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner_msg = ipad.to_vec();
    inner_msg.extend_from_slice(message);
    let inner_hash = sha1(&inner_msg);

    let mut outer_msg = opad.to_vec();
    outer_msg.extend_from_slice(&inner_hash);
    sha1(&outer_msg)
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut bit_count = 0;
    let mut out = Vec::new();

    for c in s.chars() {
        if c == '=' || c.is_whitespace() || c == '-' {
            continue;
        }
        let val = match c.to_ascii_uppercase() {
            'A'..='Z' => (c as u8 - b'A') as u32,
            '2'..='7' => (c as u8 - b'2' + 26) as u32,
            _ => return None,
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
            bits &= (1 << bit_count) - 1;
        }
    }
    Some(out)
}

pub fn generate_totp_code(secret_base32: &str, unix_timestamp: u64) -> Option<String> {
    let key = base32_decode(secret_base32)?;
    let time_step = unix_timestamp / 30;
    let hmac = hmac_sha1(&key, &time_step.to_be_bytes());

    let offset = (hmac[19] & 0x0f) as usize;
    let binary = ((hmac[offset] & 0x7f) as u32) << 24
        | ((hmac[offset + 1] as u32) << 16)
        | ((hmac[offset + 2] as u32) << 8)
        | (hmac[offset + 3] as u32);

    let otp = binary % 1_000_000;
    Some(format!("{:06}", otp))
}

pub fn verify_totp(secret_base32: &str, code: &str, unix_timestamp: u64) -> bool {
    let clean_code = code.trim().replace(' ', "");
    if clean_code.len() != 6 {
        return false;
    }
    // Acepta ventana actual y +/- 30 segundos por desfasaje de reloj
    for offset in [-1i64, 0, 1] {
        let t = (unix_timestamp as i64 + offset * 30).max(0) as u64;
        if let Some(expected) = generate_totp_code(secret_base32, t) {
            if expected == clean_code {
                return true;
            }
        }
    }
    false
}

pub fn generate_random_secret() -> String {
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(123456789);
    let mut s = String::with_capacity(16);
    let mut state = now;
    for _ in 0..16 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = ((state >> 32) as usize) % chars.len();
        s.push(chars[idx] as char);
    }
    s
}

pub fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Genera una imagen ColorImage de egui con el código QR y un margen blanco óptimo para escaneo con cámara
pub fn generate_qr_image(content: &str) -> Option<eframe::egui::ColorImage> {
    let code = qrcode::QrCode::new(content.as_bytes()).ok()?;
    let border = 2;
    let qr_width = code.width();
    let total_width = qr_width + border * 2;
    let mut pixels = vec![eframe::egui::Color32::WHITE; total_width * total_width];

    let colors = code.to_colors();
    for y in 0..qr_width {
        for x in 0..qr_width {
            let color = colors[y * qr_width + x];
            let px = x + border;
            let py = y + border;
            let idx = py * total_width + px;
            if color == qrcode::Color::Dark {
                pixels[idx] = eframe::egui::Color32::BLACK;
            } else {
                pixels[idx] = eframe::egui::Color32::WHITE;
            }
        }
    }

    Some(eframe::egui::ColorImage {
        size: [total_width, total_width],
        pixels,
    })
}
