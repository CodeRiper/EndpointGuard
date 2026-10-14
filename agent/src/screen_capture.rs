//! Real DirectX / Win32 GDI Desktop Screen Capture for EndpointGuard.
//!
//! Captures the physical display frame of the Windows host desktop and
//! encodes it into JPEG bytes using `jpeg-encoder`.
//! Attaches to `WinSta0\Default` to ensure access across service or console sessions.

use anyhow::{anyhow, Result};

#[cfg(windows)]
pub fn capture_desktop_jpeg(quality: u8) -> Result<Vec<u8>> {
    use windows::Win32::Foundation::RECT;
    use windows::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject,
        GetDC, GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER,
        BI_RGB, DIB_RGB_COLORS, SRCCOPY,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetDesktopWindow, GetSystemMetrics, GetWindowRect, SM_CXSCREEN, SM_CYSCREEN,
    };

    #[link(name = "user32")]
    extern "system" {
        fn OpenWindowStationA(name: *const u8, inherit: i32, access: u32) -> isize;
        fn SetProcessWindowStation(hwinsta: isize) -> i32;
        fn OpenDesktopA(name: *const u8, flags: u32, inherit: i32, access: u32) -> isize;
        fn SetThreadDesktop(hdesktop: isize) -> i32;
    }

    unsafe {
        // Ensure connection to interactive window station and desktop once
        static ATTACHED_DESKTOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !ATTACHED_DESKTOP.load(std::sync::atomic::Ordering::Relaxed) {
            let winsta = OpenWindowStationA(b"WinSta0\0".as_ptr(), 0, 0x037F);
            if winsta != 0 {
                let _ = SetProcessWindowStation(winsta);
            }
            let desk = OpenDesktopA(b"Default\0".as_ptr(), 0, 0, 0x01FF);
            if desk != 0 {
                let _ = SetThreadDesktop(desk);
            }
            ATTACHED_DESKTOP.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        let mut width = GetSystemMetrics(SM_CXSCREEN);
        let mut height = GetSystemMetrics(SM_CYSCREEN);

        let hwnd_target = windows::Win32::Foundation::HWND(0);
        let mut hdc_src = GetDC(hwnd_target);
        if hdc_src.is_invalid() {
            let hwnd_desk = GetDesktopWindow();
            hdc_src = GetDC(hwnd_desk);
        }
        if hdc_src.is_invalid() {
            return Err(anyhow!("Failed to acquire screen device context GetDC"));
        }

        if width <= 0 || height <= 0 {
            let hwnd_desk = GetDesktopWindow();
            let mut rect = RECT::default();
            let _ = GetWindowRect(hwnd_desk, &mut rect);
            width = (rect.right - rect.left).max(1280);
            height = (rect.bottom - rect.top).max(720);
        }

        let hdc_mem = CreateCompatibleDC(hdc_src);
        if hdc_mem.is_invalid() {
            ReleaseDC(hwnd_target, hdc_src);
            return Err(anyhow!("Failed to create compatible memory DC"));
        }

        let hbitmap = CreateCompatibleBitmap(hdc_src, width, height);
        if hbitmap.is_invalid() {
            let _ = DeleteDC(hdc_mem);
            ReleaseDC(hwnd_target, hdc_src);
            return Err(anyhow!("Failed to create compatible bitmap {}x{}", width, height));
        }

        let old_obj = SelectObject(hdc_mem, hbitmap);

        let blt_res = BitBlt(hdc_mem, 0, 0, width, height, hdc_src, 0, 0, SRCCOPY);
        if blt_res.is_err() {
            SelectObject(hdc_mem, old_obj);
            let _ = DeleteObject(hbitmap);
            let _ = DeleteDC(hdc_mem);
            ReleaseDC(hwnd_target, hdc_src);
            return Err(anyhow!("BitBlt screen copy failed"));
        }

        let mut bi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width,
                biHeight: -height, // negative = top-down bitmap
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };

        let mut raw_pixels = vec![0u8; (width * height * 4) as usize];
        let scanlines = GetDIBits(
            hdc_mem,
            hbitmap,
            0,
            height as u32,
            Some(raw_pixels.as_mut_ptr() as _),
            &mut bi,
            DIB_RGB_COLORS,
        );

        // Clean up GDI resources
        SelectObject(hdc_mem, old_obj);
        let _ = DeleteObject(hbitmap);
        let _ = DeleteDC(hdc_mem);
        ReleaseDC(hwnd_target, hdc_src);

        if scanlines == 0 {
            return Err(anyhow!("GetDIBits failed to copy pixel data"));
        }

        // Encode to JPEG using jpeg-encoder (ColorType::Bgra)
        let mut jpeg_buf = Vec::with_capacity(128 * 1024);
        let encoder = jpeg_encoder::Encoder::new(&mut jpeg_buf, quality.clamp(10, 95));
        encoder.encode(
            &raw_pixels,
            width as u16,
            height as u16,
            jpeg_encoder::ColorType::Bgra,
        )?;

        Ok(jpeg_buf)
    }
}

#[cfg(not(windows))]
pub fn capture_desktop_jpeg(_quality: u8) -> Result<Vec<u8>> {
    Err(anyhow!("Screen capture is only supported on Windows"))
}
