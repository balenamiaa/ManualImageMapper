#[link(name = "user32")]
extern "system" {
    fn MessageBoxA(hwnd: usize, text: *const i8, caption: *const i8, utype: u32) -> i32;
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_hinst: *mut u8, reason: u32, _reserved: *mut u8) -> i32 {
    if reason == 1 {
        unsafe {
            MessageBoxA(
                0,
                b"CRT Init OK!\0".as_ptr() as *const i8,
                b"Test\0".as_ptr() as *const i8,
                0,
            );
        }
    }
    1
}
