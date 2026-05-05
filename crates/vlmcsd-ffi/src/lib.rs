use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use vlmcsd_kmsdata::KmsData;
use vlmcsd_network::{ServerConfig, run_server};
use vlmcsd_protocol::{create_response_v4, create_response_v6};

const LIB_VERSION: c_int = 0x40000;

static ERROR_MSG: OnceLock<Mutex<CString>> = OnceLock::new();
static SERVER_HANDLE: OnceLock<Mutex<Option<ServerState>>> = OnceLock::new();

struct ServerState {
    _thread: std::thread::JoinHandle<()>,
}

fn set_error(msg: &str) {
    let mutex = ERROR_MSG.get_or_init(|| Mutex::new(CString::default()));
    if let Ok(mut lock) = mutex.lock() {
        *lock = CString::new(msg).unwrap_or_default();
    }
}

fn clear_error() {
    set_error("");
}

/// Returns the library version as an integer.
#[unsafe(no_mangle)]
pub extern "C" fn vlmcsd_get_version() -> c_int {
    LIB_VERSION
}

/// Returns a pointer to a null-terminated version string.
#[unsafe(no_mangle)]
pub extern "C" fn vlmcsd_get_emulator_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    let s = VERSION.get_or_init(|| {
        CString::new(format!("vlmcsd-rs {}", env!("CARGO_PKG_VERSION"))).unwrap()
    });
    s.as_ptr()
}

/// Returns a pointer to the last error message.
#[unsafe(no_mangle)]
pub extern "C" fn vlmcsd_get_error_message() -> *const c_char {
    let mutex = ERROR_MSG.get_or_init(|| Mutex::new(CString::default()));
    if let Ok(lock) = mutex.lock() {
        lock.as_ptr()
    } else {
        ptr::null()
    }
}

/// Starts the KMS server on the given port in a background thread.
/// Returns 0 on success, non-zero on error.
#[unsafe(no_mangle)]
pub extern "C" fn vlmcsd_start_server(port: c_int) -> u32 {
    clear_error();

    let state_mutex = SERVER_HANDLE.get_or_init(|| Mutex::new(None));
    let mut state = match state_mutex.lock() {
        Ok(s) => s,
        Err(_) => {
            set_error("lock poisoned");
            return 1;
        }
    };

    if state.is_some() {
        set_error("server already started");
        return 1;
    }

    let listen_addr = format!("0.0.0.0:{}", port);
    let config = ServerConfig {
        listen_addr,
        timeout: Duration::from_secs(30),
    };

    let kms_data = Arc::new(KmsData::load_embedded());

    let thread = std::thread::spawn(move || {
        if let Err(e) = run_server(&config, kms_data) {
            eprintln!("Server error: {}", e);
        }
    });

    *state = Some(ServerState { _thread: thread });
    0
}

/// Stops the KMS server.
/// Returns 0 on success.
#[unsafe(no_mangle)]
pub extern "C" fn vlmcsd_stop_server() -> u32 {
    clear_error();

    let state_mutex = SERVER_HANDLE.get_or_init(|| Mutex::new(None));
    let mut state = match state_mutex.lock() {
        Ok(s) => s,
        Err(_) => {
            set_error("lock poisoned");
            return 1;
        }
    };

    if state.is_none() {
        set_error("server not started");
        return 1;
    }

    *state = None;
    0
}

/// Processes a raw KMS request and returns a raw KMS response.
///
/// `response_data` receives a pointer to the allocated response (caller must free with `vlmcsd_free`).
/// `response_len` receives the length of the response.
///
/// Returns 0 on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vlmcsd_process_request(
    request_data: *const u8,
    request_len: usize,
    response_data: *mut *mut u8,
    response_len: *mut usize,
) -> u32 {
    clear_error();

    if request_data.is_null() || response_data.is_null() || response_len.is_null() {
        set_error("null pointer argument");
        return 1;
    }

    let input = unsafe { std::slice::from_raw_parts(request_data, request_len) };

    if input.len() < 4 {
        set_error("request too short");
        return 0x8007000D;
    }

    let kms_data = KmsData::load_embedded();

    let version = u32::from_le_bytes(input[0..4].try_into().unwrap());
    let major_ver = (version >> 16) as u16;

    let result = match major_ver {
        4 => create_response_v4(input, &kms_data),
        5 | 6 => create_response_v6(input, &kms_data),
        _ => {
            set_error("unsupported KMS version");
            return 0x8007000D;
        }
    };

    match result {
        Ok(resp) => {
            let len = resp.len();
            let ptr = Box::into_raw(resp.into_boxed_slice()) as *mut u8;
            unsafe {
                *response_data = ptr;
                *response_len = len;
            }
            0
        }
        Err(code) => {
            set_error(&format!("request processing failed: 0x{:08X}", code));
            code
        }
    }
}

/// Frees memory allocated by vlmcsd FFI functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vlmcsd_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let _ = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(ptr, len)) };
    }
}

/// Returns the number of available SKU products in the embedded database.
#[unsafe(no_mangle)]
pub extern "C" fn vlmcsd_get_product_count() -> c_int {
    let kms_data = KmsData::load_embedded();
    kms_data.sku_items.len() as c_int
}

/// Gets the name of a product by index (0-based).
/// Caller must free the returned string with `vlmcsd_free_string`.
#[unsafe(no_mangle)]
pub extern "C" fn vlmcsd_get_product_name(index: c_int) -> *mut c_char {
    let kms_data = KmsData::load_embedded();
    let idx = index as usize;

    if idx >= kms_data.sku_items.len() {
        return ptr::null_mut();
    }

    let name = kms_data.get_string(kms_data.sku_items[idx].name_offset);
    match CString::new(name) {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Frees a string returned by vlmcsd FFI functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vlmcsd_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = unsafe { CString::from_raw(ptr) };
    }
}
