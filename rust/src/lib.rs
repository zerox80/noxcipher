use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::{jbyteArray, jlong};
use android_logger::Config;
use log::LevelFilter;
use std::panic;

mod volume;

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_initLogger(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = panic::catch_unwind(|| {
        #[cfg(debug_assertions)]
        let level = LevelFilter::Trace;
        #[cfg(not(debug_assertions))]
        let level = LevelFilter::Info;

        android_logger::init_once(
            Config::default().with_max_level(level),
        );
        log::info!("Rust logger initialized");
    });
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_init(
    mut env: JNIEnv,
    _class: JClass,
    password: jbyteArray,
    header: jbyteArray,
) -> jlong {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let password_bytes = match env.convert_byte_array(password) {
            Ok(b) => b,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid password array: {}", e));
                return -1;
            }
        };

        let header_bytes = match env.convert_byte_array(header) {
            Ok(b) => b,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid header array: {}", e));
                return -1;
            }
        };

        match volume::create_context(&password_bytes, &header_bytes) {
            Ok(handle) => handle,
            Err(e) => {
                log::error!("Init failed: {}", e);
                let _ = env.throw_new("java/io/IOException", format!("Init failed: {}", e));
                -1
            }
        }
    }));

    match result {
        Ok(val) => val,
        Err(_) => {
            log::error!("Panic in init");
            -1
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_decrypt(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    offset: jlong,
    data: jbyteArray,
) {
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // We need to modify the data in place.
        // Get primitives with Critical or standard? Standard is fine for now.
        // But we need to write back.
        // `get_byte_array_elements` gives us a pointer.
        
        let data_array = match env.get_byte_array_elements(data, jni::objects::ReleaseMode::CopyBack) {
            Ok(a) => a,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get data array: {}", e));
                return;
            }
        };

        // Convert to mutable slice
        let len = data_array.len();
        let ptr = data_array.as_ptr() as *mut u8;
        let data_slice = unsafe { std::slice::from_raw_parts_mut(ptr, len) };

        if let Err(e) = volume::decrypt(handle, offset as u64, data_slice) {
             let _ = env.throw_new("java/io/IOException", format!("Decrypt failed: {}", e));
        }
        
        // data_array is dropped here, triggering CopyBack
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_close(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    let _ = panic::catch_unwind(|| {
        volume::close_context(handle);
    });
}
