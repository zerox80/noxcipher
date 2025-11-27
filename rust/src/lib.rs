use jni::JNIEnv;
use jni::objects::{JClass, JByteArray};
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
    pim: jni::sys::jint,
) -> jlong {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let password_obj = unsafe { JByteArray::from_raw(password) };
        let password_bytes = match env.convert_byte_array(&password_obj) {
            Ok(b) => b,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid password array: {}", e));
                return -1;
            }
        };

        let header_obj = unsafe { JByteArray::from_raw(header) };
        let header_bytes = match env.convert_byte_array(&header_obj) {
            Ok(b) => b,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid header array: {}", e));
                return -1;
            }
        };

        match volume::create_context(&password_bytes, &header_bytes, pim as i32) {
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
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    offset: jlong,
    data: jbyteArray,
) {
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let data_obj = unsafe { JByteArray::from_raw(data) };
        let len = match env.get_array_length(&data_obj) {
            Ok(l) => l,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get array length: {}", e));
                return;
            }
        };

        let mut buf = vec![0u8; len as usize];
        if let Err(e) = env.get_byte_array_region(data, 0, &mut buf) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read array: {}", e));
             return;
        }

        if let Err(e) = volume::decrypt(handle, offset as u64, &mut buf) {
             let _ = env.throw_new("java/io/IOException", format!("Decrypt failed: {}", e));
             return;
        }

        // Write back
        if let Err(e) = env.set_byte_array_region(data, 0, &buf) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to write back array: {}", e));
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_encrypt(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    offset: jlong,
    data: jbyteArray,
) {
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let data_obj = unsafe { JByteArray::from_raw(data) };
        let len = match env.get_array_length(&data_obj) {
            Ok(l) => l,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get array length: {}", e));
                return;
            }
        };

        let mut buf = vec![0u8; len as usize];
        if let Err(e) = env.get_byte_array_region(data, 0, &mut buf) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read array: {}", e));
             return;
        }

        if let Err(e) = volume::encrypt(handle, offset as u64, &mut buf) {
             let _ = env.throw_new("java/io/IOException", format!("Encrypt failed: {}", e));
             return;
        }

        // Write back
        if let Err(e) = env.set_byte_array_region(data, 0, &buf) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to write back array: {}", e));
        }
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
