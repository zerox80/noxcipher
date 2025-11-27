use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jobjectArray, jbyteArray};
use android_logger::Config;
use log::LevelFilter;
use std::panic;

mod volume;
use volume::VOLUME_MANAGER;

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_initLogger(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = panic::catch_unwind(|| {
        android_logger::init_once(
            Config::default().with_max_level(LevelFilter::Trace),
        );
        log::info!("Rust logger initialized");
    });
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_unlockVolume(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    password: jbyteArray,
) -> jboolean {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let password_bytes = match env.convert_byte_array(password) {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid password array: {}", e));
                return 0;
            }
        };
        
        log::info!("Attempting to unlock volume with fd: {}", fd);
        
        // Handle Mutex poisoning by recovering the lock
        let mut manager = match VOLUME_MANAGER.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::warn!("Mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let result = manager.unlock(fd, &password_bytes);
        
        // Zero out the password bytes in memory (best effort)
        let mut password_bytes = password_bytes;
        for byte in password_bytes.iter_mut() {
            *byte = 0;
        }

        match result {
            Ok(_) => 1,
            Err(e) => {
                log::error!("Unlock failed: {}", e);
                // Throw exception on failure instead of just returning false
                let _ = env.throw_new("java/io/IOException", format!("Unlock failed: {}", e));
                0
            }
        }
    }));

    match result {
        Ok(val) => val,
        Err(_) => {
            log::error!("Panic in unlockVolume");
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_listFiles(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jobjectArray {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let path: String = match env.get_string(&path) {
            Ok(s) => s.into(),
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid path string: {}", e));
                return std::ptr::null_mut();
            }
        };

        let manager = match VOLUME_MANAGER.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::warn!("Mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let files = match manager.list_files(&path) {
            Ok(f) => f,
            Err(e) => {
                let _ = env.throw_new("java/io/IOException", format!("Failed to list files: {}", e));
                return std::ptr::null_mut();
            }
        };

        let string_class = match env.find_class("java/lang/String") {
            Ok(c) => c,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Could not find String class: {}", e));
                return std::ptr::null_mut();
            }
        };
        let empty_string = match env.new_string("") {
            Ok(s) => s,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Could not create empty string: {}", e));
                return std::ptr::null_mut();
            }
        };
        
        let array = match env.new_object_array(files.len() as i32, string_class, empty_string) {
            Ok(a) => a,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Could not create string array: {}", e));
                return std::ptr::null_mut();
            }
        };

        for (i, file) in files.iter().enumerate() {
            let file_string = match env.new_string(file) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("Could not create string for file {}: {}", file, e);
                    continue;
                }
            };
            if let Err(e) = env.set_object_array_element(&array, i as i32, file_string) {
                log::error!("Could not set array element {}: {}", i, e);
            }
            let _ = env.delete_local_ref(file_string);
        }

        array.into_raw()
    }));

    match result {
        Ok(val) => val,
        Err(_) => {
            log::error!("Panic in listFiles");
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_readFile(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    offset: jni::sys::jlong,
    buffer: jbyteArray,
) -> jint {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if offset < 0 {
             let _ = env.throw_new("java/lang/IllegalArgumentException", "Offset cannot be negative");
             return -1;
        }

        let path: String = match env.get_string(&path) {
            Ok(s) => s.into(),
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid path string: {}", e));
                return -1;
            }
        };

        let buffer_len = match env.get_array_length(buffer) {
            Ok(len) => len,
            Err(e) => {
                 let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get buffer length: {}", e));
                 return -1;
            }
        };

        let manager = match VOLUME_MANAGER.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::warn!("Mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        
        let content = match manager.read_file(&path, offset as u64, buffer_len as usize) {
            Ok(c) => c,
            Err(e) => {
                let _ = env.throw_new("java/io/IOException", format!("Failed to read file: {}", e));
                return -1;
            }
        };

        if !content.is_empty() {
            // Convert &[u8] to &[i8] (jbyte)
            let content_i8 = unsafe { std::slice::from_raw_parts(content.as_ptr() as *const i8, content.len()) };
            if let Err(e) = env.set_byte_array_region(buffer, 0, content_i8) {
                 let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to copy to buffer: {}", e));
                 return -1;
            }
        }

        content.len() as jint
    }));

    match result {
        Ok(val) => val,
        Err(_) => {
            log::error!("Panic in readFile");
            -1
        }
    }
}
