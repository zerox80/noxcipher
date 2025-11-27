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
        // Bug 4 Fix: Use Trace only in debug builds, Info in release
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
pub extern "system" fn Java_com_noxcipher_RustNative_unlockVolume(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    password: jbyteArray,
) -> jboolean {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Bug 8 Fix: Use get_byte_array_elements to access password bytes and explicitly zero them
        // This avoids relying on JNI copy behavior and ensures we can clear the memory.
        let password_bytes_guard = match env.get_byte_array_elements(password, jni::objects::ReleaseMode::NoCopyBack) {
            Ok(guard) => guard,
            Err(e) => {
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid password array: {}", e));
                return 0;
            }
        };
        
        // Convert to slice for usage
        let password_slice = unsafe { std::slice::from_raw_parts(password_bytes_guard.as_ptr() as *const u8, password_bytes_guard.len()) };

        log::info!("Attempting to unlock volume with fd: {}", fd);
        
        // Handle Mutex poisoning by recovering the lock
        let mut manager = match VOLUME_MANAGER.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::warn!("Mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        let result = manager.unlock(fd, password_slice);
        
        // Zero out the password bytes in memory (best effort)
        // We cast to *mut because we need to write, and we know we have access via the guard.
        // The guard gives us a pointer.
        unsafe {
            let ptr = password_bytes_guard.as_ptr();
            let len = password_bytes_guard.len();
            std::ptr::write_bytes(ptr, 0, len);
        }
        // Guard is dropped here, releasing the array (NoCopyBack means we don't copy back changes, 
        // but we zeroed the memory which might be the pinned original or a copy. 
        // If it's a copy, we cleared the copy. If pinned, we cleared the original.
        // To be safer, we should probably use CopyBack if we modified it? 
        // But we want to clear it. If we zeroed a copy, the original in Java heap is still there?
        // Java side clears its array. This is for the JNI copy.
        // If JNI made a copy, we zeroed the copy. Good.

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
            // Bug 3 Fix: Added safety comment explaining why this unsafe block is valid.
            // SAFETY: Casting &[u8] to &[i8] is safe because they have the same layout and size.
            // The slice is only used for reading and does not outlive 'content'.
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
