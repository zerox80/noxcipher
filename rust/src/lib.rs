use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jobjectArray, jbyteArray};
use android_logger::Config;
use log::LevelFilter;

mod volume;
use volume::VOLUME_MANAGER;

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_initLogger(
    _env: JNIEnv,
    _class: JClass,
) {
    android_logger::init_once(
        Config::default().with_max_level(LevelFilter::Trace),
    );
    log::info!("Rust logger initialized");
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_unlockVolume(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    password: JString,
) -> jboolean {
    let password: String = match env.get_string(&password) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid password string: {}", e));
            return 0;
        }
    };
    
    log::info!("Attempting to unlock volume with fd: {}", fd);
    
    // Handle Mutex poisoning by recovering the lock
    let mut manager = VOLUME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    match manager.unlock(fd, &password) {
        Ok(_) => 1,
        Err(e) => {
            log::error!("Unlock failed: {}", e);
            // We throw an exception so the UI knows WHY it failed
            let _ = env.throw_new("java/io/IOException", format!("Unlock failed: {}", e));
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
    let path: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid path string: {}", e));
            return std::ptr::null_mut();
        }
    };

    let manager = VOLUME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
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
        // Fix: Delete local reference to prevent JNI table overflow
        let _ = env.delete_local_ref(file_string);
    }

    array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_readFile(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
    offset: jni::sys::jlong,
    length: jint,
) -> jbyteArray {
    let path: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(e) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid path string: {}", e));
            return std::ptr::null_mut();
        }
    };

    let manager = VOLUME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    let content = match manager.read_file(&path, offset as u64, length as usize) {
        Ok(c) => c,
        Err(e) => {
            let _ = env.throw_new("java/io/IOException", format!("Failed to read file: {}", e));
            return std::ptr::null_mut();
        }
    };

    let byte_array = match env.byte_array_from_slice(&content) {
        Ok(arr) => arr,
        Err(e) => {
            let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to create byte array: {}", e));
            return std::ptr::null_mut();
        }
    };
    byte_array.into_raw()
}
