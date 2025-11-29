use jni::JNIEnv;
use jni::objects::{JClass, JByteArray};
use jni::sys::{jbyteArray, jlong};

use log::LevelFilter;
use std::panic;

mod volume;
mod crypto;
mod header;
mod io_callback;
mod filesystem;

use filesystem::{SupportedFileSystem, DecryptedReader};
use io_callback::CallbackReader;
use ntfs::Ntfs;
use exfat::ExFat;
use jni::objects::JValue;

use std::sync::Mutex;
use lazy_static::lazy_static;

use jni::sys::jobjectArray;

lazy_static! {
    static ref LOG_BUFFER: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static ref FILESYSTEMS: Mutex<std::collections::HashMap<i64, SupportedFileSystem>> = Mutex::new(std::collections::HashMap::new());
    static ref NEXT_FS_HANDLE: Mutex<i64> = Mutex::new(1);
}

struct InMemoryLogger;

impl log::Log for InMemoryLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let log_msg = format!("{}: {}", record.level(), record.args());
            
            // Print to Android Logcat
            let _tag = std::ffi::CString::new("RustNative").unwrap();
            let _msg = std::ffi::CString::new(log_msg.clone()).unwrap();
            // Simple android logging via FFI if possible, or just rely on println! which often redirects
            // But since we can't easily link android log without crate, let's just store it.
            // Actually android_logger does this. We can't chain loggers easily without a helper crate.
            // For now, we prioritize the in-memory buffer for the user.
            
            // Store in buffer
            if let Ok(mut buffer) = LOG_BUFFER.lock() {
                if buffer.len() > 100 { buffer.remove(0); } // Keep last 100 logs
                buffer.push(log_msg);
            }
        }
    }

    fn flush(&self) {}
}

static LOGGER: InMemoryLogger = InMemoryLogger;

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_initLogger(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = panic::catch_unwind(|| {
        log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info)).ok();
        log::info!("Rust logger initialized (InMemory)");
    });
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_getLogs(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    let logs = match LOG_BUFFER.lock() {
        Ok(buffer) => buffer.clone(),
        Err(_) => vec!["Failed to lock log buffer".to_string()],
    };

    let string_class = env.find_class("java/lang/String").expect("Could not find String class");
    let empty_string = env.new_string("").expect("Could not create empty string");
    
    let array = env.new_object_array(logs.len() as i32, string_class, empty_string).expect("Could not create string array");

    for (i, log) in logs.iter().enumerate() {
        let jstr = env.new_string(log).expect("Could not create string");
        env.set_object_array_element(&array, i as i32, jstr).expect("Could not set array element");
    }

    array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_init(
    mut env: JNIEnv,
    _class: JClass,
    password: jbyteArray,
    header: jbyteArray,
    pim: jni::sys::jint,
    partition_offset: jlong,
    protection_password: jbyteArray,
    protection_pim: jni::sys::jint,
) -> jlong {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        log::info!("Rust init called");
        let password_obj = unsafe { JByteArray::from_raw(password) };
        let mut password_bytes = match env.convert_byte_array(&password_obj) {
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

        // Handle protection password
        let mut protection_password_bytes = if !protection_password.is_null() {
             let prot_obj = unsafe { JByteArray::from_raw(protection_password) };
             match env.convert_byte_array(&prot_obj) {
                Ok(b) => Some(b),
                Err(e) => {
                    log::warn!("Invalid protection password array: {}", e);
                    None
                }
             }
        } else {
            None
        };

        let res = volume::create_context(
            &password_bytes, 
            &header_bytes, 
            pim as i32, 
            partition_offset as u64,
            protection_password_bytes.as_deref(),
            protection_pim as i32
        );
        
        // Zeroize passwords
        use zeroize::Zeroize;
        password_bytes.zeroize();
        if let Some(ref mut pp) = protection_password_bytes {
            pp.zeroize();
        }
        
        match res {
            Ok(handle) => {
                log::info!("Init success, handle: {}", handle);
                handle
            },
            Err(e) => {
                log::error!("Init failed: {}", e);
                let _ = env.throw_new("java/io/IOException", format!("Init failed: {}", e));
                -1
            }
        }
    }));

    match result {
        Ok(val) => val,
        Err(e) => {
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                format!("Panic in init: {}", s)
            } else if let Some(s) = e.downcast_ref::<String>() {
                format!("Panic in init: {}", s)
            } else {
                "Panic in init: unknown cause".to_string()
            };
            log::error!("{}", msg);
            let _ = env.throw_new("java/lang/RuntimeException", msg);
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
        let data_obj = unsafe { JByteArray::from_raw(data) };
        let len = match env.get_array_length(&data_obj) {
            Ok(l) => l,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get array length: {}", e));
                return;
            }
        };

        let mut buf = vec![0u8; len as usize];
        // Cast u8 buffer to i8 for JNI
        let buf_ptr = buf.as_mut_ptr() as *mut i8;
        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf_ptr, len as usize) };

        if let Err(e) = env.get_byte_array_region(&data_obj, 0, buf_slice) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read array: {}", e));
             return;
        }

        if let Err(e) = volume::decrypt(handle, offset as u64, &mut buf) {
             let _ = env.throw_new("java/io/IOException", format!("Decrypt failed: {}", e));
             return;
        }

        // Write back
        // Cast u8 buffer to i8 for JNI
        let buf_ptr = buf.as_ptr() as *const i8;
        let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, len as usize) };

        if let Err(e) = env.set_byte_array_region(&data_obj, 0, buf_slice) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to write back array: {}", e));
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_encrypt(
    mut env: JNIEnv,
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
        // Cast u8 buffer to i8 for JNI
        let buf_ptr = buf.as_mut_ptr() as *mut i8;
        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf_ptr, len as usize) };
        
        if let Err(e) = env.get_byte_array_region(&data_obj, 0, buf_slice) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read array: {}", e));
             return;
        }

        if let Err(e) = volume::encrypt(handle, offset as u64, &mut buf) {
             let _ = env.throw_new("java/io/IOException", format!("Encrypt failed: {}", e));
             return;
        }

        // Write back
        // Cast u8 buffer to i8 for JNI
        let buf_ptr = buf.as_ptr() as *const i8;
        let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, len as usize) };

        if let Err(e) = env.set_byte_array_region(&data_obj, 0, buf_slice) {
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

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_getDataOffset(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlong {
    let res = panic::catch_unwind(|| {
        volume::get_data_offset(handle)
    });
    
    match res {
        Ok(Ok(offset)) => offset as jlong,
        Ok(Err(e)) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", format!("{}", e));
            -1
        },
        Err(_) => {
            let _ = env.throw_new("java/lang/RuntimeException", "Panic in getDataOffset");
            -1
        }
    }
}
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_mountFs(
    mut env: JNIEnv,
    _class: JClass,
    volume_handle: jlong,
    callback_obj: jni::objects::JObject,
    volume_size: jlong,
) -> jlong {
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let volume = {
            let contexts = volume::CONTEXTS.lock().unwrap();
            match contexts.get(&volume_handle) {
                Some(v) => v.clone(),
                None => return -1,
            }
        };

        let jvm = env.get_java_vm().expect("Failed to get JavaVM");
        let callback_global = env.new_global_ref(callback_obj).expect("Failed to create global ref");
        let reader = CallbackReader::new(jvm, callback_global, volume_size as u64);
        let decrypted_reader = DecryptedReader::new(reader, volume);

        // Try NTFS
        let reader_clone = decrypted_reader.clone();
        if let Ok(ntfs) = Ntfs::new(reader_clone) {
             log::info!("Mounted NTFS");
             let mut lock = FILESYSTEMS.lock().unwrap();
             let mut handle_lock = NEXT_FS_HANDLE.lock().unwrap();
             let handle = *handle_lock;
             *handle_lock += 1;
             lock.insert(handle, SupportedFileSystem::Ntfs(ntfs));
             return handle;
        }

        // Try exFAT
        let reader_clone2 = decrypted_reader.clone();
        if let Ok(exfat) = ExFat::open(reader_clone2) {
             log::info!("Mounted exFAT");
             let mut lock = FILESYSTEMS.lock().unwrap();
             let mut handle_lock = NEXT_FS_HANDLE.lock().unwrap();
             let handle = *handle_lock;
             *handle_lock += 1;
             lock.insert(handle, SupportedFileSystem::ExFat(exfat));
             return handle;
        }

        log::warn!("Failed to detect NTFS or exFAT");
        -1
    })).unwrap_or(-1)
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_listFiles(
    mut env: JNIEnv,
    _class: JClass,
    fs_handle: jlong,
    path_obj: jni::objects::JString,
) -> jobjectArray {
    let path: String = env.get_string(&path_obj).map(|s| s.into()).unwrap_or_default();
    
    let files = {
        let mut lock = FILESYSTEMS.lock().unwrap();
        if let Some(fs) = lock.get_mut(&fs_handle) {
            fs.list_files(&path).unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    let file_class = env.find_class("com/noxcipher/RustFile").expect("RustFile class not found");
    let init_id = env.get_method_id(&file_class, "<init>", "(Ljava/lang/String;ZJ)V").expect("RustFile constructor not found");
    
    let array = env.new_object_array(files.len() as i32, &file_class, jni::objects::JObject::null()).expect("Failed to create array");

    for (i, f) in files.iter().enumerate() {
        let name_jstr = env.new_string(&f.name).unwrap();
        let obj = env.new_object(&file_class, init_id, &[
            JValue::Object(&name_jstr),
            JValue::Bool(f.is_dir as u8),
            JValue::Long(f.size as i64)
        ]).unwrap();
        env.set_object_array_element(&array, i as i32, obj).unwrap();
    }
    
    array.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_readFile(
    mut env: JNIEnv,
    _class: JClass,
    fs_handle: jlong,
    path_obj: jni::objects::JString,
    offset: jlong,
    buffer: jbyteArray,
) -> jlong {
    let path: String = env.get_string(&path_obj).map(|s| s.into()).unwrap_or_default();
    
    let mut lock = FILESYSTEMS.lock().unwrap();
    if let Some(fs) = lock.get_mut(&fs_handle) {
         let buf_obj = unsafe { JByteArray::from_raw(buffer) };
         let len = env.get_array_length(&buf_obj).unwrap_or(0);
         let mut buf = vec![0u8; len as usize];
         
         match fs.read_file(&path, offset as u64, &mut buf) {
             Ok(bytes_read) => {
                 let buf_ptr = buf.as_ptr() as *const i8;
                 let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, bytes_read) };
                 env.set_byte_array_region(&buf_obj, 0, buf_slice).unwrap();
                 bytes_read as jlong
             },
             Err(_) => -1
         }
    } else {
        -1
    }
}

#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_closeFs(
    _env: JNIEnv,
    _class: JClass,
    fs_handle: jlong,
) {
    let mut lock = FILESYSTEMS.lock().unwrap();
    lock.remove(&fs_handle);
}
