// Import JNI environment types.
use jni::JNIEnv;
// Import JNI object types.
use jni::objects::{JClass, JByteArray};
// Import JNI system types.
use jni::sys::{jbyteArray, jlong};

// Import logging level filter.
use log::LevelFilter;
// Import panic handling.
use std::panic;

// Declare modules.
mod volume;
mod crypto;
mod header;
mod io_callback;
mod filesystem;

// Import filesystem types.
use filesystem::{SupportedFileSystem, DecryptedReader};
// Import CallbackReader.
use io_callback::CallbackReader;
// Import NTFS support.
use ntfs::Ntfs;
// Import ExFAT support.
use exfat::ExFat;
// Import JValue for JNI calls.
use jni::objects::JValue;

// Import Mutex for thread safety.
use std::sync::Mutex;
// Import lazy_static macro.
use lazy_static::lazy_static;

// Import jobjectArray type.
use jni::sys::jobjectArray;

// Define lazy static global variables.
lazy_static! {
    // A buffer to store log messages in memory, protected by a Mutex.
    static ref LOG_BUFFER: Mutex<Vec<String>> = Mutex::new(Vec::new());
    // A map of active file systems, keyed by handle, protected by a Mutex.
    static ref FILESYSTEMS: Mutex<std::collections::HashMap<i64, SupportedFileSystem>> = Mutex::new(std::collections::HashMap::new());
    // Counter for generating unique file system handles.
    static ref NEXT_FS_HANDLE: Mutex<i64> = Mutex::new(1);
}

// Struct for the in-memory logger.
struct InMemoryLogger;

// Implement the Log trait for InMemoryLogger.
impl log::Log for InMemoryLogger {
    // Check if logging is enabled for the given metadata.
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        // Enable for Info level and below (Error, Warn, Info).
        metadata.level() <= log::Level::Info
    }

    // Log a record.
    fn log(&self, record: &log::Record) {
        // Check if enabled.
        if self.enabled(record.metadata()) {
            // Format the log message.
            let log_msg = format!("{}: {}", record.level(), record.args());
            
            // Print to Android Logcat (commented out implementation detail).
            let _tag = std::ffi::CString::new("RustNative").unwrap();
            let _msg = std::ffi::CString::new(log_msg.clone()).unwrap();
            // Simple android logging via FFI if possible, or just rely on println! which often redirects
            // But since we can't easily link android log without crate, let's just store it.
            // Actually android_logger does this. We can't chain loggers easily without a helper crate.
            // For now, we prioritize the in-memory buffer for the user.
            
            // Store in the global buffer.
            if let Ok(mut buffer) = LOG_BUFFER.lock() {
                // Limit buffer size to last 100 logs.
                if buffer.len() > 100 { buffer.remove(0); } // Keep last 100 logs
                // Add new log message.
                buffer.push(log_msg);
            }
        }
    }

    // Flush logs (no-op for in-memory).
    fn flush(&self) {}
}

// Static instance of the logger.
static LOGGER: InMemoryLogger = InMemoryLogger;

// JNI function to initialize the logger.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_initLogger(
    _env: JNIEnv,
    _class: JClass,
) {
    // Catch panics to prevent crashing the JVM.
    let _ = panic::catch_unwind(|| {
        // Set the global logger and max log level.
        log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info)).ok();
        // Log initialization message.
        log::info!("Rust logger initialized (InMemory)");
    });
}

// JNI function to retrieve logs.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_getLogs(
    mut env: JNIEnv,
    _class: JClass,
) -> jobjectArray {
    // Lock and clone the log buffer.
    let logs = match LOG_BUFFER.lock() {
        Ok(buffer) => buffer.clone(),
        Err(_) => vec!["Failed to lock log buffer".to_string()],
    };

    // Find the String class.
    let string_class = env.find_class("java/lang/String").expect("Could not find String class");
    // Create an empty string for array initialization.
    let empty_string = env.new_string("").expect("Could not create empty string");
    
    // Create a new object array for strings.
    let array = env.new_object_array(logs.len() as i32, string_class, empty_string).expect("Could not create string array");

    // Iterate over logs and populate the array.
    for (i, log) in logs.iter().enumerate() {
        // Create a Java string from the log message.
        let jstr = env.new_string(log).expect("Could not create string");
        // Set the array element.
        env.set_object_array_element(&array, i as i32, jstr).expect("Could not set array element");
    }

    // Return the raw array pointer.
    array.into_raw()
}

// JNI function to initialize a volume context.
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
    // Wrap execution in catch_unwind to handle Rust panics gracefully.
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        log::info!("Rust init called");
        
        // Convert password JByteArray to Rust Vec<u8>.
        let password_obj = unsafe { JByteArray::from_raw(password) };
        let mut password_bytes = match env.convert_byte_array(&password_obj) {
            Ok(b) => b,
            Err(e) => {
                // Throw exception if conversion fails.
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid password array: {}", e));
                return -1;
            }
        };

        // Convert header JByteArray to Rust Vec<u8>.
        let header_obj = unsafe { JByteArray::from_raw(header) };
        let header_bytes = match env.convert_byte_array(&header_obj) {
            Ok(b) => b,
            Err(e) => {
                // Throw exception if conversion fails.
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid header array: {}", e));
                return -1;
            }
        };

        // Handle protection password (optional).
        let mut protection_password_bytes = if !protection_password.is_null() {
             // Convert protection password JByteArray if not null.
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

        // Call volume::create_context to attempt mounting.
        let res = volume::create_context(
            &password_bytes, 
            &header_bytes, 
            pim as i32, 
            partition_offset as u64,
            protection_password_bytes.as_deref(),
            protection_pim as i32
        );
        
        // Zeroize passwords in memory for security.
        use zeroize::Zeroize;
        password_bytes.zeroize();
        if let Some(ref mut pp) = protection_password_bytes {
            pp.zeroize();
        }
        
        // Handle result.
        match res {
            Ok(handle) => {
                // Return handle on success.
                log::info!("Init success, handle: {}", handle);
                handle
            },
            Err(e) => {
                // Log error and throw IOException on failure.
                log::error!("Init failed: {}", e);
                let _ = env.throw_new("java/io/IOException", format!("Init failed: {}", e));
                -1
            }
        }
    }));

    // Handle panic result.
    match result {
        Ok(val) => val,
        Err(e) => {
            // Extract panic message.
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                format!("Panic in init: {}", s)
            } else if let Some(s) = e.downcast_ref::<String>() {
                format!("Panic in init: {}", s)
            } else {
                "Panic in init: unknown cause".to_string()
            };
            // Log panic and throw RuntimeException.
            log::error!("{}", msg);
            let _ = env.throw_new("java/lang/RuntimeException", msg);
            -1
        }
    }
}

// JNI function to decrypt data.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_decrypt(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    offset: jlong,
    data: jbyteArray,
) {
    // Catch panics.
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Convert JByteArray to Rust object.
        let data_obj = unsafe { JByteArray::from_raw(data) };
        // Get array length.
        let len = match env.get_array_length(&data_obj) {
            Ok(l) => l,
            Err(e) => {
                // Throw exception if length retrieval fails.
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get array length: {}", e));
                return;
            }
        };

        // Allocate buffer.
        let mut buf = vec![0u8; len as usize];
        // Cast u8 buffer to i8 for JNI.
        let buf_ptr = buf.as_mut_ptr() as *mut i8;
        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf_ptr, len as usize) };

        // Copy data from Java array to Rust buffer.
        if let Err(e) = env.get_byte_array_region(&data_obj, 0, buf_slice) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read array: {}", e));
             return;
        }

        // Perform decryption.
        if let Err(e) = volume::decrypt(handle, offset as u64, &mut buf) {
             let _ = env.throw_new("java/io/IOException", format!("Decrypt failed: {}", e));
             return;
        }

        // Write back decrypted data to Java array.
        // Cast u8 buffer to i8 for JNI.
        let buf_ptr = buf.as_ptr() as *const i8;
        let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, len as usize) };

        if let Err(e) = env.set_byte_array_region(&data_obj, 0, buf_slice) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to write back array: {}", e));
        }
    }));
}

// JNI function to encrypt data.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_encrypt(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    offset: jlong,
    data: jbyteArray,
) {
    // Catch panics.
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Convert JByteArray to Rust object.
        let data_obj = unsafe { JByteArray::from_raw(data) };
        // Get array length.
        let len = match env.get_array_length(&data_obj) {
            Ok(l) => l,
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get array length: {}", e));
                return;
            }
        };

        // Allocate buffer.
        let mut buf = vec![0u8; len as usize];
        // Cast u8 buffer to i8 for JNI.
        let buf_ptr = buf.as_mut_ptr() as *mut i8;
        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf_ptr, len as usize) };
        
        // Copy data from Java array.
        if let Err(e) = env.get_byte_array_region(&data_obj, 0, buf_slice) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read array: {}", e));
             return;
        }

        // Perform encryption.
        if let Err(e) = volume::encrypt(handle, offset as u64, &mut buf) {
             let _ = env.throw_new("java/io/IOException", format!("Encrypt failed: {}", e));
             return;
        }

        // Write back encrypted data.
        // Cast u8 buffer to i8 for JNI.
        let buf_ptr = buf.as_ptr() as *const i8;
        let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, len as usize) };

        if let Err(e) = env.set_byte_array_region(&data_obj, 0, buf_slice) {
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to write back array: {}", e));
         }
    }));
}

// JNI function to close a volume context.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_close(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    // Catch panics.
    let _ = panic::catch_unwind(|| {
        // Close the context.
        volume::close_context(handle);
    });
}

// JNI function to get the data offset of a volume.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_getDataOffset(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlong {
    // Catch panics.
    let res = panic::catch_unwind(|| {
        // Get the offset.
        volume::get_data_offset(handle)
    });
    
    // Handle result.
    match res {
        Ok(Ok(offset)) => offset as jlong,
        Ok(Err(e)) => {
            // Throw exception on error.
            let _ = env.throw_new("java/lang/IllegalArgumentException", format!("{}", e));
            -1
        },
        Err(_) => {
            // Throw exception on panic.
            let _ = env.throw_new("java/lang/RuntimeException", "Panic in getDataOffset");
            -1
        }
    }
}
}

// JNI function to mount a file system on a volume.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_mountFs(
    mut env: JNIEnv,
    _class: JClass,
    volume_handle: jlong,
    callback_obj: jni::objects::JObject,
    volume_size: jlong,
) -> jlong {
    // Catch panics.
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Retrieve volume context.
        let volume = {
            let contexts = volume::CONTEXTS.lock().unwrap();
            match contexts.get(&volume_handle) {
                Some(v) => v.clone(),
                None => return -1,
            }
        };

        // Get JavaVM instance.
        let jvm = env.get_java_vm().expect("Failed to get JavaVM");
        // Create global reference for callback object.
        let callback_global = env.new_global_ref(callback_obj).expect("Failed to create global ref");
        // Create CallbackReader.
        let reader = CallbackReader::new(jvm, callback_global, volume_size as u64);
        // Create DecryptedReader.
        let decrypted_reader = DecryptedReader::new(reader, volume);

        // Try mounting NTFS.
        let reader_clone = decrypted_reader.clone();
        if let Ok(ntfs) = Ntfs::new(reader_clone) {
             log::info!("Mounted NTFS");
             let mut lock = FILESYSTEMS.lock().unwrap();
             let mut handle_lock = NEXT_FS_HANDLE.lock().unwrap();
             let handle = *handle_lock;
             *handle_lock += 1;
             // Store NTFS instance.
             lock.insert(handle, SupportedFileSystem::Ntfs(ntfs));
             return handle;
        }

        // Try mounting exFAT.
        let reader_clone2 = decrypted_reader.clone();
        if let Ok(exfat) = ExFat::open(reader_clone2) {
             log::info!("Mounted exFAT");
             let mut lock = FILESYSTEMS.lock().unwrap();
             let mut handle_lock = NEXT_FS_HANDLE.lock().unwrap();
             let handle = *handle_lock;
             *handle_lock += 1;
             // Store exFAT instance.
             lock.insert(handle, SupportedFileSystem::ExFat(exfat));
             return handle;
        }

        // Log warning if no supported FS found.
        log::warn!("Failed to detect NTFS or exFAT");
        -1
    })).unwrap_or(-1)
}

// JNI function to list files in a directory.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_listFiles(
    mut env: JNIEnv,
    _class: JClass,
    fs_handle: jlong,
    path_obj: jni::objects::JString,
) -> jobjectArray {
    // Convert Java string path to Rust String.
    let path: String = env.get_string(&path_obj).map(|s| s.into()).unwrap_or_default();
    
    // Retrieve file list from file system.
    let files = {
        let mut lock = FILESYSTEMS.lock().unwrap();
        if let Some(fs) = lock.get_mut(&fs_handle) {
            fs.list_files(&path).unwrap_or_default()
        } else {
            Vec::new()
        }
    };

    // Find RustFile class and constructor.
    let file_class = env.find_class("com/noxcipher/RustFile").expect("RustFile class not found");
    let init_id = env.get_method_id(&file_class, "<init>", "(Ljava/lang/String;ZJ)V").expect("RustFile constructor not found");
    
    // Create object array for results.
    let array = env.new_object_array(files.len() as i32, &file_class, jni::objects::JObject::null()).expect("Failed to create array");

    // Populate array with RustFile objects.
    for (i, f) in files.iter().enumerate() {
        let name_jstr = env.new_string(&f.name).unwrap();
        let obj = env.new_object(&file_class, init_id, &[
            JValue::Object(&name_jstr),
            JValue::Bool(f.is_dir as u8),
            JValue::Long(f.size as i64)
        ]).unwrap();
        env.set_object_array_element(&array, i as i32, obj).unwrap();
    }
    
    // Return array.
    array.into_raw()
}

// JNI function to read file content.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_readFile(
    mut env: JNIEnv,
    _class: JClass,
    fs_handle: jlong,
    path_obj: jni::objects::JString,
    offset: jlong,
    buffer: jbyteArray,
) -> jlong {
    // Convert path to Rust String.
    let path: String = env.get_string(&path_obj).map(|s| s.into()).unwrap_or_default();
    
    // Access file system.
    let mut lock = FILESYSTEMS.lock().unwrap();
    if let Some(fs) = lock.get_mut(&fs_handle) {
         // Convert Java byte array to Rust object.
         let buf_obj = unsafe { JByteArray::from_raw(buffer) };
         let len = env.get_array_length(&buf_obj).unwrap_or(0);
         let mut buf = vec![0u8; len as usize];
         
         // Read file content.
         match fs.read_file(&path, offset as u64, &mut buf) {
             Ok(bytes_read) => {
                 // Write back to Java array.
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

// JNI function to close a file system.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_closeFs(
    _env: JNIEnv,
    _class: JClass,
    fs_handle: jlong,
) {
    // Remove file system from global map.
    let mut lock = FILESYSTEMS.lock().unwrap();
    lock.remove(&fs_handle);
}
