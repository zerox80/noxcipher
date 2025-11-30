// Import the JNIEnv type from the jni crate to interact with the Java Native Interface environment.
use jni::JNIEnv;
// Import JClass and JByteArray types from the jni::objects module for handling Java classes and byte arrays.
use jni::objects::{JClass, JByteArray};
// Import jbyteArray and jlong types from the jni::sys module, representing Java's byte[] and long types.
use jni::sys::{jbyteArray, jlong};

// Import LevelFilter from the log crate to control the logging verbosity level.
use log::LevelFilter;
// Import the panic module from the standard library to handle thread panics.
use std::panic;

// Declare the volume module, which likely contains logic for handling encrypted volumes.
mod volume;
// Declare the crypto module, which likely contains cryptographic primitives and operations.
mod crypto;
// Declare the header module, which likely handles parsing and processing of volume headers.
mod header;
// Declare the io_callback module, which likely provides mechanisms for I/O callbacks.
mod io_callback;
// Declare the filesystem module, which likely handles file system operations.
mod filesystem;

// Import SupportedFileSystem and DecryptedReader types from the filesystem module.
use filesystem::{SupportedFileSystem, DecryptedReader};
// Import CallbackReader from the io_callback module.
use io_callback::CallbackReader;
// Import the Ntfs struct from the ntfs crate (or module) for NTFS file system support.
use ntfs::Ntfs;
// Import the ExFat struct from the exfat crate (or module) for exFAT file system support.
use exfat::ExFat;
// Import JValue from jni::objects to represent Java values in JNI calls.
use jni::objects::JValue;

// Import Mutex from std::sync to provide mutual exclusion for thread-safe data access.
use std::sync::Mutex;
// Import the lazy_static macro to allow declaring lazily evaluated static variables.
use lazy_static::lazy_static;

// Import jobjectArray from jni::sys to represent Java object arrays.
use jni::sys::jobjectArray;

// Use the lazy_static macro to define static variables that are initialized lazily.
lazy_static! {
    // Define a static global variable named LOG_BUFFER.
    // It is a Mutex-protected vector of Strings to store log messages safely across threads.
    // Initialize it with a new, empty Mutex containing an empty Vector.
    static ref LOG_BUFFER: Mutex<Vec<String>> = Mutex::new(Vec::new());
    // Define a static global variable named FILESYSTEMS.
    // It is a Mutex-protected HashMap mapping i64 handles to SupportedFileSystem enums.
    // This stores the active file system instances.
    static ref FILESYSTEMS: Mutex<std::collections::HashMap<i64, SupportedFileSystem>> = Mutex::new(std::collections::HashMap::new());
    // Define a static global variable named NEXT_FS_HANDLE.
    // It is a Mutex-protected i64 counter used to generate unique handles for file systems.
    // Initialize it with 1.
    static ref NEXT_FS_HANDLE: Mutex<i64> = Mutex::new(1);
}

// Define a unit struct named InMemoryLogger to implement the Log trait.
struct InMemoryLogger;

// Implement the log::Log trait for the InMemoryLogger struct.
impl log::Log for InMemoryLogger {
    // Define the enabled method to check if logging is enabled for a given metadata.
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        // Return true if the log level is Info or more critical (Error, Warn).
        metadata.level() <= log::Level::Info
    }

    // Define the log method to record a log entry.
    fn log(&self, record: &log::Record) {
        // Check if logging is enabled for this record's metadata.
        if self.enabled(record.metadata()) {
            // Format the log message with the level and the message arguments.
            let log_msg = format!("{}: {}", record.level(), record.args());
            
            // The following lines create CStrings for Android logging but are currently unused variables (prefixed with _).
            // Create a CString for the tag "RustNative".
            let _tag = std::ffi::CString::new("RustNative").unwrap();
            // Create a CString for the log message.
            let _msg = std::ffi::CString::new(log_msg.clone()).unwrap();
            // The comments explain that simple Android logging via FFI is possible but not implemented here.
            // We are prioritizing the in-memory buffer for the user to retrieve logs.
            
            // Attempt to lock the global LOG_BUFFER mutex.
            if let Ok(mut buffer) = LOG_BUFFER.lock() {
                // Check if the buffer size exceeds 100 entries.
                if buffer.len() > 100 { 
                    // Remove the oldest log entry (at index 0) to maintain a fixed size.
                    buffer.remove(0); 
                } 
                // Push the new log message into the buffer.
                buffer.push(log_msg);
            }
        }
    }

    // Define the flush method, which is required by the Log trait.
    // It is a no-op implementation as we are just writing to memory.
    fn flush(&self) {}
}

// Define a static global instance of InMemoryLogger named LOGGER.
static LOGGER: InMemoryLogger = InMemoryLogger;

// Define a JNI function named Java_com_noxcipher_RustNative_initLogger.
// It is exposed to Java with the "system" calling convention and no name mangling.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_initLogger(
    // The JNI environment.
    _env: JNIEnv,
    // The Java class calling this method (static method).
    _class: JClass,
) {
    // Use panic::catch_unwind to catch any Rust panics and prevent them from crashing the JVM.
    let _ = panic::catch_unwind(|| {
        // Set the global logger to our LOGGER instance.
        // If successful, set the max log level to Info.
        // Ignore errors if the logger is already set.
        log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Info)).ok();
        // Log an info message indicating that the Rust logger has been initialized.
        log::info!("Rust logger initialized (InMemory)");
    });
}

// Define a JNI function named Java_com_noxcipher_RustNative_getLogs.
// It returns a jobjectArray containing the logs.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_getLogs(
    // The JNI environment, mutable because we create objects.
    mut env: JNIEnv,
    // The Java class.
    _class: JClass,
) -> jobjectArray {
    // Attempt to lock the LOG_BUFFER and clone its contents.
    let logs = match LOG_BUFFER.lock() {
        // If successful, clone the vector of strings.
        Ok(buffer) => buffer.clone(),
        // If the lock fails (e.g., poisoned), return a vector with an error message.
        Err(_) => vec!["Failed to lock log buffer".to_string()],
    };

    // Find the java.lang.String class in the JVM.
    // Expect success, otherwise panic with a message.
    let string_class = env.find_class("java/lang/String").expect("Could not find String class");
    // Create a new empty Java string to use as an initial element/template.
    // Expect success.
    let empty_string = env.new_string("").expect("Could not create empty string");
    
    // Create a new object array of Strings with the size of the logs vector.
    // Expect success.
    let array = env.new_object_array(logs.len() as i32, string_class, empty_string).expect("Could not create string array");

    // Iterate over the logs with their index.
    for (i, log) in logs.iter().enumerate() {
        // Create a new Java string from the Rust string log message.
        // Expect success.
        let jstr = env.new_string(log).expect("Could not create string");
        // Set the element at index i in the array to the created Java string.
        // Expect success.
        env.set_object_array_element(&array, i as i32, jstr).expect("Could not set array element");
    }

    // Return the raw pointer to the Java object array.
    array.into_raw()
}

// Define a JNI function named Java_com_noxcipher_RustNative_init.
// It initializes the volume context and returns a handle (jlong).
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_init(
    // The JNI environment.
    mut env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The password as a byte array.
    password: jbyteArray,
    // The header data as a byte array.
    header: jbyteArray,
    // The PIM value.
    pim: jni::sys::jint,
    // The partition offset.
    partition_offset: jlong,
    // The protection password (optional) as a byte array.
    protection_password: jbyteArray,
    // The protection PIM value.
    protection_pim: jni::sys::jint,
) -> jlong {
    // Wrap the entire execution in panic::catch_unwind to handle panics gracefully.
    // AssertUnwindSafe is used because we are sharing references across the boundary.
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Log that the init function has been called.
        log::info!("Rust init called");
        
        // Convert the raw JByteArray password to a JByteArray object unsafely.
        let password_obj = unsafe { JByteArray::from_raw(password) };
        // Convert the Java byte array to a Rust Vec<u8>.
        let mut password_bytes = match env.convert_byte_array(&password_obj) {
            // If successful, return the bytes.
            Ok(b) => b,
            // If an error occurs:
            Err(e) => {
                // Throw a Java IllegalArgumentException with the error message.
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid password array: {}", e));
                // Return -1 to indicate failure.
                return -1;
            }
        };

        // Convert the raw JByteArray header to a JByteArray object unsafely.
        let header_obj = unsafe { JByteArray::from_raw(header) };
        // Convert the Java byte array to a Rust Vec<u8>.
        let header_bytes = match env.convert_byte_array(&header_obj) {
            // If successful, return the bytes.
            Ok(b) => b,
            // If an error occurs:
            Err(e) => {
                // Throw a Java IllegalArgumentException with the error message.
                let _ = env.throw_new("java/lang/IllegalArgumentException", format!("Invalid header array: {}", e));
                // Return -1 to indicate failure.
                return -1;
            }
        };

        // Handle the optional protection password.
        let mut protection_password_bytes = if !protection_password.is_null() {
             // If the pointer is not null, convert it to a JByteArray object unsafely.
             let prot_obj = unsafe { JByteArray::from_raw(protection_password) };
             // Attempt to convert the Java byte array to a Rust Vec<u8>.
             match env.convert_byte_array(&prot_obj) {
                // If successful, wrap it in Some.
                Ok(b) => Some(b),
                // If an error occurs:
                Err(e) => {
                    // Log a warning about the invalid array.
                    log::warn!("Invalid protection password array: {}", e);
                    // Return None.
                    None
                }
             }
        } else {
            // If the pointer is null, return None.
            None
        };

        // Call the volume::create_context function to attempt to mount the volume.
        // Pass references to the password, header, and other parameters.
        let res = volume::create_context(
            &password_bytes, 
            &header_bytes, 
            pim as i32, 
            partition_offset as u64,
            protection_password_bytes.as_deref(),
            protection_pim as i32
        );
        
        // Import the Zeroize trait to securely clear memory.
        use zeroize::Zeroize;
        // Zeroize the password bytes in memory.
        password_bytes.zeroize();
        // If protection password bytes exist, zeroize them as well.
        if let Some(ref mut pp) = protection_password_bytes {
            pp.zeroize();
        }
        
        // Match on the result of create_context.
        match res {
            // If successful:
            Ok(handle) => {
                // Log success and the returned handle.
                log::info!("Init success, handle: {}", handle);
                // Return the handle.
                handle
            },
            // If an error occurred:
            Err(e) => {
                // Log the error.
                log::error!("Init failed: {}", e);
                // Throw a Java IOException with the error message.
                let _ = env.throw_new("java/io/IOException", format!("Init failed: {}", e));
                // Return -1 to indicate failure.
                -1
            }
        }
    }));

    // Handle the result of the panic::catch_unwind.
    match result {
        // If the closure executed successfully (no panic), return its value.
        Ok(val) => val,
        // If a panic occurred:
        Err(e) => {
            // Try to extract the panic message.
            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                // If the panic payload is a string slice, format it.
                format!("Panic in init: {}", s)
            } else if let Some(s) = e.downcast_ref::<String>() {
                // If the panic payload is a String, format it.
                format!("Panic in init: {}", s)
            } else {
                // Otherwise, use a generic unknown cause message.
                "Panic in init: unknown cause".to_string()
            };
            // Log the panic message as an error.
            log::error!("{}", msg);
            // Throw a Java RuntimeException with the panic message.
            let _ = env.throw_new("java/lang/RuntimeException", msg);
            // Return -1 to indicate failure.
            -1
        }
    }
}

// Define a JNI function named Java_com_noxcipher_RustNative_decrypt.
// It decrypts data in place.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_decrypt(
    // The JNI environment.
    mut env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The volume handle.
    handle: jlong,
    // The offset to decrypt at.
    offset: jlong,
    // The data buffer to decrypt (in-place).
    data: jbyteArray,
) {
    // Wrap execution in panic::catch_unwind.
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Convert the raw JByteArray to a JByteArray object unsafely.
        let data_obj = unsafe { JByteArray::from_raw(data) };
        // Get the length of the Java array.
        let len = match env.get_array_length(&data_obj) {
            // If successful, return the length.
            Ok(l) => l,
            // If an error occurs:
            Err(e) => {
                // Throw a RuntimeException.
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get array length: {}", e));
                // Return early.
                return;
            }
        };

        // Allocate a Rust vector of zeros with the same length.
        let mut buf = vec![0u8; len as usize];
        // Get a mutable pointer to the buffer and cast it to i8 (signed byte for JNI).
        let buf_ptr = buf.as_mut_ptr() as *mut i8;
        // Create a mutable slice from the raw parts.
        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf_ptr, len as usize) };

        // Copy data from the Java byte array region into the Rust buffer slice.
        if let Err(e) = env.get_byte_array_region(&data_obj, 0, buf_slice) {
             // If an error occurs, throw a RuntimeException.
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read array: {}", e));
             // Return early.
             return;
        }

        // Perform the decryption operation using the volume module.
        if let Err(e) = volume::decrypt(handle, offset as u64, &mut buf) {
             // If decryption fails, throw an IOException.
             let _ = env.throw_new("java/io/IOException", format!("Decrypt failed: {}", e));
             // Return early.
             return;
        }

        // Write the decrypted data back to the Java array.
        // Get a const pointer to the buffer and cast it to i8.
        let buf_ptr = buf.as_ptr() as *const i8;
        // Create a slice from the raw parts.
        let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, len as usize) };

        // Set the Java byte array region with the decrypted data.
        if let Err(e) = env.set_byte_array_region(&data_obj, 0, buf_slice) {
             // If writing back fails, throw a RuntimeException.
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to write back array: {}", e));
        }
    }));
}

// Define a JNI function named Java_com_noxcipher_RustNative_encrypt.
// It encrypts data in place.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_encrypt(
    // The JNI environment.
    mut env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The volume handle.
    handle: jlong,
    // The offset to encrypt at.
    offset: jlong,
    // The data buffer to encrypt (in-place).
    data: jbyteArray,
) {
    // Wrap execution in panic::catch_unwind.
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Convert the raw JByteArray to a JByteArray object unsafely.
        let data_obj = unsafe { JByteArray::from_raw(data) };
        // Get the length of the Java array.
        let len = match env.get_array_length(&data_obj) {
            // If successful, return the length.
            Ok(l) => l,
            // If an error occurs:
            Err(e) => {
                // Throw a RuntimeException.
                let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to get array length: {}", e));
                // Return early.
                return;
            }
        };

        // Allocate a Rust vector of zeros with the same length.
        let mut buf = vec![0u8; len as usize];
        // Get a mutable pointer to the buffer and cast it to i8.
        let buf_ptr = buf.as_mut_ptr() as *mut i8;
        // Create a mutable slice from the raw parts.
        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf_ptr, len as usize) };
        
        // Copy data from the Java byte array region into the Rust buffer slice.
        if let Err(e) = env.get_byte_array_region(&data_obj, 0, buf_slice) {
             // If an error occurs, throw a RuntimeException.
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to read array: {}", e));
             // Return early.
             return;
        }

        // Perform the encryption operation using the volume module.
        if let Err(e) = volume::encrypt(handle, offset as u64, &mut buf) {
             // If encryption fails, throw an IOException.
             let _ = env.throw_new("java/io/IOException", format!("Encrypt failed: {}", e));
             // Return early.
             return;
        }

        // Write the encrypted data back to the Java array.
        // Get a const pointer to the buffer and cast it to i8.
        let buf_ptr = buf.as_ptr() as *const i8;
        // Create a slice from the raw parts.
        let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, len as usize) };

        // Set the Java byte array region with the encrypted data.
        if let Err(e) = env.set_byte_array_region(&data_obj, 0, buf_slice) {
             // If writing back fails, throw a RuntimeException.
             let _ = env.throw_new("java/lang/RuntimeException", format!("Failed to write back array: {}", e));
         }
    }));
}

// Define a JNI function named Java_com_noxcipher_RustNative_close.
// It closes the volume context associated with the handle.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_close(
    // The JNI environment.
    _env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The volume handle to close.
    handle: jlong,
) {
    // Wrap execution in panic::catch_unwind.
    let _ = panic::catch_unwind(|| {
        // Call volume::close_context to close the volume.
        volume::close_context(handle);
    });
}

// Define a JNI function named Java_com_noxcipher_RustNative_getDataOffset.
// It retrieves the data offset for the given volume handle.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_getDataOffset(
    // The JNI environment.
    mut env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The volume handle.
    handle: jlong,
) -> jlong {
    // Wrap execution in panic::catch_unwind.
    let res = panic::catch_unwind(|| {
        // Call volume::get_data_offset to get the offset.
        volume::get_data_offset(handle)
    });
    
    // Handle the result of the panic catch.
    match res {
        // If no panic and the function returned Ok:
        Ok(Ok(offset)) => offset as jlong,
        // If no panic but the function returned Err:
        Ok(Err(e)) => {
            // Throw an IllegalArgumentException with the error message.
            let _ = env.throw_new("java/lang/IllegalArgumentException", format!("{}", e));
            // Return -1.
            -1
        },
        // If a panic occurred:
        Err(_) => {
            // Throw a RuntimeException.
            let _ = env.throw_new("java/lang/RuntimeException", "Panic in getDataOffset");
            // Return -1.
            -1
        }
    }
}

// Define a JNI function named Java_com_noxcipher_RustNative_mountFs.
// It attempts to mount a file system (NTFS or exFAT) on the volume.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_mountFs(
    // The JNI environment.
    mut env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The volume handle.
    volume_handle: jlong,
    // The callback object for I/O operations.
    callback_obj: jni::objects::JObject,
    // The size of the volume.
    volume_size: jlong,
) -> jlong {
    // Wrap execution in panic::catch_unwind.
    let _ = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Retrieve the volume context associated with the handle.
        let volume = {
            // Lock the global CONTEXTS map.
            let contexts = volume::CONTEXTS.lock().unwrap();
            // Look up the handle.
            match contexts.get(&volume_handle) {
                // If found, clone the volume context.
                Some(v) => v.clone(),
                // If not found, return -1.
                None => return -1,
            }
        };

        // Get the JavaVM instance from the environment.
        // Expect success.
        let jvm = env.get_java_vm().expect("Failed to get JavaVM");
        // Create a global reference for the callback object so it persists.
        // Expect success.
        let callback_global = env.new_global_ref(callback_obj).expect("Failed to create global ref");
        // Create a new CallbackReader with the JVM, callback object, and volume size.
        let reader = CallbackReader::new(jvm, callback_global, volume_size as u64);
        // Create a DecryptedReader that wraps the CallbackReader and the volume context.
        // This reader handles on-the-fly decryption.
        let decrypted_reader = DecryptedReader::new(reader, volume);

        // Try mounting as NTFS.
        // Clone the decrypted reader for the NTFS attempt.
        let reader_clone = decrypted_reader.clone();
        // Attempt to create a new Ntfs instance.
        if let Ok(ntfs) = Ntfs::new(reader_clone) {
             // Log success.
             log::info!("Mounted NTFS");
             // Lock the FILESYSTEMS map.
             let mut lock = FILESYSTEMS.lock().unwrap();
             // Lock the NEXT_FS_HANDLE counter.
             let mut handle_lock = NEXT_FS_HANDLE.lock().unwrap();
             // Get the current handle value.
             let handle = *handle_lock;
             // Increment the handle counter.
             *handle_lock += 1;
             // Insert the NTFS instance into the map with the new handle.
             lock.insert(handle, SupportedFileSystem::Ntfs(ntfs));
             // Return the handle.
             return handle;
        }

        // Try mounting as exFAT.
        // Clone the decrypted reader for the exFAT attempt.
        let reader_clone2 = decrypted_reader.clone();
        // Attempt to open as ExFat.
        if let Ok(exfat) = ExFat::open(reader_clone2) {
             // Log success.
             log::info!("Mounted exFAT");
             // Lock the FILESYSTEMS map.
             let mut lock = FILESYSTEMS.lock().unwrap();
             // Lock the NEXT_FS_HANDLE counter.
             let mut handle_lock = NEXT_FS_HANDLE.lock().unwrap();
             // Get the current handle value.
             let handle = *handle_lock;
             // Increment the handle counter.
             *handle_lock += 1;
             // Insert the exFAT instance into the map with the new handle.
             lock.insert(handle, SupportedFileSystem::ExFat(exfat));
             // Return the handle.
             return handle;
        }

        // Log a warning if neither NTFS nor exFAT could be mounted.
        log::warn!("Failed to detect NTFS or exFAT");
        // Return -1 to indicate failure.
        -1
    })).unwrap_or(-1) // If a panic occurred, return -1.
}

// Define a JNI function named Java_com_noxcipher_RustNative_listFiles.
// It lists files in a directory of the mounted file system.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_listFiles(
    // The JNI environment.
    mut env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The file system handle.
    fs_handle: jlong,
    // The path to list as a Java string.
    path_obj: jni::objects::JString,
) -> jobjectArray {
    // Convert the Java string path to a Rust String.
    // If conversion fails, use an empty string.
    let path: String = env.get_string(&path_obj).map(|s| s.into()).unwrap_or_default();
    
    // Retrieve the list of files from the file system.
    let files = {
        // Lock the FILESYSTEMS map.
        let mut lock = FILESYSTEMS.lock().unwrap();
        // Look up the file system by handle.
        if let Some(fs) = lock.get_mut(&fs_handle) {
            // If found, call list_files on it.
            // If list_files fails, return an empty vector.
            fs.list_files(&path).unwrap_or_default()
        } else {
            // If not found, return an empty vector.
            Vec::new()
        }
    };

    // Find the com.noxcipher.RustFile class.
    // Expect success.
    let file_class = env.find_class("com/noxcipher/RustFile").expect("RustFile class not found");
    // Get the constructor ID for RustFile (String name, boolean isDir, long size).
    // Expect success.
    let init_id = env.get_method_id(&file_class, "<init>", "(Ljava/lang/String;ZJ)V").expect("RustFile constructor not found");
    
    // Create a new object array of RustFile objects with the size of the files vector.
    // Initialize with null.
    // Expect success.
    let array = env.new_object_array(files.len() as i32, &file_class, jni::objects::JObject::null()).expect("Failed to create array");

    // Iterate over the files and populate the array.
    for (i, f) in files.iter().enumerate() {
        // Create a Java string for the file name.
        let name_jstr = env.new_string(&f.name).unwrap();
        // Create a new RustFile object using the constructor.
        let obj = env.new_object(&file_class, init_id, &[
            JValue::Object(&name_jstr), // name
            JValue::Bool(f.is_dir as u8), // isDir
            JValue::Long(f.size as i64) // size
        ]).unwrap();
        // Set the array element at index i.
        env.set_object_array_element(&array, i as i32, obj).unwrap();
    }
    
    // Return the raw pointer to the array.
    array.into_raw()
}

// Define a JNI function named Java_com_noxcipher_RustNative_readFile.
// It reads content from a file in the mounted file system.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_readFile(
    // The JNI environment.
    mut env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The file system handle.
    fs_handle: jlong,
    // The path to the file as a Java string.
    path_obj: jni::objects::JString,
    // The offset to start reading from.
    offset: jlong,
    // The buffer to read into.
    buffer: jbyteArray,
) -> jlong {
    // Convert the Java string path to a Rust String.
    // If conversion fails, use an empty string.
    let path: String = env.get_string(&path_obj).map(|s| s.into()).unwrap_or_default();
    
    // Access the file system.
    let mut lock = FILESYSTEMS.lock().unwrap();
    // Look up the file system by handle.
    if let Some(fs) = lock.get_mut(&fs_handle) {
         // Convert the raw JByteArray buffer to a JByteArray object unsafely.
         let buf_obj = unsafe { JByteArray::from_raw(buffer) };
         // Get the length of the buffer.
         let len = env.get_array_length(&buf_obj).unwrap_or(0);
         // Allocate a Rust vector of zeros with the same length.
         let mut buf = vec![0u8; len as usize];
         
         // Read the file content into the buffer.
         match fs.read_file(&path, offset as u64, &mut buf) {
             // If successful, returns the number of bytes read.
             Ok(bytes_read) => {
                 // Write the data back to the Java array.
                 // Get a const pointer to the buffer and cast it to i8.
                 let buf_ptr = buf.as_ptr() as *const i8;
                 // Create a slice from the raw parts with the number of bytes read.
                 let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, bytes_read) };
                 // Set the Java byte array region.
                 env.set_byte_array_region(&buf_obj, 0, buf_slice).unwrap();
                 // Return the number of bytes read as jlong.
                 bytes_read as jlong
             },
             // If reading fails, return -1.
             Err(_) => -1
         }
    } else {
        // If file system not found, return -1.
        -1
    }
}

// Define a JNI function named Java_com_noxcipher_RustNative_closeFs.
// It closes the file system associated with the handle.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_closeFs(
    // The JNI environment.
    _env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The file system handle.
    fs_handle: jlong,
) {
    // Lock the FILESYSTEMS map.
    let mut lock = FILESYSTEMS.lock().unwrap();
    // Remove the file system with the given handle.
    // This will drop the SupportedFileSystem instance, cleaning up resources.
    lock.remove(&fs_handle);
}
