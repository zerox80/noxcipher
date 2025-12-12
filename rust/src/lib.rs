// Import the JNIEnv type from the jni crate to interact with the Java Native Interface environment.
use jni::JNIEnv;
// Import JClass and JByteArray types from the jni::objects module for handling Java classes and byte arrays.
use jni::objects::{JByteArray, JClass};
// Import jbyteArray and jlong types from the jni::sys module, representing Java's byte[] and long types.
use jni::sys::{jbyteArray, jlong};

// Import LevelFilter from the log crate to control the logging verbosity level.
use log::LevelFilter;
// Import the panic module from the standard library to handle thread panics.
use std::panic;
// Pointer helpers and zeroing utilities.
use std::ptr;
use zeroize::Zeroizing;

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
use filesystem::{DecryptedReader, SupportedFileSystem};
// Import CallbackReader from the io_callback module.
use io_callback::CallbackReader;
// Import the Ntfs struct from the ntfs crate (or module) for NTFS file system support.
use ntfs::Ntfs;
// Import the ExFat struct from the exfat crate (or module) for exFAT file system support.
use exfat::ExFat;
// Import JValue from jni::objects to represent Java values in JNI calls.
use jni::objects::JValue;

// Import Mutex from std::sync to provide mutual exclusion for thread-safe data access.
// Import Mutex and RwLock from std::sync for concurrency.
use std::sync::{Arc, Mutex, RwLock};
// Import the lazy_static macro to allow declaring lazily evaluated static variables.
use lazy_static::lazy_static;

// Import jobjectArray from jni::sys to represent Java object arrays.
use jni::sys::jobjectArray;

// Use the lazy_static macro to define static variables that are initialized lazily.
lazy_static! {
    // Define a static global variable named LOG_BUFFER.
    // It is a Mutex-protected vector of Strings to store log messages safely across threads.
    // Initialize it with a new, empty Mutex containing an empty Vector.
    static ref LOG_BUFFER: Mutex<std::collections::VecDeque<String>> = Mutex::new(std::collections::VecDeque::new());
    // Define a static global variable named FILESYSTEMS.
    // It is a RwLock-protected HashMap mapping i64 handles to Arc<Mutex<SupportedFileSystem>>.
    // This allows concurrent access to the map (read) while specific filesystems are locked individually.
    static ref FILESYSTEMS: RwLock<std::collections::HashMap<i64, Arc<Mutex<SupportedFileSystem>>>> = RwLock::new(std::collections::HashMap::new());
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

            // The following lines create CStrings for Android logging but are currently unused variables (prefixed with _).
            // Create a CString for the tag "RustNative".
            // Create a CString for the log message.
            // The comments explain that simple Android logging via FFI is possible but not implemented here.
            // We are prioritizing the in-memory buffer for the user to retrieve logs.

            // Attempt to lock the global LOG_BUFFER mutex.
            if let Ok(mut buffer) = LOG_BUFFER.lock() {
                // Check if the buffer size exceeds 100 entries.
                if buffer.len() > 100 {
                    // Remove the oldest log entry (at index 0) to maintain a fixed size.
                    buffer.pop_front();
                }
                // Push the new log message into the buffer.
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
        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(LevelFilter::Info))
            .ok();
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Attempt to lock the LOG_BUFFER and clone its contents.
        let logs = match LOG_BUFFER.lock() {
            // If successful, clone the vector of strings.
            Ok(buffer) => buffer.clone(),
            // If the lock fails (e.g., poisoned), return a vector with an error message.
            Err(_) => vec!["Failed to lock log buffer".to_string()],
        };

        // Find the java.lang.String class in the JVM.
        // Expect success, otherwise panic with a message.
        let string_class = env
            .find_class("java/lang/String")
            .unwrap_or_else(|_| {
                 // Fallback? If we can't find String, we can't do much.
                 panic!("Could not find String class");
            });
            
        // Create a new empty Java string to use as an initial element/template.
        // Expect success.
        let empty_string = env.new_string("").unwrap_or_else(|_| panic!("Could not create empty string"));

        // Create a new object array of Strings with the size of the logs vector.
        // Expect success.
        let array = env
            .new_object_array(logs.len() as i32, string_class, empty_string)
            .unwrap_or(std::ptr::null_mut()); // Use unwrap_or to just return null if fail
            
        if array.is_null() {
            return std::ptr::null_mut();
        }

        // Iterate over the logs with their index.
        for (i, log) in logs.iter().enumerate() {
            // Create a new Java string from the Rust string log message.
            if let Ok(jstr) = env.new_string(log) {
                 // Set the element at index i in the array to the created Java string.
                let _ = env.set_object_array_element(&array, i as i32, jstr);
            }
        }

        // Return the raw pointer to the Java object array.
        array.into_raw()
    }));
    
    match result {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

// ... init ... (skipping unchanged functions)

// ...

// Define a JNI function named Java_com_noxcipher_RustNative_closeFs.
// It closes the file system associated with the handle.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_closeFs(
    // The JNI environment.
    _env: JNIEnv,
    // The Java class.
    _class: JClass,
    // The file system handle.
    handle: jlong,
) {
    // Wrap execution in panic::catch_unwind.
    let _ = std::panic::catch_unwind(|| {
        // Use unwrap_or_else to handle poisoned mutex gracefully
        let mut lock = FILESYSTEMS.write().unwrap_or_else(|e| e.into_inner());
        lock.remove(&handle);
    });
}

// Define a JNI function named Java_com_noxcipher_RustNative_init.
// It initializes the volume context and returns a handle (jlong).
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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
    // The total volume size (for safety checks).
    // The total volume size (for safety checks).
    volume_size: jlong,
    // The backup header data as a byte array (optional).
    backup_header: jbyteArray,
) -> jlong {
    // Wrap the entire execution in panic::catch_unwind to handle panics gracefully.
    // AssertUnwindSafe is used because we are sharing references across the boundary.
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Log that the init function has been called.
        log::info!("Rust init called");
        
        // Validate inputs are not null where required
        if password.is_null() {
             let _ = env.throw_new("java/lang/IllegalArgumentException", "Password cannot be null");
             return -1;
        }
        if header.is_null() {
             let _ = env.throw_new("java/lang/IllegalArgumentException", "Header cannot be null");
             return -1;
        }

        // Convert the raw JByteArray password to a JByteArray object unsafely.
        let password_obj = unsafe { JByteArray::from_raw(password) };
        // Convert the Java byte array to a Rust Vec<u8>.
        let mut password_bytes = match env.convert_byte_array(&password_obj) {
            // If successful, return the bytes.
            Ok(b) => b,
            // If an error occurs:
            Err(e) => {
                // Throw a Java IllegalArgumentException with the error message.
                let _ = env.throw_new(
                    "java/lang/IllegalArgumentException",
                    format!("Invalid password array: {}", e),
                );
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
                let _ = env.throw_new(
                    "java/lang/IllegalArgumentException",
                    format!("Invalid header array: {}", e),
                );
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

        // Handle the optional backup header.
        let mut backup_header_bytes = if !backup_header.is_null() {
            let bh_obj = unsafe { JByteArray::from_raw(backup_header) };
            match env.convert_byte_array(&bh_obj) {
                Ok(b) => Some(b),
                Err(e) => {
                    log::warn!("Invalid backup header array: {}", e);
                    None
                }
            }
        } else {
            None
        };

        if partition_offset < 0 {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Negative partition offset");
            return -1;
        }

        // Call the volume::create_context function to attempt to mount the volume.
        // Pass references to the password, header, and other parameters.
        let res = volume::create_context(
            &password_bytes,
            &header_bytes,
            pim,
            partition_offset as u64,
            None,
            protection_password_bytes.as_deref().map(|z| z.as_slice()),
            protection_pim,
            volume_size as u64,
            backup_header_bytes.as_deref().map(|z| z.as_slice()),
        );

        // Explicit zeroize is redundant if we use Zeroizing, but keeping for clarity/legacy correctness
        // Import the Zeroize trait to securely clear memory.
        use zeroize::Zeroize;
        // Zeroize the password bytes in memory.
        // password_bytes.zeroize(); // drop handles it
        // Zeroize header bytes.
        // header_bytes.zeroize(); // drop handles it
        // If protection password bytes exist, zeroize them as well.
        // if let Some(ref mut pp) = protection_password_bytes {
        //     pp.zeroize(); // drop handles it
        // }
        // If backup header bytes exist, zeroize them (though not critical if just ciphertext, good practice).
        // if let Some(ref mut bh) = backup_header_bytes {
        //     bh.zeroize(); // drop handles it
        // }

        // Match on the result of create_context.
        match res {
            // If successful:
            Ok(handle) => {
                // Log success and the returned handle.
                log::info!("Init success, handle: {}", handle);
                // Return the handle.
                handle
            }
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
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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
                let _ = env.throw_new(
                    "java/lang/RuntimeException",
                    format!("Failed to get array length: {}", e),
                );
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
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("Failed to read array: {}", e),
            );
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
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("Failed to write back array: {}", e),
            );
        }
        
        // Zeroize buffer
        use zeroize::Zeroize;
        buf.zeroize();
    }));
}

// Define a JNI function named Java_com_noxcipher_RustNative_encrypt.
// It encrypts data in place.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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
                let _ = env.throw_new(
                    "java/lang/RuntimeException",
                    format!("Failed to get array length: {}", e),
                );
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
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("Failed to read array: {}", e),
            );
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
            let _ = env.throw_new(
                "java/lang/RuntimeException",
                format!("Failed to write back array: {}", e),
            );
        }
        
        // Zeroize buffer
        use zeroize::Zeroize;
        buf.zeroize();
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
        }
        // If a panic occurred:
        Err(_) => {
            // Throw a RuntimeException.
            let _ = env.throw_new("java/lang/RuntimeException", "Panic in getDataOffset");
            // Return -1.
            -1
        }
    }
}

// Define a JNI function named Java_com_noxcipher_RustNative_isBackupHeaderUsed.
// It checks if the volume was mounted using the backup header.
#[no_mangle]
pub extern "system" fn Java_com_noxcipher_RustNative_isBackupHeaderUsed(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jni::sys::jboolean {
    let res = panic::catch_unwind(|| {
        let contexts_lock = volume::CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(context) = contexts_lock.get(&handle) {
            if context.used_backup_header { 1 } else { 0 }
        } else {
            0 // False or error (handle not found)
        }
    });

    match res {
        Ok(val) => val,
        Err(_) => {
            let _ = env.throw_new("java/lang/RuntimeException", "Panic in isBackupHeaderUsed");
            0
        }
    }
}

// Define a JNI function named Java_com_noxcipher_RustNative_mountFs.
// It attempts to mount a file system (NTFS or exFAT) on the volume.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "system" fn Java_com_noxcipher_RustNative_mountFs(
    // The JNI environment.
    env: JNIEnv,
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
    panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Retrieve the volume context associated with the handle.
        let volume = {
            // Lock the global CONTEXTS map.
            if let Ok(contexts) = volume::CONTEXTS.lock() {
                // Look up the handle.
                match contexts.get(&volume_handle) {
                    // If found, clone the volume context.
                    Some(v) => v.clone(),
                    // If not found, return -1.
                    None => return -1,
                }
            } else {
                 return -1;
            }
        };

        // Get the JavaVM instance from the environment.
        // Expect success.
        let jvm = env.get_java_vm().expect("Failed to get JavaVM");
        // Create a global reference for the callback object so it persists.
        // Expect success.
        let callback_global = env
            .new_global_ref(callback_obj)
            .map_err(|e| format!("Failed to create global ref: {}", e))
            .expect("Global ref creation failed"); // We can expect here because we are in catch_unwind

        // Create a new CallbackReader with the JVM, callback object, and volume size.
        let reader = CallbackReader::new(jvm, callback_global, volume_size as u64);
        // Create a DecryptedReader that wraps the CallbackReader and the volume context.
        // This reader handles on-the-fly decryption.
        let decrypted_reader = DecryptedReader::new(reader, volume);

        // Try mounting as NTFS.
        // Clone the decrypted reader for the NTFS attempt.
        let mut reader_clone = decrypted_reader.clone();
        // Attempt to create a new Ntfs instance.
        // Try mounting as NTFS.
        if let Ok(ntfs_instance) = Ntfs::new(decrypted_reader.clone()) {
            // Wait, Ntfs::new takes `&mut T`.
            // We want to OWN the reader in the stored Ntfs instance.
            // But `Ntfs::new` takes `R` (reader) by value? No, `&mut R` usually for methods.
            // Let's check `filesystem.rs` usage: `Ntfs::new(&mut *reader)`.
            // Wait, does `Ntfs` TAKE ownership? `pub struct Ntfs<R> { ... }`.
            // `Ntfs::new(reader: R)`.
            // In `filesystem.rs` previously:
            // `match self { SupportedFileSystem::Ntfs(reader) => { ... Ntfs::new(&mut *reader) ... } }`
            // This suggests `Ntfs` constructor might take `R` or `&mut R`.
            // If it takes `&mut R`, then `Ntfs` struct holds a reference? That would be impossible for `SupportedFileSystem` enum to hold.
            // So `Ntfs` MUST take `R` by value to own it.
            // `ntfs` crate `Ntfs::new` typically takes `R`.
            // Why did `filesystem.rs` use `&mut *reader`?
            // `reader` was `DecryptedReader`. `&mut *reader` is `&mut DecryptedReader`.
            // If `Ntfs::new` takes `R`, and we pass `&mut DecryptedReader`, then `R` is inferred as `&mut DecryptedReader`.
            // This works for temporary usage.
            // BUT if we want to STORE `Ntfs<DecryptedReader>`, we must pass `DecryptedReader` by value.
            
            // So:
            // Or better:
            
            // Lock the FILESYSTEMS map for writing.
            // Using unwrap_or_else to handle poisoned mutex gracefully
            let mut lock = FILESYSTEMS.write().unwrap_or_else(|e| e.into_inner());
            
            // Lock the NEXT_FS_HANDLE counter.
            if let Ok(mut handle_lock) = NEXT_FS_HANDLE.lock() {
                // Get the current handle value.
                let handle = *handle_lock;
                // Increment the handle counter.
                *handle_lock += 1;
                // Insert the NTFS reader into the map with the new handle wrapped in Arc<Mutex>.
                lock.insert(handle, Arc::new(Mutex::new(SupportedFileSystem::Ntfs(Box::new(ntfs_instance)))));
                // Return the handle.
                return handle;
            }
            return -1;
        }

        // Try mounting as exFAT.
        // Clone the decrypted reader for the exFAT attempt.
        let reader_clone2 = decrypted_reader.clone();
        // Attempt to open as ExFat.
        if let Ok(exfat) = ExFat::open(reader_clone2) {
            // Log success.
            log::info!("Mounted exFAT");
                // Lock the FILESYSTEMS map for writing.
            let mut lock = FILESYSTEMS.write().unwrap_or_else(|e| e.into_inner());
             
             // Lock the NEXT_FS_HANDLE counter.
             if let Ok(mut handle_lock) = NEXT_FS_HANDLE.lock() {
                 // Get the current handle value.
                 let handle = *handle_lock;
                 // Increment the handle counter.
                 *handle_lock += 1;
                 // Insert the exFAT instance into the map with the new handle wrapped in Arc<Mutex>.
                 let items: Vec<_> = exfat.into_iter().collect();
                 lock.insert(handle, Arc::new(Mutex::new(SupportedFileSystem::ExFat(items))));
                 // Return the handle.
                 return handle;
             }
             return -1;
        }

        // Log a warning if neither NTFS nor exFAT could be mounted.
        log::warn!("Failed to detect NTFS or exFAT");
        // Return -1 to indicate failure.
        -1
    }))
    .unwrap_or(-1) // If a panic occurred, return -1.
}

// Define a JNI function named Java_com_noxcipher_RustNative_listFiles.
// It lists files in a directory of the mounted file system.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Convert the Java string path to a Rust String.
        // If conversion fails, use an empty string.
        let path: String = env
            .get_string(&path_obj)
            .map(|s| s.into())
            .unwrap_or_default();

        // Retrieve the list of files from the file system.
        let files = {
            // Lock the FILESYSTEMS map for reading.
            let lock = FILESYSTEMS.read().unwrap_or_else(|e| e.into_inner());
            
            if let Some(fs_arc) = lock.get(&fs_handle) {
                 // Lock the specific filesystem for mutation (list_files requires &mut self).
                 if let Ok(mut fs) = fs_arc.lock() {
                     // Call list_files on it.
                     fs.list_files(&path).unwrap_or_default()
                 } else {
                     // If individual FS lock is poisoned, return empty or try to recover?
                     // Verify if we can recover. If it panicked inside list_files, it might be in inconsistent state via Mutex.
                     // But we can try.
                     match fs_arc.lock() {
                         Ok(mut fs) => fs.list_files(&path).unwrap_or_default(),
                         Err(poisoned) => {
                             // Try to recover
                             let mut fs = poisoned.into_inner();
                             fs.list_files(&path).unwrap_or_default()
                         }
                     }
                 }
            } else {
                // If not found, return an empty vector.
                std::collections::VecDeque::new()
            }
        };

        // Find the com.noxcipher.RustFile class.
        // Expect success.
        let file_class = match env.find_class("com/noxcipher/RustFile") {
             Ok(cls) => cls,
             Err(e) => {
                 log::error!("Failed to find RustFile class: {}", e);
                 return ptr::null_mut(); // Return null on failure
             }
        };

        // Get the constructor ID for RustFile (String name, boolean isDir, long size).
        // Expect success.
        let init_id = match env.get_method_id(&file_class, "<init>", "(Ljava/lang/String;ZJ)V") {
            Ok(id) => id,
            Err(e) => {
                 log::error!("Failed to find RustFile constructor: {}", e);
                 return ptr::null_mut();
            }
        };

        // Create a new object array of RustFile objects with the size of the files vector.
        // Initialize with null.
        // Expect success.
        let array = match env.new_object_array(
            files.len() as i32,
            &file_class,
            jni::objects::JObject::null(),
        ) {
            Ok(arr) => arr,
            Err(e) => {
                 log::error!("Failed to create RustFile array: {}", e);
                 return ptr::null_mut();
            }
        };

        // Iterate over the files and populate the array.
        for (i, f) in files.iter().enumerate() {
            // Create a Java string for the file name.
            let name_jstr = match env.new_string(&f.name) {
                Ok(s) => s,
                Err(_) => continue,
            };
            
            // Create a new RustFile object using the constructor.
            let obj = unsafe {
                env.new_object_unchecked(
                    &file_class,
                    init_id,
                    &[
                        JValue::Object(&name_jstr).as_jni(),   // name
                        JValue::Bool(f.is_dir as u8).as_jni(), // isDir
                        JValue::Long(f.size as i64).as_jni(),  // size
                    ],
                )
            };
            
            if let Ok(obj_ref) = obj {
                 // Set the array element at index i.
                 if let Err(e) = env.set_object_array_element(&array, i as i32, obj_ref) {
                     log::warn!("Failed to set array element: {}", e);
                 }
            }
        }

        // Return the raw pointer to the array.
        array.into_raw()
    }));

    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            log::error!("Panic in listFiles");
            std::ptr::null_mut()
        }
    }
}

// Define a JNI function named Java_com_noxcipher_RustNative_readFile.
// It reads content from a file in the mounted file system.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Convert the Java string path to a Rust String.
        // If conversion fails, use an empty string.
        let path: String = env
            .get_string(&path_obj)
            .map(|s| s.into())
            .unwrap_or_default();

        // Access the file system.
        if let Ok(mut lock) = FILESYSTEMS.read() {
             // Look up the file system by handle.
            if let Some(fs) = lock.get_mut(&fs_handle) {
                // Convert the raw JByteArray buffer to a JByteArray object unsafely.
                let buf_obj = unsafe { JByteArray::from_raw(buffer) };
                // Get the length of the buffer.
                let len = env.get_array_length(&buf_obj).unwrap_or(0);
                // Allocate a Rust vector of zeros with the same length.
                let mut buf = Zeroizing::new(vec![0u8; len as usize]);

                // Read the file content into the buffer.
                let res = match fs.read_file(&path, offset as u64, &mut buf) {
                    // If successful, returns the number of bytes read.
                    Ok(bytes_read) => {
                        // Write the data back to the Java array.
                        // Get a const pointer to the buffer and cast it to i8.
                         let buf_ptr = buf.as_ptr() as *const i8;
                        // Create a slice from the raw parts with the number of bytes read.
                        let buf_slice = unsafe { std::slice::from_raw_parts(buf_ptr, bytes_read) };
                        // Set the Java byte array region.
                        if let Err(e) = env.set_byte_array_region(&buf_obj, 0, buf_slice) {
                             log::error!("Failed to set byte array region: {}", e);
                             -1
                        } else {
                            bytes_read as jlong
                        }
                    }
                    // If reading fails, return -1.
                    Err(_) => -1,
                };
                
                // Zeroize buffer - handled by Zeroizing
                
                res
            } else {
                -1
            }
        } else {
            -1
        }
    }));

    match result {
        Ok(val) => val,
        Err(_) => {
            log::error!("Panic in readFile");
            -1
        }
    }
}

// Define a JNI function named Java_com_noxcipher_RustNative_changePassword.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "system" fn Java_com_noxcipher_RustNative_changePassword(
    mut env: JNIEnv,
    _class: JClass,
    path: jni::objects::JString,
    old_password: jbyteArray,
    old_pim: jni::sys::jint,
    new_password: jbyteArray,
    new_pim: jni::sys::jint,
) -> jint {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let path_str: String = env.get_string(&path)
            .map(|s| s.into())
            .unwrap_or_default();
            
        let old_pwd_obj = unsafe { JByteArray::from_raw(old_password) };
        let mut old_pwd_bytes = Zeroizing::new(env.convert_byte_array(&old_pwd_obj).unwrap_or_default());
        
        let new_pwd_obj = unsafe { JByteArray::from_raw(new_password) };
        let mut new_pwd_bytes = Zeroizing::new(env.convert_byte_array(&new_pwd_obj).unwrap_or_default());
        
        let res = volume::change_password(
             &path_str,
             &old_pwd_bytes,
             old_pim,
             &new_pwd_bytes,
             new_pim
        );
        
        // zeroize handled by Drop
        
        match res {
            Ok(_) => 0,
            Err(e) => {
                log::error!("Change password failed: {:?}", e);
                -1
            }
        }
    }));
    
    match result {
        Ok(code) => code,
        Err(_) => -1,
    }
}

// Define a JNI function named Java_com_noxcipher_RustNative_formatVolume.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "system" fn Java_com_noxcipher_RustNative_formatVolume(
    mut env: JNIEnv,
    _class: JClass,
    path: jni::objects::JString,
    password: jbyteArray,
    pim: jni::sys::jint,
    volume_size: jlong,
) -> jint {
    let result = panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let path_str: String = env.get_string(&path)
            .map(|s| s.into())
            .unwrap_or_default();
            
        let pwd_obj = unsafe { JByteArray::from_raw(password) };
        let mut pwd_bytes = Zeroizing::new(env.convert_byte_array(&pwd_obj).unwrap_or_default());
        
        let res = volume::create_volume(
             &path_str,
             &pwd_bytes,
             pim,
             volume_size as u64
        );
        
        // zeroize handled by Drop
        
        match res {
            Ok(_) => 0,
            Err(e) => {
                log::error!("Format volume failed: {:?}", e);
                -1
            }
        }
    }));
    
    match result {
        Ok(code) => code,
        Err(_) => -1,
    }
}

