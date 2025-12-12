 // Import standard I/O traits.
use std::io::{self, Read, Seek, SeekFrom};
// Import JNI types.
use jni::objects::{GlobalRef, JValue};
use jni::JavaVM;
use std::sync::Arc;
use std::ops::Deref;

// Import zeroize trait.
use zeroize::Zeroize;

// Struct to read data via a Java callback.
#[derive(Clone)]
pub struct CallbackReader {
    // Java VM instance to attach threads.
    jvm: Arc<JavaVM>,
    // Global reference to the Java callback object.
    callback_obj: Arc<GlobalRef>,
    // Current read position.
    position: u64,
    // Total size of the data source.
    volume_size: u64,
}

// Implementation of CallbackReader.
impl CallbackReader {
    // Constructor.
    pub fn new(jvm: JavaVM, callback_obj: GlobalRef, volume_size: u64) -> Self {
        Self {
            jvm: Arc::new(jvm),
            callback_obj: Arc::new(callback_obj),
            position: 0,
            volume_size,
        }
    }
}

// Implement Read trait for CallbackReader.
impl Read for CallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // If buffer is empty, return 0.
        if buf.is_empty() {
            return Ok(0);
        }

        // Attach current thread to JVM.
        let mut env = self.jvm.attach_current_thread().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("JNI attach failed: {}", e))
        })?;

        // Prepare arguments.
        // Cap length at i32::MAX to prevent overflow when calling Java
        let len = std::cmp::min(buf.len(), i32::MAX as usize) as i32;
        // Check for integer overflow when casting position to i64 (JNI limitation)
        let offset: i64 = self.position.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Offset too large for JNI (max 8EB)")
        })?;

        // Call Java method: byte[] read(long offset, int length)
        let result = env
            .call_method(
                &self.callback_obj,
                "read",
                "(JI)[B",
                &[JValue::Long(offset), JValue::Int(len)],
            )
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("JNI call failed: {}", e)))?;

        // Get byte array from result.
        let byte_array = result.l().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("JNI result error: {}", e))
        })?;

        // Check for null (EOF or error).
        if byte_array.is_null() {
            return Ok(0);
        }

        // Wrap the JObject (array)
        let ba_obj = unsafe { jni::objects::JByteArray::from_raw(byte_array.into_raw()) };

        // Get the length of the array returned by Java.
        let read_len = env.get_array_length(&ba_obj).map_err(|e| {
             io::Error::new(io::ErrorKind::Other, format!("JNI array length error: {}", e))
        })? as usize;

        // Check if returned data fits in buffer.
        // If Java returns more than we asked, it's a protocol violation or buffer overflow risk.
        if read_len > buf.len() {
             // We can't copy everything. Error out.
             return Err(io::Error::new(
                io::ErrorKind::Other,
                "Java returned more bytes than requested",
            ));
        }

        // Get the bytes directly into our buffer using generic JNI interface (if available in this version)
        // or get_byte_array_region.
        // We need a mutable slice of `i8` or `u8` depending on JNI crate version?
        // `get_byte_array_region` takes `&mut [i8]` usually?
        // Let's check `lib.rs` usage: `env.get_byte_array_region(&data_obj, 0, buf_slice)` where `buf_slice` is `&mut [i8]`.
        // So we need to cast `buf` to `&mut [i8]`.
        // This is safe because `u8` and `i8` have same layout.
        
        let buf_slice = unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut i8, read_len)
        };

        env.get_byte_array_region(&ba_obj, 0, buf_slice).map_err(|e| {
             io::Error::new(io::ErrorKind::Other, format!("JNI copy failed: {}", e))
        })?;

        // Zeroize isn't needed for `buf` here (it's the output buffer, caller handles it).
        // But we avoided the intermediate `Vec<u8>`.

        // Update position.
        self.position += read_len as u64;

        // Return bytes read.
        Ok(read_len)
    }
}

// Implement Seek trait for CallbackReader.
impl Seek for CallbackReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Calculate new position.
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(p) => {
                if self.volume_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Cannot seek from end: size unknown",
                    ));
                }
                // Safe arithmetic for seek from end
                if p >= 0 {
                    self.volume_size.checked_add(p as u64)
                        .ok_or(io::Error::new(io::ErrorKind::Other, "Seek overflow"))?
                } else {
                     self.volume_size.checked_sub(p.unsigned_abs())
                        .ok_or(io::Error::new(io::ErrorKind::Other, "Seek underflow"))?
                }
            }
            SeekFrom::Current(p) => {
                if p >= 0 {
                    self.position.checked_add(p as u64)
                        .ok_or(io::Error::new(io::ErrorKind::Other, "Seek overflow"))?
                } else {
                    self.position.checked_sub(p.unsigned_abs())
                        .ok_or(io::Error::new(io::ErrorKind::Other, "Seek underflow"))?
                }
            }
        };

        // Update position.
        self.position = new_pos;
        Ok(new_pos)
    }
}
