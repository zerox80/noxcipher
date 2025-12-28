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

        // Create a DirectByteBuffer wrapping the mutable slice.
        // UNSAFE: We must ensure Java does not retain reference to this ByteBuffer 
        // after this call returns, as the underlying memory (buf) lifetime is bound to this function.
        // Since we are calling a synchronous method 'read', and the ByteBuffer is local, this is active.
        let buf_ptr = buf.as_mut_ptr();
        let buf_len = buf.len();
        
        let byte_buffer = unsafe {
            env.new_direct_byte_buffer(buf_ptr, buf_len).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("JNI BB creation failed: {}", e))
            })?
        };

        // Check for integer overflow when casting position to i64 (JNI limitation)
        let offset: i64 = self.position.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Offset too large for JNI (max 8EB)")
        })?;

        // Call Java method: int read(long offset, ByteBuffer buffer)
        let result = env
            .call_method(
                &self.callback_obj,
                "read",
                "(JLjava/nio/ByteBuffer;)I",
                &[JValue::Long(offset), JValue::Object(&byte_buffer)],
            )
            .map_err(|e| {
                let _ = env.exception_clear(); 
                io::Error::new(io::ErrorKind::Other, format!("JNI call failed: {}", e))
            })?;

        // Get int result.
        let bytes_read = result.i().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("JNI result error: {}", e))
        })?;

        if bytes_read < 0 {
             return Err(io::Error::new(io::ErrorKind::Other, "Java read callback returned error (-1)"));
        }

        let read_len = bytes_read as usize;

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
