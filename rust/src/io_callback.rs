 // Import standard I/O traits.
use std::io::{self, Read, Seek, SeekFrom};
// Import JNI types.
use jni::objects::{GlobalRef, JValue};
use jni::JavaVM;
use std::sync::Arc;
use std::ops::Deref;

// Import zeroize trait.
use zeroize::Zeroize;

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn other_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message)
}

fn validated_read_len(bytes_read: i32, buf_len: usize) -> io::Result<usize> {
    if bytes_read < 0 {
        return Err(other_error("Java read callback returned error (-1)"));
    }

    let read_len = bytes_read as usize;
    if read_len > buf_len {
        return Err(invalid_input("Java read callback exceeded requested buffer length"));
    }

    Ok(read_len)
}

fn checked_seek_position(current: u64, volume_size: u64, pos: SeekFrom) -> io::Result<u64> {
    match pos {
        SeekFrom::Start(p) => Ok(p),
        SeekFrom::End(p) => {
            if volume_size == 0 {
                return Err(other_error("Cannot seek from end: size unknown"));
            }

            if p >= 0 {
                volume_size
                    .checked_add(p as u64)
                    .ok_or_else(|| other_error("Seek overflow"))
            } else {
                volume_size
                    .checked_sub(p.unsigned_abs())
                    .ok_or_else(|| other_error("Seek underflow"))
            }
        }
        SeekFrom::Current(p) => {
            if p >= 0 {
                current
                    .checked_add(p as u64)
                    .ok_or_else(|| other_error("Seek overflow"))
            } else {
                current
                    .checked_sub(p.unsigned_abs())
                    .ok_or_else(|| other_error("Seek underflow"))
            }
        }
    }
}

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

        let buf_len = buf.len();

        let byte_array = env.new_byte_array(buf_len as i32).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("JNI array creation failed: {}", e))
        })?;

        let byte_buffer = env
            .call_static_method(
                "java/nio/ByteBuffer",
                "wrap",
                "([B)Ljava/nio/ByteBuffer;",
                &[JValue::Object(&byte_array)],
            )
            .map_err(|e| {
                let _ = env.exception_clear();
                io::Error::new(io::ErrorKind::Other, format!("JNI ByteBuffer.wrap failed: {}", e))
            })?
            .l()
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("JNI ByteBuffer.wrap result error: {}", e))
            })?;

        // Check for integer overflow when casting position to i64 (JNI limitation)
        let offset: i64 = self.position.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Offset too large for JNI (max 8EB)")
        })?;

        // Call Java method: int read(long offset, ByteBuffer buffer)
        let result = env
            .call_method(
                &*self.callback_obj,
                "read",
                "(JLjava/nio/ByteBuffer;)I",
                &[JValue::Long(offset), JValue::Object(&byte_buffer)],
            )
            .map_err(|e| {
                let _ = env.exception_clear(); 
                io::Error::new(io::ErrorKind::Other, format!("JNI call failed: {}", e))
            });

        // Delete the local reference to the ByteBuffer to prevent memory leak
        let _ = env.delete_local_ref(byte_buffer);

        let result = result?;

        // Get int result.
        let bytes_read = result.i().map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("JNI result error: {}", e))
        })?;

        let read_len = match validated_read_len(bytes_read, buf_len) {
            Ok(read_len) => read_len,
            Err(err) => {
                let _ = env.delete_local_ref(byte_array);
                return Err(err);
            }
        };

        if read_len > 0 {
            // SAFE COPY: Use get_byte_array_region to copy data from the Java byte[] 
            // back to the Rust buffer. This is the safe way to handle JNI memory.
            env.get_byte_array_region(&byte_array, 0, buf[..read_len].as_mut())
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("JNI array region copy failed: {}", e))
                })?;
        }

        let _ = env.delete_local_ref(byte_array);

        // Update position.
        self.position = self
            .position
            .checked_add(read_len as u64)
            .ok_or_else(|| other_error("Read position overflow"))?;

        // Return bytes read.
        Ok(read_len)
    }
}

// Implement Seek trait for CallbackReader.
impl Seek for CallbackReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = checked_seek_position(self.position, self.volume_size, pos)?;

        // Update position.
        self.position = new_pos;
        Ok(new_pos)
    }
}

#[cfg(test)]
mod tests {
    use super::{checked_seek_position, validated_read_len};
    use std::io::SeekFrom;

    #[test]
    fn rejects_callback_read_larger_than_buffer() {
        let err = validated_read_len(9, 8).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn accepts_exact_buffer_length() {
        assert_eq!(validated_read_len(8, 8).unwrap(), 8);
    }

    #[test]
    fn rejects_seek_from_unknown_end() {
        let err = checked_seek_position(0, 0, SeekFrom::End(0)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn rejects_seek_underflow() {
        let err = checked_seek_position(4, 64, SeekFrom::Current(-5)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn computes_seek_from_end() {
        assert_eq!(checked_seek_position(0, 64, SeekFrom::End(-8)).unwrap(), 56);
    }
}
