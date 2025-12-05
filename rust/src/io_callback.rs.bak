// Import standard I/O traits.
use std::io::{self, Read, Seek, SeekFrom};
// Import JNI types.
use jni::objects::{GlobalRef, JValue};
use jni::JavaVM;
use std::sync::Arc;

// Struct to read data via a Java callback.
#[derive(Clone)]
pub struct CallbackReader {
    // Java VM instance to attach threads.
    jvm: Arc<JavaVM>,
    // Global reference to the Java callback object.
    callback_obj: GlobalRef,
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
            callback_obj,
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
        let len = buf.len() as i32;
        let offset = self.position as i64;

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
            return Ok(0); // EOF or error
        }

        // Convert Java byte array to Rust Vec<u8>.
        let ba: jni::objects::JByteArray = byte_array.into();
        let bytes = env.convert_byte_array(&ba).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("JNI array conversion failed: {}", e))
        })?;

        // Check if returned data fits in buffer.
        let read_len = bytes.len();
        if read_len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Java returned more bytes than requested",
            ));
        }

        // Copy data to buffer.
        buf[..read_len].copy_from_slice(&bytes);
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
                (self.volume_size as i64 + p) as u64
            }
            SeekFrom::Current(p) => (self.position as i64 + p) as u64,
        };

        // Update position.
        self.position = new_pos;
        Ok(new_pos)
    }
}
