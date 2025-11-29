use std::io::{self, Read, Seek, SeekFrom};
use jni::objects::{GlobalRef, JValue};
use jni::JavaVM;

#[derive(Clone)]
pub struct CallbackReader {
    jvm: JavaVM,
    callback: GlobalRef,
    position: u64,
    size: u64,
}

impl CallbackReader {
    pub fn new(jvm: JavaVM, callback: GlobalRef, size: u64) -> Self {
        Self {
            jvm,
            callback,
            position: 0,
            size,
        }
    }
}

impl Read for CallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut env = self.jvm.attach_current_thread()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("JNI attach failed: {}", e)))?;

        let len = buf.len() as i32;
        let offset = self.position as i64;

        // Call read(offset, length)
        let result = env.call_method(
            &self.callback,
            "read",
            "(JI)[B",
            &[JValue::Long(offset), JValue::Int(len)],
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("JNI call failed: {}", e)))?;

        let byte_array = result.l()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("JNI result error: {}", e)))?;

        if byte_array.is_null() {
            return Ok(0); // EOF or error
        }
        
        let byte_array = byte_array.into_inner();
        let bytes = env.convert_byte_array(byte_array)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("JNI array conversion failed: {}", e)))?;

        let read_len = bytes.len();
        if read_len > buf.len() {
             return Err(io::Error::new(io::ErrorKind::Other, "Java returned more bytes than requested"));
        }

        buf[..read_len].copy_from_slice(&bytes);
        self.position += read_len as u64;

        Ok(read_len)
    }
}

impl Seek for CallbackReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(p) => {
                if self.size == 0 {
                     return Err(io::Error::new(io::ErrorKind::Other, "Cannot seek from end: size unknown"));
                }
                (self.size as i64 + p) as u64
            },
            SeekFrom::Current(p) => (self.position as i64 + p) as u64,
        };

        self.position = new_pos;
        Ok(new_pos)
    }
}
