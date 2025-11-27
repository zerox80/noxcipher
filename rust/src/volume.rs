use aes::Aes256;
use xts_mode::{Xts128, get_tweak_default};
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::{Sha512, Sha256};
use whirlpool::Whirlpool;
use serpent::Serpent;
use twofish::Twofish;
use std::sync::Mutex;
use std::fmt;
use cipher::{KeyInit, BlockDecrypt, BlockEncrypt};

// Type alias for the XTS cipher. We need a trait object or enum to handle different ciphers.
// For simplicity in this "try-all" approach, we'll define an enum.
pub enum SupportedCipher {
    Aes(Xts128<Aes256>),
    Serpent(Xts128<Serpent>),
    Twofish(Xts128<Twofish>),
    // Cascades could be added here, e.g., AesTwofish(Xts128<AesTwofish>)
}

impl SupportedCipher {
    fn decrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u128) {
        match self {
            SupportedCipher::Aes(xts) => xts.decrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::Serpent(xts) => xts.decrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::Twofish(xts) => xts.decrypt_area(data, sector_size, sector_index, get_tweak_default),
        }
    }

    fn encrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u128) {
        match self {
            SupportedCipher::Aes(xts) => xts.encrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::Serpent(xts) => xts.encrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::Twofish(xts) => xts.encrypt_area(data, sector_size, sector_index, get_tweak_default),
        }
    }
}

#[derive(Debug)]
pub enum VolumeError {
    InvalidPassword,
    InvalidHeader,
    CryptoError(String),
}

impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VolumeError::InvalidPassword => write!(f, "Invalid password or PIM"),
            VolumeError::InvalidHeader => write!(f, "Invalid volume header"),
            VolumeError::CryptoError(msg) => write!(f, "Crypto Error: {}", msg),
        }
    }
}

pub struct VeracryptContext {
    cipher: SupportedCipher,
}

// Send is required for Mutex.
unsafe impl Send for VeracryptContext {}

impl VeracryptContext {
    pub fn new(password: &[u8], header_bytes: &[u8], pim: i32) -> Result<Self, VolumeError> {
        if header_bytes.len() < 512 {
            return Err(VolumeError::InvalidHeader);
        }

        let salt = &header_bytes[..64];
        let encrypted_header = &header_bytes[64..512];

        // Iterations calculation
        let iterations_sha512 = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 500_000 };
        let iterations_sha256 = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 500_000 }; // Same for now
        let iterations_whirlpool = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 500_000 };

        // Try combinations. 
        // Real VeraCrypt tries all KDFs, then all Ciphers.
        
        // 1. Try SHA-512
        if let Ok(ctx) = Self::try_kdf::<Hmac<Sha512>>(password, salt, iterations_sha512, encrypted_header) {
            return Ok(ctx);
        }
        
        // 2. Try SHA-256
        if let Ok(ctx) = Self::try_kdf::<Hmac<Sha256>>(password, salt, iterations_sha256, encrypted_header) {
            return Ok(ctx);
        }

        // 3. Try Whirlpool
        if let Ok(ctx) = Self::try_kdf::<Hmac<Whirlpool>>(password, salt, iterations_whirlpool, encrypted_header) {
            return Ok(ctx);
        }

        Err(VolumeError::InvalidPassword)
    }

    fn try_kdf<D>(password: &[u8], salt: &[u8], iterations: u32, encrypted_header: &[u8]) -> Result<Self, VolumeError> 
    where D: digest::KeyInit + digest::Digest + digest::FixedOutput + digest::Update + Clone + Sync + Send // Simplified constraints
    {
        // This generic approach is tricky with rust-crypto traits. 
        // Let's unroll for simplicity or use specific calls.
        // Actually, pbkdf2 takes a generic PRF.
        Err(VolumeError::CryptoError("Generic KDF not implemented fully in this snippet".to_string()))
    }
    
    // Helper to try specific KDF + All Ciphers
    fn try_unlock_with_derived_key(header_key: &[u8], encrypted_header: &[u8]) -> Result<Self, VolumeError> {
        // Try AES
        if let Ok(ctx) = Self::try_cipher_aes(header_key, encrypted_header) { return Ok(ctx); }
        // Try Serpent
        if let Ok(ctx) = Self::try_cipher_serpent(header_key, encrypted_header) { return Ok(ctx); }
        // Try Twofish
        if let Ok(ctx) = Self::try_cipher_twofish(header_key, encrypted_header) { return Ok(ctx); }
        
        Err(VolumeError::InvalidPassword)
    }

    fn try_cipher_aes(header_key: &[u8], encrypted_header: &[u8]) -> Result<Self, VolumeError> {
        let key_1 = &header_key[0..32];
        let key_2 = &header_key[32..64];
        let cipher_1 = Aes256::new(key_1.into());
        let cipher_2 = Aes256::new(key_2.into());
        let xts = Xts128::new(cipher_1, cipher_2);
        
        let mut decrypted = [0u8; 448];
        decrypted.copy_from_slice(encrypted_header);
        xts.decrypt_area(&mut decrypted, 512, 0, get_tweak_default);

        if &decrypted[0..4] == b"VERA" {
             // Found it!
             let master_key_offset = 256 - 64;
             let mk1 = &decrypted[master_key_offset..master_key_offset+32];
             let mk2 = &decrypted[master_key_offset+32..master_key_offset+64];
             let vol_xts = Xts128::new(Aes256::new(mk1.into()), Aes256::new(mk2.into()));
             return Ok(VeracryptContext { cipher: SupportedCipher::Aes(vol_xts) });
        }
        Err(VolumeError::InvalidPassword)
    }

    fn try_cipher_serpent(header_key: &[u8], encrypted_header: &[u8]) -> Result<Self, VolumeError> {
        let key_1 = &header_key[0..32];
        let key_2 = &header_key[32..64];
        let cipher_1 = Serpent::new(key_1.into());
        let cipher_2 = Serpent::new(key_2.into());
        let xts = Xts128::new(cipher_1, cipher_2);
        
        let mut decrypted = [0u8; 448];
        decrypted.copy_from_slice(encrypted_header);
        xts.decrypt_area(&mut decrypted, 512, 0, get_tweak_default);

        if &decrypted[0..4] == b"VERA" {
             let master_key_offset = 256 - 64;
             let mk1 = &decrypted[master_key_offset..master_key_offset+32];
             let mk2 = &decrypted[master_key_offset+32..master_key_offset+64];
             let vol_xts = Xts128::new(Serpent::new(mk1.into()), Serpent::new(mk2.into()));
             return Ok(VeracryptContext { cipher: SupportedCipher::Serpent(vol_xts) });
        }
        Err(VolumeError::InvalidPassword)
    }

    fn try_cipher_twofish(header_key: &[u8], encrypted_header: &[u8]) -> Result<Self, VolumeError> {
        let key_1 = &header_key[0..32];
        let key_2 = &header_key[32..64];
        let cipher_1 = Twofish::new(key_1.into());
        let cipher_2 = Twofish::new(key_2.into());
        let xts = Xts128::new(cipher_1, cipher_2);
        
        let mut decrypted = [0u8; 448];
        decrypted.copy_from_slice(encrypted_header);
        xts.decrypt_area(&mut decrypted, 512, 0, get_tweak_default);

        if &decrypted[0..4] == b"VERA" {
             let master_key_offset = 256 - 64;
             let mk1 = &decrypted[master_key_offset..master_key_offset+32];
             let mk2 = &decrypted[master_key_offset+32..master_key_offset+64];
             let vol_xts = Xts128::new(Twofish::new(mk1.into()), Twofish::new(mk2.into()));
             return Ok(VeracryptContext { cipher: SupportedCipher::Twofish(vol_xts) });
        }
        Err(VolumeError::InvalidPassword)
    }

    pub fn decrypt_sector(&self, sector_index: u64, data: &mut [u8]) {
        let sector_size = 512;
        let chunks = data.chunks_mut(sector_size);
        for (i, chunk) in chunks.enumerate() {
            if chunk.len() == sector_size {
                let current_sector = sector_index + i as u64;
                self.cipher.decrypt_area(chunk, sector_size, current_sector as u128);
            }
        }
    }

    pub fn encrypt_sector(&self, sector_index: u64, data: &mut [u8]) {
        let sector_size = 512;
        let chunks = data.chunks_mut(sector_size);
        for (i, chunk) in chunks.enumerate() {
            if chunk.len() == sector_size {
                let current_sector = sector_index + i as u64;
                self.cipher.encrypt_area(chunk, sector_size, current_sector as u128);
            }
        }
    }
}

// Global map of contexts, keyed by a handle (ID).
lazy_static::lazy_static! {
    pub static ref CONTEXTS: Mutex<std::collections::HashMap<i64, VeracryptContext>> = Mutex::new(std::collections::HashMap::new());
    static ref NEXT_HANDLE: Mutex<i64> = Mutex::new(1);
}

pub fn create_context(password: &[u8], header: &[u8], pim: i32) -> Result<i64, VolumeError> {
    // We need to implement the top-level loop here or in new()
    // Let's implement the specific calls here to avoid generic hell in `new`
    
    let header_bytes = header;
    if header_bytes.len() < 512 { return Err(VolumeError::InvalidHeader); }
    let salt = &header_bytes[..64];
    let encrypted_header = &header_bytes[64..512];
    
    let iterations_sha512 = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 500_000 };
    let iterations_sha256 = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 500_000 };
    let iterations_whirlpool = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 500_000 };

    let mut header_key = [0u8; 64];

    // 1. SHA-512
    pbkdf2::<Hmac<Sha512>>(password, salt, iterations_sha512, &mut header_key).ok();
    if let Ok(ctx) = VeracryptContext::try_unlock_with_derived_key(&header_key, encrypted_header) {
        return register_context(ctx);
    }

    // 2. SHA-256
    pbkdf2::<Hmac<Sha256>>(password, salt, iterations_sha256, &mut header_key).ok();
    if let Ok(ctx) = VeracryptContext::try_unlock_with_derived_key(&header_key, encrypted_header) {
        return register_context(ctx);
    }

    // 3. Whirlpool
    pbkdf2::<Hmac<Whirlpool>>(password, salt, iterations_whirlpool, &mut header_key).ok();
    if let Ok(ctx) = VeracryptContext::try_unlock_with_derived_key(&header_key, encrypted_header) {
        return register_context(ctx);
    }

    Err(VolumeError::InvalidPassword)
}

fn register_context(context: VeracryptContext) -> Result<i64, VolumeError> {
    let mut handle_lock = NEXT_HANDLE.lock().unwrap();
    let handle = *handle_lock;
    *handle_lock += 1;
    
    let mut contexts_lock = CONTEXTS.lock().unwrap();
    contexts_lock.insert(handle, context);
    
    Ok(handle)
}

pub fn decrypt(handle: i64, offset: u64, data: &mut [u8]) -> Result<(), VolumeError> {
    let contexts_lock = CONTEXTS.lock().unwrap();
    if let Some(context) = contexts_lock.get(&handle) {
        let start_sector = offset / 512;
        context.decrypt_sector(start_sector, data);
        Ok(())
    } else {
        Err(VolumeError::CryptoError("Invalid handle".to_string()))
    }
}

pub fn encrypt(handle: i64, offset: u64, data: &mut [u8]) -> Result<(), VolumeError> {
    let contexts_lock = CONTEXTS.lock().unwrap();
    if let Some(context) = contexts_lock.get(&handle) {
        let start_sector = offset / 512;
        context.encrypt_sector(start_sector, data);
        Ok(())
    } else {
        Err(VolumeError::CryptoError("Invalid handle".to_string()))
    }
}

pub fn close_context(handle: i64) {
    let mut contexts_lock = CONTEXTS.lock().unwrap();
    contexts_lock.remove(&handle);
}
