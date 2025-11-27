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
use cipher::KeyInit;

// Type alias for the XTS cipher. We need a trait object or enum to handle different ciphers.
// For simplicity in this "try-all" approach, we'll define an enum.
pub enum SupportedCipher {
    Aes(Xts128<Aes256>),
    Serpent(Xts128<Serpent>),
    Twofish(Xts128<Twofish>),
    AesTwofish(Xts128<Aes256>, Xts128<Twofish>),
    AesTwofishSerpent(Xts128<Aes256>, Xts128<Twofish>, Xts128<Serpent>),
}

impl SupportedCipher {
    fn decrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u128) {
        match self {
            SupportedCipher::Aes(xts) => xts.decrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::Serpent(xts) => xts.decrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::Twofish(xts) => xts.decrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::AesTwofish(xts_aes, xts_twofish) => {
                xts_aes.decrypt_area(data, sector_size, sector_index, get_tweak_default);
                xts_twofish.decrypt_area(data, sector_size, sector_index, get_tweak_default);
            },
            SupportedCipher::AesTwofishSerpent(xts_aes, xts_twofish, xts_serpent) => {
                xts_aes.decrypt_area(data, sector_size, sector_index, get_tweak_default);
                xts_twofish.decrypt_area(data, sector_size, sector_index, get_tweak_default);
                xts_serpent.decrypt_area(data, sector_size, sector_index, get_tweak_default);
            },
        }
    }

    fn encrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u128) {
        match self {
            SupportedCipher::Aes(xts) => xts.encrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::Serpent(xts) => xts.encrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::Twofish(xts) => xts.encrypt_area(data, sector_size, sector_index, get_tweak_default),
            SupportedCipher::AesTwofish(xts_aes, xts_twofish) => {
                xts_twofish.encrypt_area(data, sector_size, sector_index, get_tweak_default);
                xts_aes.encrypt_area(data, sector_size, sector_index, get_tweak_default);
            },
            SupportedCipher::AesTwofishSerpent(xts_aes, xts_twofish, xts_serpent) => {
                xts_serpent.encrypt_area(data, sector_size, sector_index, get_tweak_default);
                xts_twofish.encrypt_area(data, sector_size, sector_index, get_tweak_default);
                xts_aes.encrypt_area(data, sector_size, sector_index, get_tweak_default);
            },
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




    
    // Helper to try specific KDF + All Ciphers
    fn try_unlock_with_derived_key(header_key: &[u8], encrypted_header: &[u8]) -> Result<Self, VolumeError> {
        // Try AES
        if let Ok(ctx) = Self::try_cipher_aes(header_key, encrypted_header) { return Ok(ctx); }
        // Try Serpent
        if let Ok(ctx) = Self::try_cipher_serpent(header_key, encrypted_header) { return Ok(ctx); }
        // Try Twofish
        // Try Twofish
        if let Ok(ctx) = Self::try_cipher_twofish(header_key, encrypted_header) { return Ok(ctx); }
        // Try AES-Twofish
        if let Ok(ctx) = Self::try_cipher_aes_twofish(header_key, encrypted_header) { return Ok(ctx); }
        // Try AES-Twofish-Serpent
        if let Ok(ctx) = Self::try_cipher_aes_twofish_serpent(header_key, encrypted_header) { return Ok(ctx); }
        
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

    fn try_cipher_aes_twofish(header_key: &[u8], encrypted_header: &[u8]) -> Result<Self, VolumeError> {
        let key_1 = &header_key[0..32];
        let key_2 = &header_key[32..64];
        let cipher_aes_1 = Aes256::new(key_1.into());
        let cipher_aes_2 = Aes256::new(key_2.into());
        let xts_aes = Xts128::new(cipher_aes_1, cipher_aes_2);

        let cipher_twofish_1 = Twofish::new(key_1.into());
        let cipher_twofish_2 = Twofish::new(key_2.into());
        let xts_twofish = Xts128::new(cipher_twofish_1, cipher_twofish_2);
        
        let mut decrypted = [0u8; 448];
        decrypted.copy_from_slice(encrypted_header);
        // Decrypt: AES then Twofish
        xts_aes.decrypt_area(&mut decrypted, 512, 0, get_tweak_default);
        xts_twofish.decrypt_area(&mut decrypted, 512, 0, get_tweak_default);

        if &decrypted[0..4] == b"VERA" {
             let master_key_offset = 256 - 64; // Standard offset
             // For cascades, master keys are concatenated? 
             // AES key (64) + Twofish key (64) = 128 bytes
             let mk_aes = &decrypted[master_key_offset..master_key_offset+64];
             let mk_twofish = &decrypted[master_key_offset+64..master_key_offset+128];
             
             let vol_xts_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
             let vol_xts_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
             
             return Ok(VeracryptContext { cipher: SupportedCipher::AesTwofish(vol_xts_aes, vol_xts_twofish) });
        }
        Err(VolumeError::InvalidPassword)
    }

    fn try_cipher_aes_twofish_serpent(header_key: &[u8], encrypted_header: &[u8]) -> Result<Self, VolumeError> {
        let key_1 = &header_key[0..32];
        let key_2 = &header_key[32..64];
        
        let xts_aes = Xts128::new(Aes256::new(key_1.into()), Aes256::new(key_2.into()));
        let xts_twofish = Xts128::new(Twofish::new(key_1.into()), Twofish::new(key_2.into()));
        let xts_serpent = Xts128::new(Serpent::new(key_1.into()), Serpent::new(key_2.into()));
        
        let mut decrypted = [0u8; 448];
        decrypted.copy_from_slice(encrypted_header);
        
        // Decrypt: AES -> Twofish -> Serpent
        xts_aes.decrypt_area(&mut decrypted, 512, 0, get_tweak_default);
        xts_twofish.decrypt_area(&mut decrypted, 512, 0, get_tweak_default);
        xts_serpent.decrypt_area(&mut decrypted, 512, 0, get_tweak_default);

        if &decrypted[0..4] == b"VERA" {
             let master_key_offset = 256 - 64;
             // AES (64) + Twofish (64) + Serpent (64) = 192 bytes
             let mk_aes = &decrypted[master_key_offset..master_key_offset+64];
             let mk_twofish = &decrypted[master_key_offset+64..master_key_offset+128];
             let mk_serpent = &decrypted[master_key_offset+128..master_key_offset+192];
             
             let vol_xts_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
             let vol_xts_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
             let vol_xts_serpent = Xts128::new(Serpent::new(mk_serpent[0..32].into()), Serpent::new(mk_serpent[32..64].into()));
             
             return Ok(VeracryptContext { cipher: SupportedCipher::AesTwofishSerpent(vol_xts_aes, vol_xts_twofish, vol_xts_serpent) });
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
