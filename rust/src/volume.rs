use crate::crypto::{SupportedCipher, KuznyechikWrapper, CamelliaWrapper};
use crate::header::{VolumeHeader, HeaderError};
use aes::Aes256;
use xts_mode::Xts128;
use pbkdf2::pbkdf2;
use hmac::{Hmac, SimpleHmac};
use sha2::{Sha512, Sha256};
use whirlpool::Whirlpool;
use serpent::Serpent;
use twofish::Twofish;
use blake2::Blake2s256;
use streebog::Streebog512;
use ripemd::Ripemd160;
use zeroize::Zeroize;
use std::sync::Mutex;
use std::fmt;
use cipher::{KeyInit, KeySizeUser, BlockCipher};
use cipher::consts::{U32, U64};

#[derive(Debug)]
pub enum VolumeError {
    InvalidPassword,
    InvalidHeader(HeaderError),
    CryptoError(String),
    NotInitialized,
}

impl From<HeaderError> for VolumeError {
    fn from(e: HeaderError) -> Self {
        VolumeError::InvalidHeader(e)
    }
}

impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VolumeError::InvalidPassword => write!(f, "Invalid password or PIM"),
            VolumeError::InvalidHeader(e) => write!(f, "Invalid volume header: {}", e),
            VolumeError::CryptoError(msg) => write!(f, "Crypto Error: {}", msg),
            VolumeError::NotInitialized => write!(f, "Volume not initialized"),
        }
    }
}

pub struct Volume {
    header: VolumeHeader,
    cipher: SupportedCipher,
    partition_start_offset: u64,
    read_only: bool,
}

// Send is required for Mutex.
unsafe impl Send for Volume {}

impl Volume {
    pub fn new(header: VolumeHeader, cipher: SupportedCipher, partition_start_offset: u64, read_only: bool) -> Self {
        Volume { header, cipher, partition_start_offset, read_only }
    }

    pub fn decrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<(), VolumeError> {
        let sector_size = self.header.sector_size as usize;
        
        if data.len() % sector_size != 0 {
            return Err(VolumeError::CryptoError(format!("Data length {} is not a multiple of sector size {}", data.len(), sector_size)));
        }

        let mut offset = 0;
        while offset < data.len() {
            let current_sector = sector_index + (offset / sector_size) as u64;
            
            // Tweak calculation fix:
            // VeraCrypt uses 0-based sector index relative to the start of the Data Area for standard volumes.
            // The `sector_index` passed here is assumed to be relative to the start of the Data Area (VolumeDataOffset).
            // So we just use it directly.
            // For system encryption or partitions where we might need physical sector numbers, 
            // `partition_start_offset` would be relevant, but for standard file containers or non-system partitions,
            // the tweak is just the relative sector index.
            
            // However, we must handle sector sizes > 512.
            // VeraCrypt: unitNo = startUnitNo + (offset / ENCRYPTION_DATA_UNIT_SIZE)
            // ENCRYPTION_DATA_UNIT_SIZE is 512 (XTS block size).
            // So if sector size is 4096, we process 8 XTS units per sector.
            // The `cipher.decrypt_area` handles the loop over units if we pass the correct start unit.
            
            // If `current_sector` is the sector index (0, 1, 2...),
            // The start unit number is `current_sector * (sector_size / 512)`.
            
            let start_unit_no = current_sector * (self.header.sector_size as u64 / 512);
            
            self.cipher.decrypt_area(&mut data[offset..offset+sector_size], sector_size, start_unit_no);
            offset += sector_size;
        }
        Ok(())
    }

    pub fn encrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<(), VolumeError> {
        if self.read_only {
             return Err(VolumeError::CryptoError("Volume is Read-Only".to_string()));
        }

        let sector_size = self.header.sector_size as usize;
        if data.len() % sector_size != 0 {
            return Err(VolumeError::CryptoError(format!("Data length {} is not a multiple of sector size {}", data.len(), sector_size)));
        }

        let mut offset = 0;
        while offset < data.len() {
            let current_sector = sector_index + (offset / sector_size) as u64;
            let start_unit_no = current_sector * (self.header.sector_size as u64 / 512);
            
            self.cipher.encrypt_area(&mut data[offset..offset+sector_size], sector_size, start_unit_no);
            offset += sector_size;
        }
        Ok(())
    }
}

// Global map of contexts, keyed by a handle (ID).
lazy_static::lazy_static! {
    pub static ref CONTEXTS: Mutex<std::collections::HashMap<i64, Volume>> = Mutex::new(std::collections::HashMap::new());
    static ref NEXT_HANDLE: Mutex<i64> = Mutex::new(1);
}

pub fn create_context(password: &[u8], header_bytes: &[u8], pim: i32) -> Result<i64, VolumeError> {
    if header_bytes.len() < 512 { return Err(VolumeError::InvalidHeader(HeaderError::InvalidMagic)); }
    
    let salt = &header_bytes[..64];
    let encrypted_header = &header_bytes[64..512];
    
    // Iteration counts based on VeraCrypt source (Pkcs5Kdf.cpp)
    // If PIM is 0 (default):
    // SHA-512: 500,000
    // SHA-256: 500,000
    // Whirlpool: 500,000
    // Streebog: 500,000
    // Blake2s: 200,000 (Wait, VC uses 500,000 for all except Blake2s?)
    // Let's verify Blake2s default. VC 1.26: Blake2s is 200,000? No, it's 500,000 for system encryption, but for standard?
    // Checking VeraCrypt source Pkcs5Kdf.h:
    // default_iterations = 500000;
    // But for RIPEMD160 it is 655331 (Legacy)
    
    let iterations_default = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 500_000 };
    let iterations_ripemd = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 655_331 };
    let iterations_blake2s = if pim > 0 { 15000 + (pim as u32 * 1000) } else { 500_000 }; // VeraCrypt uses 500k for standard volumes

    let mut header_key = [0u8; 192]; // Max key size (Serpent-Twofish-AES = 192 bytes)

    // Helper to try all ciphers with a derived key
    let try_unlock = |key: &[u8]| -> Result<Volume, VolumeError> {
        // Try AES
        if let Ok(v) = try_cipher::<Aes256>(key, encrypted_header, |k1, k2| SupportedCipher::Aes(Xts128::new(Aes256::new(k1.into()), Aes256::new(k2.into())))) { return Ok(v); }
        
        // Try Serpent
        if let Ok(v) = try_cipher_serpent(key, encrypted_header) { return Ok(v); }
        
        // Try Twofish
        if let Ok(v) = try_cipher::<Twofish>(key, encrypted_header, |k1, k2| SupportedCipher::Twofish(Xts128::new(Twofish::new(k1.into()), Twofish::new(k2.into())))) { return Ok(v); }
        
        // Try Cascades...
        // For brevity in this fix, I'll implement the most common ones and the structure for others.
        // The previous implementation had them all, I should restore them.
        
        if let Ok(v) = try_cipher_aes_twofish(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_aes_twofish_serpent(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_serpent_aes(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_twofish_serpent(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_serpent_twofish_aes(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_camellia(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_kuznyechik(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_camellia_kuznyechik(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_camellia_serpent(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_kuznyechik_aes(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_kuznyechik_serpent_camellia(key, encrypted_header) { return Ok(v); }
        if let Ok(v) = try_cipher_kuznyechik_twofish(key, encrypted_header) { return Ok(v); }

        Err(VolumeError::InvalidPassword)
    };

    // 1. SHA-512
    log::info!("Trying SHA-512 KDF");
    pbkdf2::<Hmac<Sha512>>(password, salt, iterations_default, &mut header_key).ok();
    if let Ok(vol) = try_unlock(&header_key) { return register_context(vol); }

    // 2. SHA-256
    log::info!("Trying SHA-256 KDF");
    pbkdf2::<Hmac<Sha256>>(password, salt, iterations_default, &mut header_key).ok();
    if let Ok(vol) = try_unlock(&header_key) { return register_context(vol); }

    // 3. Whirlpool
    log::info!("Trying Whirlpool KDF");
    pbkdf2::<Hmac<Whirlpool>>(password, salt, iterations_default, &mut header_key).ok();
    if let Ok(vol) = try_unlock(&header_key) { return register_context(vol); }

    // 4. Blake2s
    log::info!("Trying Blake2s KDF");
    pbkdf2::<SimpleHmac<Blake2s256>>(password, salt, iterations_blake2s, &mut header_key).ok();
    if let Ok(vol) = try_unlock(&header_key) { return register_context(vol); }

    // 5. Streebog
    log::info!("Trying Streebog KDF");
    pbkdf2::<SimpleHmac<Streebog512>>(password, salt, iterations_default, &mut header_key).ok();
    if let Ok(vol) = try_unlock(&header_key) { return register_context(vol); }
    
    // 6. RIPEMD-160
    log::info!("Trying RIPEMD-160 KDF");
    pbkdf2::<Hmac<Ripemd160>>(password, salt, iterations_ripemd, &mut header_key).ok();
    let res = try_unlock(&header_key);
    header_key.zeroize(); // Zeroize key after use
    if let Ok(vol) = res { return register_context(vol); }

    Err(VolumeError::InvalidPassword)
}

fn register_context(vol: Volume) -> Result<i64, VolumeError> {
    let mut handle_lock = NEXT_HANDLE.lock().unwrap_or_else(|e| e.into_inner());
    let handle = *handle_lock;
    *handle_lock += 1;
    
    let mut contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    contexts_lock.insert(handle, vol);
    
    Ok(handle)
}

pub fn decrypt(handle: i64, offset: u64, data: &mut [u8]) -> Result<(), VolumeError> {
    let contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(context) = contexts_lock.get(&handle) {
        let start_sector = offset / (context.header.sector_size as u64);
        context.decrypt_sector(start_sector, data)
    } else {
        Err(VolumeError::CryptoError("Invalid handle".to_string()))
    }
}

pub fn encrypt(handle: i64, offset: u64, data: &mut [u8]) -> Result<(), VolumeError> {
    let contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(context) = contexts_lock.get(&handle) {
        let start_sector = offset / (context.header.sector_size as u64);
        context.encrypt_sector(start_sector, data)
    } else {
        Err(VolumeError::CryptoError("Invalid handle".to_string()))
    }
}

pub fn close_context(handle: i64) {
    if let Ok(mut contexts_lock) = CONTEXTS.lock() {
        contexts_lock.remove(&handle);
    }
}

pub fn get_data_offset(handle: i64) -> Result<u64, VolumeError> {
    let contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(context) = contexts_lock.get(&handle) {
        Ok(context.header.encrypted_area_start)
    } else {
        Err(VolumeError::CryptoError("Invalid handle".to_string()))
    }
}

// --- Cipher specific try functions ---

fn try_cipher<C: BlockCipher + KeySizeUser + KeyInit>(
    header_key: &[u8], 
    encrypted_header: &[u8],
    create_cipher: impl Fn(&[u8], &[u8]) -> SupportedCipher
) -> Result<Volume, VolumeError> {
    let key_size = C::key_size();
    if header_key.len() < key_size * 2 { return Err(VolumeError::CryptoError("Key too short".into())); }
    
    let key_1 = &header_key[0..key_size];
    let key_2 = &header_key[key_size..key_size*2];
    
    // We need to construct Xts128 manually or use the callback.
    // But Xts128 needs the cipher instance.
    // The callback approach is cleaner for generic XTS construction if we passed cipher instances,
    // but here we are constructing the SupportedCipher enum variant.
    
    let cipher_enum = create_cipher(key_1, key_2);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    
    // Decrypt header using sector 0, tweak 0?
    // Header is not sector 0. Header is encrypted with XTS using 0 as tweak?
    // VeraCrypt: "The header is encrypted in XTS mode... The secondary key... is used to encrypt the 64-bit data unit number... which is 0 for the volume header."
    cipher_enum.decrypt_area(&mut decrypted, 512, 0); // Sector size 512 for header? Yes.

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        // Found it! Now derive the master keys for the volume data.
        // The master keys are in the decrypted header at offset 192.
        // We need to create the volume cipher using these keys.
        
        let mk = &header.master_key_data;
        // Re-create the SAME cipher mode but with the master keys.
        let vol_cipher = create_cipher(&mk[0..key_size], &mk[key_size..key_size*2]);
        
        if header.is_key_vulnerable(key_size) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        return Ok(Volume::new(header, vol_cipher, 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_serpent(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    let key_1 = &header_key[0..32];
    let key_2 = &header_key[32..64];
    let cipher_1 = Serpent::new_from_slice(key_1).map_err(|_| VolumeError::CryptoError("Invalid key".into()))?;
    let cipher_2 = Serpent::new_from_slice(key_2).map_err(|_| VolumeError::CryptoError("Invalid key".into()))?;
    let xts = Xts128::new(cipher_1, cipher_2);
    let cipher_enum = SupportedCipher::Serpent(xts);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let c1 = Serpent::new_from_slice(&mk[0..32]).map_err(|_| VolumeError::CryptoError("Invalid key".into()))?;
        let c2 = Serpent::new_from_slice(&mk[32..64]).map_err(|_| VolumeError::CryptoError("Invalid key".into()))?;
        let vol_cipher = SupportedCipher::Serpent(Xts128::new(c1, c2));
        return Ok(Volume::new(header, vol_cipher, 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_aes_twofish(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // Order: Twofish, AES (Inner to Outer for Decryption? No, Outer to Inner)
    // VeraCrypt EncryptionModeXTS.cpp:
    // Encrypt: Ciphers[0] -> Ciphers[1] ...
    // Decrypt: Ciphers[N] -> ... -> Ciphers[0]
    //
    // For "AES-Twofish", the list is [AES, Twofish].
    // So Encrypt is AES then Twofish.
    // Decrypt is Twofish then AES.
    //
    // Keys in header_key:
    // AES key (64), Twofish key (64).
    // Wait, `try_cipher_aes_twofish` in original code used:
    // key_twofish_1 (0..32), key_aes_1 (32..64) ...
    // This implies the key order in `header_key` is Twofish then AES?
    // Let's check VeraCrypt `VolumeHeader::DeriveKey`.
    // It calls `pkcs5->DeriveKey`. The result is `headerKey`.
    // Then it iterates encryptionModes.
    // For AES-Twofish, it sets keys.
    //
    // Actually, let's look at `try_cipher_aes_twofish` in the original `volume.rs` I read.
    // It used:
    // let key_twofish_1 = &header_key[0..32];
    // let key_aes_1 = &header_key[32..64];
    //
    // This suggests the derived key has Twofish first.
    //
    // And decryption:
    // xts_aes.decrypt_area...
    // xts_twofish.decrypt_area...
    //
    // If Decrypt is Twofish -> AES, then it should be `xts_twofish` then `xts_aes`.
    // But original code did `xts_aes` then `xts_twofish`.
    // This means original code assumed "AES-Twofish" meant AES is the *inner* layer?
    // Or maybe "AES-Twofish" means AES then Twofish (Encrypt).
    // So Decrypt is Twofish then AES.
    //
    // If original code did AES then Twofish for decryption, it matches "Twofish-AES" order.
    //
    // Let's stick to the logic:
    // "AES(Twofish(Data))" -> Decrypt: Twofish_Decrypt(AES_Decrypt(Data))?
    // No, Decrypt(Encrypt(M)) = M.
    // Decrypt(AES(Twofish(M))) = Twofish_Decrypt(AES_Decrypt(AES(Twofish(M)))) = Twofish_Decrypt(Twofish(M)) = M.
    // So yes, reverse order.
    //
    // If "AES-Twofish" means AES is first applied (outer?), then Decrypt is AES then Twofish.
    // If "AES-Twofish" means AES then Twofish (cascade), usually means Encrypt = Twofish(AES(M)).
    //
    // VeraCrypt "AES-Twofish":
    // Outer: AES? Inner: Twofish?
    //
    // Let's assume the original code was mostly correct on *order* but I should verify with `SupportedCipher` enum.
    // `SupportedCipher::AesTwofish` implementation:
    // decrypt_area: xts_aes.decrypt ... xts_twofish.decrypt.
    // This means AES decrypt then Twofish decrypt.
    // This implies Encrypt was Twofish then AES.
    // So "AES-Twofish" in `SupportedCipher` means "Twofish then AES" encryption?
    //
    // Let's just implement `try_cipher_aes_twofish` using `SupportedCipher::AesTwofish`.
    // And ensure we map keys correctly.
    
    // VeraCrypt AESTwofish: Twofish then AES.
    // Key mapping: 0..32 -> Twofish, 32..64 -> AES.
    
    let key_twofish_1 = &header_key[0..32];
    let key_aes_1 = &header_key[32..64];
    let key_twofish_2 = &header_key[64..96];
    let key_aes_2 = &header_key[96..128];

    let cipher_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));
    let cipher_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));
    
    let cipher_enum = SupportedCipher::AesTwofish(cipher_aes, cipher_twofish);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        // Keys in master key area:
        // VeraCrypt AESTwofish: Key[0..32]->Twofish, Key[32..64]->AES.
        // Wait, check EncryptionAlgorithm.cpp:
        // AESTwofish::AESTwofish() { Ciphers.push_back(Twofish); Ciphers.push_back(AES); }
        // SetKey: keyOffset=0 -> Twofish, keyOffset=32 -> AES.
        // So Twofish uses 0..32, AES uses 32..64.
        
        let mk_twofish = &mk[0..64];
        let mk_aes = &mk[64..128];
        
        let vol_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
        let vol_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
        
        return Ok(Volume::new(header, SupportedCipher::AesTwofish(vol_aes, vol_twofish), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_aes_twofish_serpent(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: Serpent, Twofish, AES
    let key_serpent_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_aes_1 = &header_key[64..96];
    
    let key_serpent_2 = &header_key[96..128];
    let key_twofish_2 = &header_key[128..160];
    let key_aes_2 = &header_key[160..192];
    
    let xts_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));
    let xts_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));
    let xts_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    
    let cipher_enum = SupportedCipher::AesTwofishSerpent(xts_aes, xts_twofish, xts_serpent);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_serpent = &mk[0..64];
        let mk_twofish = &mk[64..128];
        let mk_aes = &mk[128..192];
        
        let vol_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
        let vol_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        
        return Ok(Volume::new(header, SupportedCipher::AesTwofishSerpent(vol_aes, vol_twofish, vol_serpent), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_serpent_aes(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: AES, Serpent
    let key_aes_1 = &header_key[0..32];
    let key_serpent_1 = &header_key[32..64];
    let key_aes_2 = &header_key[64..96];
    let key_serpent_2 = &header_key[96..128];
    
    let xts_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    let xts_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));
    
    let cipher_enum = SupportedCipher::SerpentAes(xts_serpent, xts_aes);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_aes = &mk[0..64];
        let mk_serpent = &mk[64..128];
        
        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        let vol_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
        
        return Ok(Volume::new(header, SupportedCipher::SerpentAes(vol_serpent, vol_aes), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_twofish_serpent(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: Serpent, Twofish
    let key_serpent_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_serpent_2 = &header_key[64..96];
    let key_twofish_2 = &header_key[96..128];
    
    let xts_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));
    let xts_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    
    let cipher_enum = SupportedCipher::TwofishSerpent(xts_twofish, xts_serpent);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_serpent = &mk[0..64];
        let mk_twofish = &mk[64..128];
        
        let vol_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        
        return Ok(Volume::new(header, SupportedCipher::TwofishSerpent(vol_twofish, vol_serpent), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_serpent_twofish_aes(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: AES, Twofish, Serpent
    let key_aes_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_serpent_1 = &header_key[64..96];
    
    let key_aes_2 = &header_key[96..128];
    let key_twofish_2 = &header_key[128..160];
    let key_serpent_2 = &header_key[160..192];
    
    let xts_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    let xts_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));
    let xts_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));
    
    let cipher_enum = SupportedCipher::SerpentTwofishAes(xts_serpent, xts_twofish, xts_aes);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_aes = &mk[0..64];
        let mk_twofish = &mk[64..128];
        let mk_serpent = &mk[128..192];
        
        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        let vol_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
        let vol_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
        
        return Ok(Volume::new(header, SupportedCipher::SerpentTwofishAes(vol_serpent, vol_twofish, vol_aes), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_camellia(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    let key_1 = &header_key[0..32];
    let key_2 = &header_key[32..64];
    let xts = Xts128::new(CamelliaWrapper::new(key_1.into()), CamelliaWrapper::new(key_2.into()));
    let cipher_enum = SupportedCipher::Camellia(xts);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let vol_xts = Xts128::new(CamelliaWrapper::new(mk[0..32].into()), CamelliaWrapper::new(mk[32..64].into()));
        return Ok(Volume::new(header, SupportedCipher::Camellia(vol_xts), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_kuznyechik(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    let key_1 = &header_key[0..32];
    let key_2 = &header_key[32..64];
    let xts = Xts128::new(KuznyechikWrapper::new(key_1.into()), KuznyechikWrapper::new(key_2.into()));
    let cipher_enum = SupportedCipher::Kuznyechik(xts);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let vol_xts = Xts128::new(KuznyechikWrapper::new(mk[0..32].into()), KuznyechikWrapper::new(mk[32..64].into()));
        return Ok(Volume::new(header, SupportedCipher::Kuznyechik(vol_xts), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_camellia_kuznyechik(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: Kuznyechik, Camellia
    let key_kuznyechik_1 = &header_key[0..32];
    let key_camellia_1 = &header_key[32..64];
    let key_kuznyechik_2 = &header_key[64..96];
    let key_camellia_2 = &header_key[96..128];
    
    let xts_camellia = Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into()));
    let xts_kuznyechik = Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()));
    
    let cipher_enum = SupportedCipher::CamelliaKuznyechik(xts_camellia, xts_kuznyechik);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_kuznyechik = &mk[0..64];
        let mk_camellia = &mk[64..128];
        
        let vol_camellia = Xts128::new(CamelliaWrapper::new(mk_camellia[0..32].into()), CamelliaWrapper::new(mk_camellia[32..64].into()));
        let vol_kuznyechik = Xts128::new(KuznyechikWrapper::new(mk_kuznyechik[0..32].into()), KuznyechikWrapper::new(mk_kuznyechik[32..64].into()));
        
        return Ok(Volume::new(header, SupportedCipher::CamelliaKuznyechik(vol_camellia, vol_kuznyechik), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_camellia_serpent(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: Serpent, Camellia
    let key_serpent_1 = &header_key[0..32];
    let key_camellia_1 = &header_key[32..64];
    let key_serpent_2 = &header_key[64..96];
    let key_camellia_2 = &header_key[96..128];
    
    let xts_camellia = Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into()));
    let xts_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    
    let cipher_enum = SupportedCipher::CamelliaSerpent(xts_camellia, xts_serpent);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_serpent = &mk[0..64];
        let mk_camellia = &mk[64..128];
        
        let vol_camellia = Xts128::new(CamelliaWrapper::new(mk_camellia[0..32].into()), CamelliaWrapper::new(mk_camellia[32..64].into()));
        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        
        return Ok(Volume::new(header, SupportedCipher::CamelliaSerpent(vol_camellia, vol_serpent), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_kuznyechik_aes(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: AES, Kuznyechik
    let key_aes_1 = &header_key[0..32];
    let key_kuznyechik_1 = &header_key[32..64];
    let key_aes_2 = &header_key[64..96];
    let key_kuznyechik_2 = &header_key[96..128];
    
    let xts_kuznyechik = Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()));
    let xts_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));
    
    let cipher_enum = SupportedCipher::KuznyechikAes(xts_kuznyechik, xts_aes);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_aes = &mk[0..64];
        let mk_kuznyechik = &mk[64..128];
        
        let vol_kuznyechik = Xts128::new(KuznyechikWrapper::new(mk_kuznyechik[0..32].into()), KuznyechikWrapper::new(mk_kuznyechik[32..64].into()));
        let vol_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
        
        return Ok(Volume::new(header, SupportedCipher::KuznyechikAes(vol_kuznyechik, vol_aes), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_kuznyechik_serpent_camellia(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: Camellia, Serpent, Kuznyechik
    let key_camellia_1 = &header_key[0..32];
    let key_serpent_1 = &header_key[32..64];
    let key_kuznyechik_1 = &header_key[64..96];
    
    let key_camellia_2 = &header_key[96..128];
    let key_serpent_2 = &header_key[128..160];
    let key_kuznyechik_2 = &header_key[160..192];
    
    let xts_kuznyechik = Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()));
    let xts_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    let xts_camellia = Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into()));
    
    let cipher_enum = SupportedCipher::KuznyechikSerpentCamellia(xts_kuznyechik, xts_serpent, xts_camellia);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_camellia = &mk[0..64];
        let mk_serpent = &mk[64..128];
        let mk_kuznyechik = &mk[128..192];
        
        let vol_kuznyechik = Xts128::new(KuznyechikWrapper::new(mk_kuznyechik[0..32].into()), KuznyechikWrapper::new(mk_kuznyechik[32..64].into()));
        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        let vol_camellia = Xts128::new(CamelliaWrapper::new(mk_camellia[0..32].into()), CamelliaWrapper::new(mk_camellia[32..64].into()));
        
        return Ok(Volume::new(header, SupportedCipher::KuznyechikSerpentCamellia(vol_kuznyechik, vol_serpent, vol_camellia), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_kuznyechik_twofish(header_key: &[u8], encrypted_header: &[u8]) -> Result<Volume, VolumeError> {
    // VeraCrypt: Twofish, Kuznyechik
    let key_twofish_1 = &header_key[0..32];
    let key_kuznyechik_1 = &header_key[32..64];
    let key_twofish_2 = &header_key[64..96];
    let key_kuznyechik_2 = &header_key[96..128];
    
    let xts_kuznyechik = Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()));
    let xts_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));
    
    let cipher_enum = SupportedCipher::KuznyechikTwofish(xts_kuznyechik, xts_twofish);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_twofish = &mk[0..64];
        let mk_kuznyechik = &mk[64..128];
        
        let vol_kuznyechik = Xts128::new(KuznyechikWrapper::new(mk_kuznyechik[0..32].into()), KuznyechikWrapper::new(mk_kuznyechik[32..64].into()));
        let vol_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
        
        return Ok(Volume::new(header, SupportedCipher::KuznyechikTwofish(vol_kuznyechik, vol_twofish), 0, false));
    }
    Err(VolumeError::InvalidPassword)
}
