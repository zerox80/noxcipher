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
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::sync::{Mutex, Arc};
use std::fmt;
use cipher::{KeyInit, KeySizeUser, BlockCipher};

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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Volume {
    header: VolumeHeader,
    #[zeroize(skip)]
    cipher: SupportedCipher,
    partition_start_offset: u64,
    hidden_volume_offset: u64,
    read_only: bool,
    protected_range_start: u64,
    protected_range_end: u64,
}

// Send is required for Mutex.
unsafe impl Send for Volume {}

impl Volume {
    pub fn new(header: VolumeHeader, cipher: SupportedCipher, partition_start_offset: u64, hidden_volume_offset: u64, read_only: bool) -> Self {
        Volume { header, cipher, partition_start_offset, hidden_volume_offset, read_only, protected_range_start: 0, protected_range_end: 0 }
    }

    pub fn set_protection(&mut self, start: u64, end: u64) {
        self.protected_range_start = start;
        self.protected_range_end = end;
    }

    pub fn sector_size(&self) -> u32 {
        self.header.sector_size
    }

    pub fn decrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<(), VolumeError> {
        let sector_size = self.header.sector_size as usize;
        
        if data.len() % 512 != 0 {
            return Err(VolumeError::CryptoError(format!("Data length {} is not a multiple of XTS data unit size 512", data.len())));
        }

        let mut offset = 0;
        while offset < data.len() {
            let current_sector = sector_index + (offset / sector_size) as u64;
            
            // VeraCrypt XTS uses 512-byte data units regardless of sector size.
            // For a 4096-byte sector, we process 8 units with sequential tweaks.
            let units_per_sector = sector_size / 512;
            
            for i in 0..units_per_sector {
                let unit_offset = i * 512;
                let unit_data_offset = offset + unit_offset;
                
                // Calculate unit number (tweak)
                // unitNo = startUnitNo + i
                // startUnitNo = (partition_start_offset + encrypted_area_start + current_sector * sector_size) / 512
                let start_unit_no = (self.partition_start_offset + self.header.encrypted_area_start + current_sector * sector_size as u64) / 512;
                let unit_no = start_unit_no + i as u64;
                
                self.cipher.decrypt_area(
                    &mut data[unit_data_offset..unit_data_offset+512], 
                    512, 
                    unit_no
                );
            }
            offset += sector_size;
        }
        Ok(())
    }

    pub fn encrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<(), VolumeError> {
        if self.read_only {
             return Err(VolumeError::CryptoError("Volume is Read-Only".to_string()));
        }

        let sector_size = self.header.sector_size as usize;
        let start_offset = sector_index * sector_size as u64;
        let end_offset = start_offset + data.len() as u64;

        // Check hidden volume protection
        if self.protected_range_end > 0 {
            // Check overlap
            // protected_range is physical offset? Or logical?
            // In create_context, we set it using `hidden_vol.header.encrypted_area_start`.
            // That is physical offset relative to volume start.
            // Here start_offset is logical.
            // We must convert start_offset to physical.
            let phys_start = self.header.encrypted_area_start + start_offset;
            let phys_end = self.header.encrypted_area_start + end_offset;

            if (phys_start < self.protected_range_end) && (phys_end > self.protected_range_start) {
                 return Err(VolumeError::CryptoError("Write operation blocked by Hidden Volume Protection".to_string()));
            }
        }
        if data.len() % 512 != 0 {
            return Err(VolumeError::CryptoError(format!("Data length {} is not a multiple of XTS data unit size 512", data.len())));
        }

        let mut offset = 0;
        while offset < data.len() {
            let current_sector = sector_index + (offset / sector_size) as u64;
            
            let units_per_sector = sector_size / 512;
            
            for i in 0..units_per_sector {
                let unit_offset = i * 512;
                let unit_data_offset = offset + unit_offset;
                
                let start_unit_no = (self.partition_start_offset + self.header.encrypted_area_start + current_sector * sector_size as u64) / 512;
                let unit_no = start_unit_no + i as u64;
                
                self.cipher.encrypt_area(
                    &mut data[unit_data_offset..unit_data_offset+512], 
                    512, 
                    unit_no
                );
            }
            offset += sector_size;
        }
        Ok(())
    }
}

// Global map of contexts, keyed by a handle (ID).
lazy_static::lazy_static! {
    pub static ref CONTEXTS: Mutex<std::collections::HashMap<i64, Arc<Volume>>> = Mutex::new(std::collections::HashMap::new());
    static ref NEXT_HANDLE: Mutex<i64> = Mutex::new(1);
}

pub fn create_context(password: &[u8], header_bytes: &[u8], pim: i32, partition_start_offset: u64, protection_password: Option<&[u8]>, protection_pim: i32) -> Result<i64, VolumeError> {
    // Try Standard Header at offset 0
    if let Ok(mut vol) = try_header_at_offset(password, header_bytes, pim, 0, partition_start_offset) {
        // If protection is requested, try to mount hidden volume
        if let Some(prot_pass) = protection_password {
             if header_bytes.len() >= 65536 + 512 {
                 match try_header_at_offset(prot_pass, header_bytes, protection_pim, 65536, partition_start_offset) {
                     Ok(hidden_vol) => {
                         log::info!("Hidden Volume Protection Enabled");
                         // Calculate protected range
                         // Hidden volume is at the end of the outer volume?
                         // No, hidden volume is within the outer volume.
                         // We need to protect the area occupied by the hidden volume.
                         // The hidden volume header is at 65536.
                         // The hidden volume data starts at `hidden_vol.header.encrypted_area_start`?
                         // Actually, for hidden volume, `encrypted_area_start` is the offset relative to the start of the *host* volume (outer volume).
                         // So we protect from `encrypted_area_start` to `encrypted_area_start + encrypted_area_length`.
                         
                         let start = hidden_vol.header.encrypted_area_start;
                         let end = start + hidden_vol.header.encrypted_area_length;
                         vol.set_protection(start, end);
                     },
                     Err(_) => {
                         // If protection password provided but failed to mount hidden volume, fail the whole operation?
                         // VeraCrypt behavior: "Incorrect protection password" or similar.
                         return Err(VolumeError::CryptoError("Failed to mount hidden volume for protection".to_string()));
                     }
                 }
             } else {
                 return Err(VolumeError::CryptoError("Buffer too small for hidden volume check".to_string()));
             }
        }
        return register_context(vol);
    }
    
    // Try Hidden Volume Header at offset 65536 (64KB)
    // Only if NOT protecting (if protecting, we expect outer volume at 0)
    if protection_password.is_none() && header_bytes.len() >= 65536 + 512 {
        if let Ok(vol) = try_header_at_offset(password, header_bytes, pim, 65536, partition_start_offset) {
            log::info!("Mounted Hidden Volume");
            return register_context(vol);
        }
    }
    
    Err(VolumeError::InvalidPassword)
}



// Renamed helper to return Volume
fn try_header_at_offset(password: &[u8], full_buffer: &[u8], pim: i32, offset: usize, partition_start_offset: u64) -> Result<Volume, VolumeError> {
    if full_buffer.len() < offset + 512 {
        return Err(VolumeError::InvalidHeader(HeaderError::InvalidMagic));
    }
    
    let header_slice = &full_buffer[offset..offset+512];
    let salt = &header_slice[..64];
    let encrypted_header = &header_slice[64..512];

    // Iteration counts to try
    let mut iterations_list = Vec::new();
    
    if pim > 0 {
        iterations_list.push(15000 + (pim as u32 * 1000));
        // System Encryption / Boot (SHA-256, Blake2s, Streebog)
        iterations_list.push(pim as u32 * 2048);
    } else {
        // Default VeraCrypt
        iterations_list.push(500_000); 
        // System Encryption (SHA-256, Blake2s, Streebog)
        iterations_list.push(200_000);
        // Legacy TrueCrypt
        iterations_list.push(1000); 
        iterations_list.push(2000);
    }
    
    let mut header_key = [0u8; 192]; 

    // Helper to try all ciphers
    let try_unlock = |key: &[u8]| -> Result<Volume, VolumeError> {
        let hv_offset = offset as u64;
        // Try AES
        if let Ok(v) = try_cipher::<Aes256>(key, encrypted_header, partition_start_offset, hv_offset, |k1, k2| SupportedCipher::Aes(Xts128::new(Aes256::new(k1.into()), Aes256::new(k2.into())))) { return Ok(v); }
        // Try Serpent
        if let Ok(v) = try_cipher_serpent(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        // Try Twofish
        if let Ok(v) = try_cipher::<Twofish>(key, encrypted_header, partition_start_offset, hv_offset, |k1, k2| SupportedCipher::Twofish(Xts128::new(Twofish::new(k1.into()), Twofish::new(k2.into())))) { return Ok(v); }
        
        // Cascades
        if let Ok(v) = try_cipher_aes_twofish(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_aes_twofish_serpent(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_serpent_aes(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_twofish_serpent(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_serpent_twofish_aes(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_camellia(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_kuznyechik(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_camellia_kuznyechik(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_camellia_serpent(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_kuznyechik_aes(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_kuznyechik_serpent_camellia(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }
        if let Ok(v) = try_cipher_kuznyechik_twofish(key, encrypted_header, partition_start_offset, hv_offset) { return Ok(v); }

        Err(VolumeError::InvalidPassword)
    };

    for &iter in &iterations_list {
        // 1. SHA-512
        pbkdf2::<Hmac<Sha512>>(password, salt, iter, &mut header_key).ok();
        if let Ok(vol) = try_unlock(&header_key) { return Ok(vol); }

        // 2. SHA-256
        pbkdf2::<Hmac<Sha256>>(password, salt, iter, &mut header_key).ok();
        if let Ok(vol) = try_unlock(&header_key) { return Ok(vol); }

        // 3. Whirlpool
        pbkdf2::<Hmac<Whirlpool>>(password, salt, iter, &mut header_key).ok();
        if let Ok(vol) = try_unlock(&header_key) { return Ok(vol); }

        // 4. Blake2s
        // Blake2s default is 500,000. System/Boot is 200,000. PIM is pim*2048.
        // We just use `iter` from the list which covers these cases.
        pbkdf2::<SimpleHmac<Blake2s256>>(password, salt, iter, &mut header_key).ok();
        if let Ok(vol) = try_unlock(&header_key) { return Ok(vol); }

        // 5. Streebog
        pbkdf2::<SimpleHmac<Streebog512>>(password, salt, iter, &mut header_key).ok();
        if let Ok(vol) = try_unlock(&header_key) { return Ok(vol); }
        
        // 6. RIPEMD-160
        // VC Default: 655331. TC Legacy: 1000 or 2000. System Encryption: 327661. PIM: 15000 + pim*1000.
        // If PIM is provided, we use the calculated iter (15000+...).
        // If PIM=0, we need to map 500,000 -> 655,331 and 200,000 -> 327,661.
        let ripemd_iter = if pim > 0 { 
             // For RIPEMD-160, PIM formula is same as others? Yes.
             15000 + (pim as u32 * 1000) 
        } else { 
            if iter == 500_000 { 655_331 } else if iter == 200_000 { 327_661 } else { iter } 
        };
        
        pbkdf2::<Hmac<Ripemd160>>(password, salt, ripemd_iter, &mut header_key).ok();
        let res = try_unlock(&header_key);
        header_key.zeroize(); 
        if let Ok(vol) = res { return Ok(vol); }
    }

    Err(VolumeError::InvalidPassword)
}

fn register_context(vol: Volume) -> Result<i64, VolumeError> {
    let mut handle_lock = NEXT_HANDLE.lock().unwrap_or_else(|e| e.into_inner());
    let handle = *handle_lock;
    *handle_lock += 1;
    
    let mut contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    contexts_lock.insert(handle, Arc::new(vol));
    
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
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
            // return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, vol_cipher, partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_serpent(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
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

        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, vol_cipher, partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_aes_twofish(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
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
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::AesTwofish(vol_aes, vol_twofish), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_aes_twofish_serpent(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_serpent_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_aes_1 = &header_key[64..96];
    
    let key_serpent_2 = &header_key[96..128];
    let key_twofish_2 = &header_key[128..160];
    let key_aes_2 = &header_key[160..192];

    let cipher_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));
    let cipher_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));
    let cipher_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());

    let cipher_enum = SupportedCipher::AesTwofishSerpent(cipher_aes, cipher_twofish, cipher_serpent);
    
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
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::AesTwofishSerpent(vol_aes, vol_twofish, vol_serpent), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_serpent_aes(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_aes_1 = &header_key[0..32];
    let key_serpent_1 = &header_key[32..64];
    let key_aes_2 = &header_key[64..96];
    let key_serpent_2 = &header_key[96..128];

    let cipher_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    let cipher_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));

    let cipher_enum = SupportedCipher::SerpentAes(cipher_serpent, cipher_aes);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_aes = &mk[0..64];
        let mk_serpent = &mk[64..128];

        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        let vol_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::SerpentAes(vol_serpent, vol_aes), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_twofish_serpent(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_serpent_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_serpent_2 = &header_key[64..96];
    let key_twofish_2 = &header_key[96..128];

    let cipher_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));
    let cipher_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());

    let cipher_enum = SupportedCipher::TwofishSerpent(cipher_twofish, cipher_serpent);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_serpent = &mk[0..64];
        let mk_twofish = &mk[64..128];

        let vol_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::TwofishSerpent(vol_twofish, vol_serpent), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_serpent_twofish_aes(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_aes_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_serpent_1 = &header_key[64..96];
    let key_aes_2 = &header_key[96..128];
    let key_twofish_2 = &header_key[128..160];
    let key_serpent_2 = &header_key[160..192];

    let cipher_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    let cipher_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));
    let cipher_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));

    let cipher_enum = SupportedCipher::SerpentTwofishAes(cipher_serpent, cipher_twofish, cipher_aes);
    
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
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::SerpentTwofishAes(vol_serpent, vol_twofish, vol_aes), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_camellia(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    try_cipher::<CamelliaWrapper>(header_key, encrypted_header, partition_start_offset, hidden_volume_offset, |k1, k2| {
        SupportedCipher::Camellia(Xts128::new(CamelliaWrapper::new(k1.into()), CamelliaWrapper::new(k2.into())))
    })
}

fn try_cipher_kuznyechik(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    try_cipher::<KuznyechikWrapper>(header_key, encrypted_header, partition_start_offset, hidden_volume_offset, |k1, k2| {
        SupportedCipher::Kuznyechik(Xts128::new(KuznyechikWrapper::new(k1.into()), KuznyechikWrapper::new(k2.into())))
    })
}

fn try_cipher_camellia_kuznyechik(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_kuznyechik_1 = &header_key[0..32];
    let key_camellia_1 = &header_key[32..64];
    let key_kuznyechik_2 = &header_key[64..96];
    let key_camellia_2 = &header_key[96..128];

    let cipher_camellia = Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into()));
    let cipher_kuznyechik = Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()));

    let cipher_enum = SupportedCipher::CamelliaKuznyechik(cipher_camellia, cipher_kuznyechik);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_kuznyechik = &mk[0..64];
        let mk_camellia = &mk[64..128];

        let vol_camellia = Xts128::new(CamelliaWrapper::new(mk_camellia[0..32].into()), CamelliaWrapper::new(mk_camellia[32..64].into()));
        let vol_kuznyechik = Xts128::new(KuznyechikWrapper::new(mk_kuznyechik[0..32].into()), KuznyechikWrapper::new(mk_kuznyechik[32..64].into()));
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::CamelliaKuznyechik(vol_camellia, vol_kuznyechik), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_camellia_serpent(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_serpent_1 = &header_key[0..32];
    let key_camellia_1 = &header_key[32..64];
    let key_serpent_2 = &header_key[64..96];
    let key_camellia_2 = &header_key[96..128];

    let cipher_camellia = Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into()));
    let cipher_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());

    let cipher_enum = SupportedCipher::CamelliaSerpent(cipher_camellia, cipher_serpent);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_serpent = &mk[0..64];
        let mk_camellia = &mk[64..128];

        let vol_camellia = Xts128::new(CamelliaWrapper::new(mk_camellia[0..32].into()), CamelliaWrapper::new(mk_camellia[32..64].into()));
        let vol_serpent = Xts128::new(Serpent::new_from_slice(&mk_serpent[0..32]).unwrap(), Serpent::new_from_slice(&mk_serpent[32..64]).unwrap());
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::CamelliaSerpent(vol_camellia, vol_serpent), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_kuznyechik_aes(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_aes_1 = &header_key[0..32];
    let key_kuznyechik_1 = &header_key[32..64];
    let key_aes_2 = &header_key[64..96];
    let key_kuznyechik_2 = &header_key[96..128];

    let cipher_kuznyechik = Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()));
    let cipher_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));

    let cipher_enum = SupportedCipher::KuznyechikAes(cipher_kuznyechik, cipher_aes);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_aes = &mk[0..64];
        let mk_kuznyechik = &mk[64..128];

        let vol_kuznyechik = Xts128::new(KuznyechikWrapper::new(mk_kuznyechik[0..32].into()), KuznyechikWrapper::new(mk_kuznyechik[32..64].into()));
        let vol_aes = Xts128::new(Aes256::new(mk_aes[0..32].into()), Aes256::new(mk_aes[32..64].into()));
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::KuznyechikAes(vol_kuznyechik, vol_aes), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_kuznyechik_serpent_camellia(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_camellia_1 = &header_key[0..32];
    let key_serpent_1 = &header_key[32..64];
    let key_kuznyechik_1 = &header_key[64..96];
    let key_camellia_2 = &header_key[96..128];
    let key_serpent_2 = &header_key[128..160];
    let key_kuznyechik_2 = &header_key[160..192];

    let cipher_kuznyechik = Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()));
    let cipher_serpent = Xts128::new(Serpent::new_from_slice(key_serpent_1).unwrap(), Serpent::new_from_slice(key_serpent_2).unwrap());
    let cipher_camellia = Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into()));

    let cipher_enum = SupportedCipher::KuznyechikSerpentCamellia(cipher_kuznyechik, cipher_serpent, cipher_camellia);
    
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
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::KuznyechikSerpentCamellia(vol_kuznyechik, vol_serpent, vol_camellia), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}

fn try_cipher_kuznyechik_twofish(header_key: &[u8], encrypted_header: &[u8], partition_start_offset: u64, hidden_volume_offset: u64) -> Result<Volume, VolumeError> {
    let key_twofish_1 = &header_key[0..32];
    let key_kuznyechik_1 = &header_key[32..64];
    let key_twofish_2 = &header_key[64..96];
    let key_kuznyechik_2 = &header_key[96..128];

    let cipher_kuznyechik = Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()));
    let cipher_twofish = Xts128::new(Twofish::new(key_twofish_1.into()), Twofish::new(key_twofish_2.into()));

    let cipher_enum = SupportedCipher::KuznyechikTwofish(cipher_kuznyechik, cipher_twofish);
    
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 512, 0);

    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        let mk = &header.master_key_data;
        let mk_twofish = &mk[0..64];
        let mk_kuznyechik = &mk[64..128];

        let vol_kuznyechik = Xts128::new(KuznyechikWrapper::new(mk_kuznyechik[0..32].into()), KuznyechikWrapper::new(mk_kuznyechik[32..64].into()));
        let vol_twofish = Xts128::new(Twofish::new(mk_twofish[0..32].into()), Twofish::new(mk_twofish[32..64].into()));
        
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        return Ok(Volume::new(header, SupportedCipher::KuznyechikTwofish(vol_kuznyechik, vol_twofish), partition_start_offset, hidden_volume_offset, false));
    }
    Err(VolumeError::InvalidPassword)
}
