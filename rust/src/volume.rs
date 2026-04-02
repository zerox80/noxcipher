// Import supported cipher wrappers from the crypto module.
use crate::crypto::{
    AesWrapper, CamelliaWrapper, KuznyechikWrapper, SerpentWrapper, SupportedCipher, TwofishWrapper,
};
// Import VolumeHeader and HeaderError from the header module.
use crate::header::{HeaderError, VolumeHeader};
// Import AES-256 cipher.
use aes::Aes256;
// Import XTS mode implementation.
use xts_mode::Xts128;
// Import PBKDF2 key derivation function.
use pbkdf2::pbkdf2;
// Import HMAC implementation.
use hmac::{Hmac, SimpleHmac};
// Import SHA-2 hash functions.
use sha2::{Sha256, Sha512};
use sha1::Sha1;
// Import Whirlpool hash function.
use whirlpool::Whirlpool;
// Import Serpent cipher.
use serpent::Serpent;
// Import Twofish cipher.
use twofish::Twofish;
// Import Blake2s hash function.
use blake2::Blake2s256;
// Import Streebog hash function.
use streebog::Streebog512;
// Import RIPEMD-160 hash function.
use ripemd::Ripemd160;
// Import Zeroize traits for secure memory clearing.
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
// Import standard library types.
use std::sync::{Arc, Mutex};
// Import formatting traits.
use std::fmt;
// Import cipher traits.
use cipher::{BlockCipher, KeyInit, KeySizeUser};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};

// Define an enumeration for volume-related errors.
#[derive(Debug)]
#[allow(dead_code)]
#[allow(unused_assignments)]
pub enum VolumeError {
    // Error indicating an invalid password or PIM.
    InvalidPassword(String),
    // Error indicating an invalid volume header.
    InvalidHeader(HeaderError),
    // Generic cryptographic error with a message.
    CryptoError(String),
    // Error indicating the volume is not initialized.
    NotInitialized,
    // Error indicating an I/O error.
    IoError(std::io::Error),
}

// Implement conversion from HeaderError to VolumeError.
impl From<HeaderError> for VolumeError {
    fn from(e: HeaderError) -> Self {
        // Wrap the HeaderError in VolumeError::InvalidHeader.
        VolumeError::InvalidHeader(e)
    }
}

// Implement conversion from std::io::Error to VolumeError.
impl From<std::io::Error> for VolumeError {
    fn from(e: std::io::Error) -> Self {
        VolumeError::IoError(e)
    }
}

// Implement Display trait for VolumeError to provide user-friendly messages.
impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Write "Invalid password or PIM" for InvalidPassword.
            VolumeError::InvalidPassword(debug) => write!(f, "Invalid password or PIM ({})", debug),
            // Write "Invalid volume header: " followed by the header error.
            VolumeError::InvalidHeader(e) => write!(f, "Invalid volume header: {}", e),
            // Write "Crypto Error: " followed by the message.
            VolumeError::CryptoError(msg) => write!(f, "Crypto Error: {}", msg),
            // Write "Volume not initialized" for NotInitialized.
            VolumeError::NotInitialized => write!(f, "Volume not initialized"),
            // Write "I/O Error: " followed by the error.
            VolumeError::IoError(e) => write!(f, "I/O Error: {}", e),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfAlgorithm {
    Sha512,
    Sha256,
    Whirlpool,
    Ripemd160,
    Streebog, // 512
    Blake2s, // 256
    Sha1, // Legacy
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    Aes,
    Serpent,
    Twofish,
    AesTwofish,
    AesTwofishSerpent,
    SerpentAes,
    TwofishSerpent,
    SerpentTwofishAes,
    Camellia,
    Kuznyechik,
    CamelliaKuznyechik,
    CamelliaSerpent,
    KuznyechikAes,
    KuznyechikSerpentCamellia,
    KuznyechikTwofish,
}

// Define the Volume struct representing a mounted volume.
// Derive Zeroize and ZeroizeOnDrop to securely clear sensitive data.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Volume {
    // The parsed volume header.
    header: VolumeHeader,
    // The cipher used for encryption/decryption. Skipped for zeroization as it might contain non-zeroizable types or is handled separately.
    // The cipher used for encryption/decryption.
    #[zeroize(skip)]
    cipher: SupportedCipher,
    // The offset where the partition starts.
    partition_start_offset: u64, 
    hidden_volume_offset: Option<u64>,
    
    // Flag indicating if the volume is read-only.
    read_only: bool,
    // Start of the protected range (for hidden volume protection).
    protected_range_start: u64,
    // End of the protected range.
    protected_range_end: u64,
    // Flag indicating if the backup header was used.
    pub used_backup_header: bool,
    // The offset of the header used to mount this volume
    pub header_offset: u64,
    // The PRF algorithm used for key derivation
    #[zeroize(skip)]
    pub prf: Option<PrfAlgorithm>,
}

// Implement Send trait for Volume to allow it to be sent across threads.
// This is unsafe because we are asserting it is safe to send.
unsafe impl Send for Volume {}
// Implement Sync trait for Volume to allow shared references across threads.
// Required for Arc<Volume> to be used safely in multi-threaded contexts.
unsafe impl Sync for Volume {}

// Implementation block for Volume methods.
impl Volume {
    // Constructor to create a new Volume instance.
    pub fn new(
        header: VolumeHeader,
        cipher: SupportedCipher,
        partition_start_offset: u64, 
        hidden_volume_offset: Option<u64>,
        header_offset: u64,
        read_only: bool,
        prf: Option<PrfAlgorithm>,
    ) -> Self {
        // Return a new Volume struct with initialized fields.
        Volume {
            header,
            cipher,
            partition_start_offset,
            hidden_volume_offset,
            read_only,
            protected_range_start: 0,
            protected_range_end: 0,
            used_backup_header: false,
            header_offset,
            prf,
        }
    }

    // Method to set the protected range for hidden volume protection.
    pub fn set_protection(&mut self, start: u64, end: u64) {
        // Set the start of the protected range.
        self.protected_range_start = start;
        // Set the end of the protected range.
        self.protected_range_end = end;
    }

    // Method to get the sector size of the volume.
    pub fn sector_size(&self) -> u32 {
        // Return the sector size from the header.
        self.header.sector_size
    }

    // Method to get the volume data size.
    pub fn size(&self) -> u64 {
        self.header.volume_data_size
    }

    pub fn data_offset(&self) -> u64 {
        self.header.encrypted_area_start
    }

    // Method to decrypt a sector of data.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn decrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<(), VolumeError> {
        // Get the sector size as usize.
        let sector_size = self.header.sector_size as usize;

        if data.len() % sector_size != 0 {
            // Return an error if not aligned.
            return Err(VolumeError::CryptoError(format!(
                "Data length {} is not a multiple of sector size {}",
                data.len(),
                sector_size
            )));
        }

        // Boundary check
        let end_offset = sector_index.checked_mul(sector_size as u64)
            .and_then(|o| o.checked_add(data.len() as u64))
            .ok_or(VolumeError::CryptoError("Sector index overflow".to_string()))?;
        
        if end_offset > self.header.volume_data_size {
             return Err(VolumeError::CryptoError("Sector out of bounds".to_string()));
        }

        // Initialize offset for processing data chunks.
        let mut offset = 0;
        // Loop through the data buffer.
        while offset < data.len() {
            // Calculate the current sector index based on the offset.
            let current_sector = sector_index + (offset / sector_size) as u64;

            // VeraCrypt XTS uses 512-byte data units regardless of sector size.
            // For a 4096-byte sector, we process 8 units with sequential tweaks.
            // Calculate how many 512-byte units are in a sector.
            let units_per_sector = sector_size / 512;

            // Iterate through each unit in the sector.
            for i in 0..units_per_sector {
                // Calculate the byte offset of the unit within the sector.
                let unit_offset = i * 512;
                // Calculate the absolute byte offset in the data buffer.
                let unit_data_offset = offset + unit_offset;

                // Calculate unit number (tweak)
                // unitNo = startUnitNo + i
                // startUnitNo = (partition_start_offset + encrypted_area_start + current_sector * sector_size) / 512
                // Calculate the starting unit number for the current sector.
                // Calculate unit number (tweak) carefully using checked arithmetic
                // unitNo = startUnitNo + i
                // startUnitNo = (partition_start_offset + encrypted_area_start + current_sector * sector_size) / 512
                
                let sector_offset = current_sector.checked_mul(sector_size as u64)
                    .ok_or(VolumeError::CryptoError("Sector offset overflow".to_string()))?;
                
                let abs_offset = self.partition_start_offset.checked_add(self.header.encrypted_area_start)
                    .and_then(|sum| sum.checked_add(sector_offset))
                    .ok_or(VolumeError::CryptoError("Absolute offset overflow".to_string()))?;
                
                let start_unit_no = abs_offset / 512;
                let unit_no = start_unit_no.checked_add(i as u64)
                    .ok_or(VolumeError::CryptoError("Unit number overflow".to_string()))?;

                // Decrypt the 512-byte area using the cipher.
                self.cipher.decrypt_area(
                    &mut data[unit_data_offset..unit_data_offset + 512],
                    512,
                    unit_no,
                );
            }
            // Move to the next sector.
            offset += sector_size;
        }
        // Return success.
        Ok(())
    }

    // Method to encrypt a sector of data.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn encrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<(), VolumeError> {
        // Check if the volume is read-only.
        if self.read_only {
            // Return error if writing to a read-only volume.
            return Err(VolumeError::CryptoError("Volume is Read-Only".to_string()));
        }

        // Get the sector size.
        let sector_size = self.header.sector_size as usize;
        // Calculate the start offset of the write operation.
        let start_offset = sector_index.checked_mul(sector_size as u64)
            .ok_or(VolumeError::CryptoError("Write start offset overflow".to_string()))?;
        // Calculate the end offset of the write operation.
        let end_offset = start_offset.checked_add(data.len() as u64)
            .ok_or(VolumeError::CryptoError("Write end offset overflow".to_string()))?;

        // Check hidden volume protection
        if self.protected_range_end > 0 {
            // Check overlap
            // protected_range is physical offset? Or logical?
            // In create_context, we set it using `hidden_vol.header.encrypted_area_start`.
            // That is physical offset relative to volume start.
            // Here start_offset is logical.
            // We must convert start_offset to physical.
            // Calculate physical start offset.
            let phys_start = self.partition_start_offset.checked_add(self.header.encrypted_area_start)
                .and_then(|sum| sum.checked_add(start_offset))
                .ok_or(VolumeError::CryptoError("Protected range physical start overflow".to_string()))?;
            // Calculate physical end offset.
            let phys_end = self.partition_start_offset.checked_add(self.header.encrypted_area_start)
                .and_then(|sum| sum.checked_add(end_offset))
                .ok_or(VolumeError::CryptoError("Protected range physical end overflow".to_string()))?;

            // Check if the write operation overlaps with the protected range.
            if (phys_start < self.protected_range_end) && (phys_end > self.protected_range_start) {
                // Return error if it overlaps, blocking the write.
                return Err(VolumeError::CryptoError(
                    "Write operation blocked by Hidden Volume Protection".to_string(),
                ));
            }
        }
        if data.len() % sector_size != 0 {
            // Return error if not aligned.
            return Err(VolumeError::CryptoError(format!(
                "Data length {} is not a multiple of sector size {}",
                data.len(),
                sector_size
            )));
        }

        // Boundary check
        let start_offset_calc = sector_index.checked_mul(sector_size as u64)
            .ok_or(VolumeError::CryptoError("Sector index overflow".to_string()))?;
        let end_offset_calc = start_offset_calc.checked_add(data.len() as u64)
            .ok_or(VolumeError::CryptoError("Write offset overflow".to_string()))?;

        if end_offset_calc > self.header.volume_data_size {
             return Err(VolumeError::CryptoError("Write sector out of bounds".to_string()));
        }

        // Initialize offset.
        let mut offset = 0;
        // Loop through data.
        while offset < data.len() {
            // Calculate current sector.
            let current_sector = sector_index + (offset / sector_size) as u64;

            // Calculate units per sector.
            let units_per_sector = sector_size / 512;

            // Iterate through units.
            for i in 0..units_per_sector {
                // Calculate unit offset.
                let unit_offset = i * 512;
                // Calculate data offset.
                let unit_data_offset = offset + unit_offset;

                // Calculate unit number (tweak).
                // Calculate unit number (tweak) with overflow protection.
                let sector_offset = current_sector.checked_mul(sector_size as u64)
                    .ok_or(VolumeError::CryptoError("Sector offset overflow".to_string()))?;

                let abs_offset = self.partition_start_offset.checked_add(self.header.encrypted_area_start)
                    .and_then(|sum| sum.checked_add(sector_offset))
                    .ok_or(VolumeError::CryptoError("Absolute offset overflow".to_string()))?;

                let start_unit_no = abs_offset / 512;
                let unit_no = start_unit_no.checked_add(i as u64)
                    .ok_or(VolumeError::CryptoError("Unit number overflow".to_string()))?;

                // Encrypt the area.
                self.cipher.encrypt_area(
                    &mut data[unit_data_offset..unit_data_offset + 512],
                    512,
                    unit_no,
                );
            }
            // Move to next sector.
            offset += sector_size;
        }
        // Return success.
        Ok(())
    }
}

// Global map of contexts, keyed by a handle (ID).
// Use lazy_static to initialize the global map lazily.
lazy_static::lazy_static! {
    // A thread-safe HashMap to store active volume contexts, protected by a Mutex.
    pub static ref CONTEXTS: Mutex<std::collections::HashMap<i64, Arc<Volume>>> = Mutex::new(std::collections::HashMap::new());
    // A counter for generating unique handles, protected by a Mutex.
    static ref NEXT_HANDLE: Mutex<i64> = Mutex::new(1);
}

// Function to create a new volume context (mount a volume).
// Function to create a new volume context (mount a volume).
pub fn create_context(
    password: &[u8],
    header_bytes: &[u8],
    pim: i32,
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset_bias: u64, // The physical offset where header_bytes starts
    protection_password: Option<&[u8]>,
    protection_pim: i32,
    volume_size: u64,
    backup_header_bytes: Option<&[u8]>,
) -> Result<i64, VolumeError> {
    // Check PIM validity
    if pim < 0 {
        return Err(VolumeError::InvalidPassword("PIM cannot be negative".to_string()));
    }
    if protection_pim < 0 {
        return Err(VolumeError::InvalidPassword("Protection PIM cannot be negative".to_string()));
    }

    // 1. Try Standard Header at offset 0 (relative to header_offset_bias)
    let mut attempt_errors = Vec::new();
    
    // Attempt to decrypt the header at the beginning of the buffer.
    match try_header_at_offset(
        password,
        header_bytes,
        pim,
        header_offset_bias + 0u64, // Use absolute offset
        partition_start_offset,
        None,
    ) {
        Ok(mut vol) => {
             // If protection is requested, try to mount hidden volume
            if let Some(prot_pass) = protection_password {
                // Check if buffer is large enough for hidden volume header (at 64KB).
                if header_bytes.len() >= 65536 + 512 {
                    // Attempt to decrypt the hidden volume header.
                    match try_header_at_offset(
                        prot_pass,
                        header_bytes,
                        protection_pim,
                        header_offset_bias + 65536u64, // Absolute offset
                        partition_start_offset,
                        None,
                    ) {
                        Ok(hidden_vol) => {
                            log::info!("Hidden Volume Protection Enabled");
                            // Protect the hidden volume header (at 65536) and data.
                            // The hidden volume data is located at hidden_vol.header.encrypted_area_start relative to the volume start.
                            // We must protect the Hidden Volume Header AND the Hidden Volume Data.
                            // Actually, protecting the header (64KB offset) is good, but usually we just protect the data area?
                            // VeraCrypt documentation says: "When a hidden volume is protected... write operations to the hidden volume area will be rejected."
                            // The hidden volume header is at 65536. If we overwrite it, we destroy the hidden volume entry point.
                            // However, strictly speaking, the "Protected Range" usually refers to the data area. 
                            // But usually usage includes preserving the header.
                            // Let's protect the Data Area primarily as that's the large area.
                            // The code below was: offset 65536 + size. This assumes data starts at 65536, which is WRONG.
                            
                            // Correct logic:
                            // Protected Range Start = header_offset_bias + hidden_vol.header.encrypted_area_start
                            // Protected Range End = Protected Range Start + hidden_vol.header.volume_data_size
                            
                            let start = header_offset_bias.checked_add(hidden_vol.header.encrypted_area_start)
                                .ok_or(VolumeError::CryptoError("Hidden volume start offset overflow".to_string()))?;
                            
                            let end = start.checked_add(hidden_vol.header.volume_data_size)
                                .ok_or(VolumeError::CryptoError("Hidden volume end offset overflow".to_string()))?;
                                
                            vol.set_protection(start, end);
                        }
                        Err(_) => {
                            return Err(VolumeError::CryptoError(
                                "Failed to mount hidden volume for protection".to_string(),
                            ));
                        }
                    }
                } else {
                    return Err(VolumeError::CryptoError(
                        "Buffer too small for hidden volume check".to_string(),
                    ));
                }
            }
            return register_context(vol);
        },
        Err(e) => attempt_errors.push(format!("Primary: {}", e)),
    }

    // 2. Try Hidden Volume Header at offset 65536 (64KB)
    // Only if NOT protecting (if protecting, we expect outer volume at 0)
    if protection_password.is_none() && header_bytes.len() >= 65536 + 512 {
        // Attempt to decrypt header at 64KB offset.
        if let Ok(vol) = try_header_at_offset(
            password,
            header_bytes,
            pim,
            header_offset_bias + 65536u64, // Absolute offset
            partition_start_offset,
            None,
        ) {
            log::info!("Mounted Hidden Volume");
            return register_context(vol);
        }
    }

    // 3. Try Backup Header at offset (Volume Size - 131072)
    // VeraCrypt stores a backup header at the end of the volume.
    // Offset is: volume_size - 131072
    if protection_password.is_none() {
        if let Some(bh) = backup_header_bytes {
            // Backup Header provided by caller (preferred for large volumes where we don't map everything)
            if bh.len() >= 512 {
                 // The backup header decryption uses the same logic, but we need to know the offset for relative checks?
                 // Actually, for backup header, the offset passed to XTS (if any) is usually relative to the volume end?
                 // But in `try_header_at_offset` we use `offset` to slice buffer.
                 // Here `bh` is the buffer starting at the backup header. So offset 0 relative to `bh`.
                 // But `try_header_at_offset` uses `offset` as `u64` for XTS tweak if applicable?
                 // Wait, `try_header_at_offset` takes `offset` (usize) and `partition_start_offset` (u64).
                 // Inside: `let hv_offset = offset as u64;`
                 // XTS tweak usually depends on the data unit number.
                 // For the header, it is encrypted with XTS.
                 // The tweak for the header is 0??
                 // "The secondary key... is used to encrypt the 64-bit data unit number... which is 0 for the volume header."
                 // So `hv_offset` passed to `try_cipher` should be 0?
                 // `try_header_at_offset` calls `try_cipher` with `hv_offset`.
                 // Let's check `try_header_at_offset` logic again.
                 // It calls `try_cipher` with `hv_offset`.
                 // `try_cipher` calls `create_cipher`? No, it calls `decrypt_area` with tweak 0?
                 // Ah, `try_cipher` calls `cipher_enum.decrypt_area(&mut decrypted, 448, 0);`
                 // It PASSES 0 AS TWEAK regardless of `hv_offset`.
                 // So `hv_offset` argument to try_cipher seems unused for the header tweak itself!
                 // Let's verify `try_cipher` (it was not fully shown in previous view).
                 // I need to be careful.
                 
                 // If I use `try_header_at_offset` with `bh` and offset 0, it should work for backup header
                 // because the tweak 0 is hardcoded in `try_cipher` variants (seen in `try_cipher_serpent` etc).
                 
                 match try_header_at_offset(password, bh, pim, 0u64, partition_start_offset, None) {
                     Ok(mut vol) => {
                         log::info!("Mounted Backup Header");
                         vol.used_backup_header = true;
                         // Fix Bug 4: Update header_offset to absolute position
                         if volume_size >= 131072 {
                             vol.header_offset = volume_size - 131072;
                         }
                         return register_context(vol);
                     }
                     Err(_) => attempt_errors.push("Backup Header: Failed".to_string()),
                 }
            }
        } else if volume_size >= 131072 {
            // Fallback to legacy behavior if backup_header_bytes not provided but buffer might be large enough
            let backup_offset = volume_size - 131072;
            
            // Check overflow for + 512
            if backup_offset.checked_add(512).map_or(false, |end| (header_bytes.len() as u64) >= end) {
                 if let Ok(mut vol) = try_header_at_offset(
                    password, 
                    header_bytes, 
                    pim, 
                    backup_offset, // Now passing u64
                    partition_start_offset,
                    None
                ) {
                    log::info!("Mounted Backup Header (Embedded)");
                    vol.used_backup_header = true;
                    return register_context(vol);
                } else {
                     attempt_errors.push("Backup Header (Embedded): Failed".to_string());
                }
            }
        }
    }

    Err(VolumeError::InvalidPassword(format!("All attempts failed. Errors: {:?}", attempt_errors)))
}

const EFFECTIVE_HEADER_SIZE: usize = 512;
const HEADER_SALT_SIZE: usize = 64;
const ENCRYPTED_HEADER_SIZE: usize = EFFECTIVE_HEADER_SIZE - HEADER_SALT_SIZE;
const XTS_KEY_SIZE: usize = 32;
const PRIMARY_VOLUME_HEADER_AREA_SIZE: u64 = 131072;
const TOTAL_VOLUME_HEADER_AREA_SIZE: u64 = PRIMARY_VOLUME_HEADER_AREA_SIZE * 2;
const MIN_FILE_HOSTED_VOLUME_SIZE: u64 = 299008;

fn cipher_component_count(alg: CipherType) -> usize {
    match alg {
        CipherType::Aes
        | CipherType::Serpent
        | CipherType::Twofish
        | CipherType::Camellia
        | CipherType::Kuznyechik => 1,
        CipherType::AesTwofish
        | CipherType::SerpentAes
        | CipherType::TwofishSerpent
        | CipherType::CamelliaKuznyechik
        | CipherType::CamelliaSerpent
        | CipherType::KuznyechikAes
        | CipherType::KuznyechikTwofish => 2,
        CipherType::AesTwofishSerpent
        | CipherType::SerpentTwofishAes
        | CipherType::KuznyechikSerpentCamellia => 3,
    }
}

fn required_key_size_for_cipher(alg: CipherType) -> usize {
    cipher_component_count(alg) * XTS_KEY_SIZE * 2
}

fn cipher_type_from_supported(cipher: &SupportedCipher) -> CipherType {
    match cipher {
        SupportedCipher::Aes(_) => CipherType::Aes,
        SupportedCipher::Serpent(_) => CipherType::Serpent,
        SupportedCipher::Twofish(_) => CipherType::Twofish,
        SupportedCipher::AesTwofish(_, _) => CipherType::AesTwofish,
        SupportedCipher::AesTwofishSerpent(_, _, _) => CipherType::AesTwofishSerpent,
        SupportedCipher::SerpentAes(_, _) => CipherType::SerpentAes,
        SupportedCipher::TwofishSerpent(_, _) => CipherType::TwofishSerpent,
        SupportedCipher::SerpentTwofishAes(_, _, _) => CipherType::SerpentTwofishAes,
        SupportedCipher::Camellia(_) => CipherType::Camellia,
        SupportedCipher::Kuznyechik(_) => CipherType::Kuznyechik,
        SupportedCipher::CamelliaKuznyechik(_, _) => CipherType::CamelliaKuznyechik,
        SupportedCipher::CamelliaSerpent(_, _) => CipherType::CamelliaSerpent,
        SupportedCipher::KuznyechikAes(_, _) => CipherType::KuznyechikAes,
        SupportedCipher::KuznyechikSerpentCamellia(_, _, _) => CipherType::KuznyechikSerpentCamellia,
        SupportedCipher::KuznyechikTwofish(_, _) => CipherType::KuznyechikTwofish,
    }
}

fn cipher_key_pair<'a>(
    key: &'a [u8],
    component_index: usize,
    component_count: usize,
) -> Result<(&'a [u8], &'a [u8]), VolumeError> {
    let required_key_size = component_count * XTS_KEY_SIZE * 2;
    if key.len() < required_key_size {
        return Err(VolumeError::CryptoError(format!(
            "Key too short. Need {}",
            required_key_size
        )));
    }

    let primary_start = component_index * XTS_KEY_SIZE;
    let secondary_start = component_count * XTS_KEY_SIZE + primary_start;

    Ok((
        &key[primary_start..primary_start + XTS_KEY_SIZE],
        &key[secondary_start..secondary_start + XTS_KEY_SIZE],
    ))
}

fn decrypt_effective_header(
    cipher: &SupportedCipher,
    encrypted_header: &[u8],
) -> Result<Zeroizing<[u8; ENCRYPTED_HEADER_SIZE]>, VolumeError> {
    if encrypted_header.len() != ENCRYPTED_HEADER_SIZE {
        return Err(VolumeError::CryptoError(format!(
            "Invalid encrypted header size: {}",
            encrypted_header.len()
        )));
    }

    let mut decrypted = Zeroizing::new([0u8; ENCRYPTED_HEADER_SIZE]);
    decrypted.copy_from_slice(encrypted_header);
    cipher.decrypt_area(&mut *decrypted, ENCRYPTED_HEADER_SIZE, 0);
    Ok(decrypted)
}

fn encrypt_effective_header(
    cipher: &SupportedCipher,
    effective_header: &mut [u8],
) -> Result<(), VolumeError> {
    if effective_header.len() != EFFECTIVE_HEADER_SIZE {
        return Err(VolumeError::CryptoError(format!(
            "Invalid effective header size: {}",
            effective_header.len()
        )));
    }

    cipher.encrypt_area(
        &mut effective_header[HEADER_SALT_SIZE..EFFECTIVE_HEADER_SIZE],
        ENCRYPTED_HEADER_SIZE,
        0,
    );

    Ok(())
}

fn has_vulnerable_xts_key_material(key: &[u8], alg: CipherType) -> bool {
    let component_count = cipher_component_count(alg);
    let required_key_size = required_key_size_for_cipher(alg);
    if key.len() < required_key_size {
        return true;
    }

    for component_index in 0..component_count {
        let primary_start = component_index * XTS_KEY_SIZE;
        let secondary_start = component_count * XTS_KEY_SIZE + primary_start;
        let primary = &key[primary_start..primary_start + XTS_KEY_SIZE];
        let secondary = &key[secondary_start..secondary_start + XTS_KEY_SIZE];

        let mut diff = 0u8;
        for (left, right) in primary.iter().zip(secondary.iter()) {
            diff |= left ^ right;
        }

        if diff == 0 {
            return true;
        }
    }

    false
}

// Helper to create a SupportedCipher instance from keys and type
fn create_cipher(alg: CipherType, key: &[u8]) -> Result<SupportedCipher, VolumeError> {
     let component_count = cipher_component_count(alg);

     match alg {
        CipherType::Aes => {
            let (key_1, key_2) = cipher_key_pair(key, 0, component_count)?;
            Ok(SupportedCipher::Aes(Xts128::new(AesWrapper::new(key_1.into()), AesWrapper::new(key_2.into()))))
        },
        CipherType::Serpent => {
            let (key_1, key_2) = cipher_key_pair(key, 0, component_count)?;
            Ok(SupportedCipher::Serpent(Xts128::new(SerpentWrapper::new(key_1.into()), SerpentWrapper::new(key_2.into()))))
        },
        CipherType::Twofish => {
            let (key_1, key_2) = cipher_key_pair(key, 0, component_count)?;
            Ok(SupportedCipher::Twofish(Xts128::new(TwofishWrapper::new(key_1.into()), TwofishWrapper::new(key_2.into()))))
        },
        CipherType::AesTwofish => {
            let (key_twofish_1, key_twofish_2) = cipher_key_pair(key, 0, component_count)?;
            let (key_aes_1, key_aes_2) = cipher_key_pair(key, 1, component_count)?;
            Ok(SupportedCipher::AesTwofish(
                Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into())),
                Xts128::new(TwofishWrapper::new(key_twofish_1.into()), TwofishWrapper::new(key_twofish_2.into()))
            ))
        },
        CipherType::AesTwofishSerpent => {
             let (key_serpent_1, key_serpent_2) = cipher_key_pair(key, 0, component_count)?;
             let (key_twofish_1, key_twofish_2) = cipher_key_pair(key, 1, component_count)?;
             let (key_aes_1, key_aes_2) = cipher_key_pair(key, 2, component_count)?;
             Ok(SupportedCipher::AesTwofishSerpent(
                Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into())),
                Xts128::new(TwofishWrapper::new(key_twofish_1.into()), TwofishWrapper::new(key_twofish_2.into())),
                Xts128::new(SerpentWrapper::new(key_serpent_1.into()), SerpentWrapper::new(key_serpent_2.into()))
             ))
        },
        CipherType::SerpentAes => {
            let (key_aes_1, key_aes_2) = cipher_key_pair(key, 0, component_count)?;
            let (key_serpent_1, key_serpent_2) = cipher_key_pair(key, 1, component_count)?;
            Ok(SupportedCipher::SerpentAes(
                Xts128::new(SerpentWrapper::new(key_serpent_1.into()), SerpentWrapper::new(key_serpent_2.into())),
                Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into()))
            ))
        },
        CipherType::TwofishSerpent => {
            let (key_serpent_1, key_serpent_2) = cipher_key_pair(key, 0, component_count)?;
            let (key_twofish_1, key_twofish_2) = cipher_key_pair(key, 1, component_count)?;
            Ok(SupportedCipher::TwofishSerpent(
                Xts128::new(TwofishWrapper::new(key_twofish_1.into()), TwofishWrapper::new(key_twofish_2.into())),
                Xts128::new(SerpentWrapper::new(key_serpent_1.into()), SerpentWrapper::new(key_serpent_2.into()))
            ))
        },
        CipherType::SerpentTwofishAes => {
             let (key_aes_1, key_aes_2) = cipher_key_pair(key, 0, component_count)?;
             let (key_twofish_1, key_twofish_2) = cipher_key_pair(key, 1, component_count)?;
             let (key_serpent_1, key_serpent_2) = cipher_key_pair(key, 2, component_count)?;
             Ok(SupportedCipher::SerpentTwofishAes(
                 Xts128::new(SerpentWrapper::new(key_serpent_1.into()), SerpentWrapper::new(key_serpent_2.into())),
                 Xts128::new(TwofishWrapper::new(key_twofish_1.into()), TwofishWrapper::new(key_twofish_2.into())),
                 Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into()))
             ))
        },
        CipherType::Camellia => {
            let (key_1, key_2) = cipher_key_pair(key, 0, component_count)?;
            Ok(SupportedCipher::Camellia(Xts128::new(CamelliaWrapper::new(key_1.into()), CamelliaWrapper::new(key_2.into()))))
        },
        CipherType::Kuznyechik => {
            let (key_1, key_2) = cipher_key_pair(key, 0, component_count)?;
            Ok(SupportedCipher::Kuznyechik(Xts128::new(KuznyechikWrapper::new(key_1.into()), KuznyechikWrapper::new(key_2.into()))))
        },
        CipherType::CamelliaKuznyechik => {
            let (key_kuznyechik_1, key_kuznyechik_2) = cipher_key_pair(key, 0, component_count)?;
            let (key_camellia_1, key_camellia_2) = cipher_key_pair(key, 1, component_count)?;
            Ok(SupportedCipher::CamelliaKuznyechik(
                Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into())),
                Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into()))
            ))
        },
        CipherType::CamelliaSerpent => {
            let (key_serpent_1, key_serpent_2) = cipher_key_pair(key, 0, component_count)?;
            let (key_camellia_1, key_camellia_2) = cipher_key_pair(key, 1, component_count)?;
            Ok(SupportedCipher::CamelliaSerpent(
                Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into())),
                Xts128::new(SerpentWrapper::new(key_serpent_1.into()), SerpentWrapper::new(key_serpent_2.into()))
            ))
        },
        CipherType::KuznyechikAes => {
            let (key_aes_1, key_aes_2) = cipher_key_pair(key, 0, component_count)?;
            let (key_kuznyechik_1, key_kuznyechik_2) = cipher_key_pair(key, 1, component_count)?;
            Ok(SupportedCipher::KuznyechikAes(
                Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into())),
                Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into()))
            ))
        },
        CipherType::KuznyechikSerpentCamellia => {
             let (key_camellia_1, key_camellia_2) = cipher_key_pair(key, 0, component_count)?;
             let (key_serpent_1, key_serpent_2) = cipher_key_pair(key, 1, component_count)?;
             let (key_kuznyechik_1, key_kuznyechik_2) = cipher_key_pair(key, 2, component_count)?;
             Ok(SupportedCipher::KuznyechikSerpentCamellia(
                 Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into())),
                 Xts128::new(SerpentWrapper::new(key_serpent_1.into()), SerpentWrapper::new(key_serpent_2.into())),
                 Xts128::new(CamelliaWrapper::new(key_camellia_1.into()), CamelliaWrapper::new(key_camellia_2.into()))
             ))
        },
        CipherType::KuznyechikTwofish => {
            let (key_twofish_1, key_twofish_2) = cipher_key_pair(key, 0, component_count)?;
            let (key_kuznyechik_1, key_kuznyechik_2) = cipher_key_pair(key, 1, component_count)?;
            Ok(SupportedCipher::KuznyechikTwofish(
                Xts128::new(KuznyechikWrapper::new(key_kuznyechik_1.into()), KuznyechikWrapper::new(key_kuznyechik_2.into())),
                Xts128::new(TwofishWrapper::new(key_twofish_1.into()), TwofishWrapper::new(key_twofish_2.into()))
            ))
        },
    }
}

// Encrypted Writer for Formatting
// Encrypted Writer for Formatting
// Encrypted Writer for Formatting
struct EncryptedVolumeWriter<'a, W: Read + Write + Seek> {
    inner: &'a mut W,
    cipher: SupportedCipher,
    sector_size: u64,
    data_start_offset: u64,
    current_pos: u64,
    buffer: Vec<u8>,
}

impl<'a, W: Read + Write + Seek> EncryptedVolumeWriter<'a, W> {
    fn new(inner: &'a mut W, cipher: SupportedCipher, sector_size: u64, data_start: u64) -> Self {
        Self {
            inner,
            cipher,
            sector_size,
            data_start_offset: data_start,
            current_pos: 0,
            buffer: Vec::new(),
        }
    }
    
    fn flush_sector(&mut self) -> std::io::Result<()> {
        if self.buffer.is_empty() { return Ok(()); }
        
        // Calculate start position of the data currently in buffer
        let start_pos = self.current_pos - self.buffer.len() as u64;
        let start_sector = start_pos / self.sector_size;
        let start_offset = (start_pos % self.sector_size) as usize;
        
        let old_pos = self.inner.stream_position()?;

        // 1. Handle Head Alignment (Prefix)
        if start_offset != 0 {
            // We need to read the prefix of the sector from disk to align the buffer start
            let prefix_len = start_offset;
            let mut prefix = vec![0u8; prefix_len];
            
            let read_pos = self.data_start_offset + (start_sector * self.sector_size);
            self.inner.seek(SeekFrom::Start(read_pos))?;
            
            // Attempt to read prefix.
            if let Err(e) = self.inner.read_exact(&mut prefix) {
                 // Propagate error to avoid data corruption
                 return Err(e);
            }

            // Prepend prefix to buffer
            let mut new_buf = prefix;
            new_buf.extend_from_slice(&self.buffer);
            self.buffer = new_buf;
        }
        
        // 2. Handle Tail Alignment (Suffix)
        let rem = self.buffer.len() % (self.sector_size as usize);
        if rem != 0 {
             let padding_needed = (self.sector_size as usize) - rem;
             let mut suffix = vec![0u8; padding_needed];
             
             // Calculate read position for suffix: Disk Start + Buffer Len (which includes prefix now)
             let read_pos = self.data_start_offset + (start_sector * self.sector_size) + self.buffer.len() as u64;
             self.inner.seek(SeekFrom::Start(read_pos))?;
             
             if let Ok(_) = self.inner.read_exact(&mut suffix) {
                 self.buffer.extend_from_slice(&suffix);
             } else {
                 self.buffer.resize(self.buffer.len() + padding_needed, 0);
             }
        }
        
        // Now buffer is aligned to sector boundaries and starts at start_sector
        let mut chunks = self.buffer.chunks_exact_mut(self.sector_size as usize);
        let mut idx = start_sector;
        
        let units_per_sector = self.sector_size / 512;

        for sector_data in chunks.by_ref() {
             // Encrypt using correct tweak
             let sector_tweak_start = (self.data_start_offset / 512) + (idx * units_per_sector);
             
             for i in 0..units_per_sector {
                 let unit_off = (i * 512) as usize;
                 let unit_tweak = sector_tweak_start + i;
                 self.cipher.encrypt_area(
                     &mut sector_data[unit_off..unit_off+512],
                     512, 
                     unit_tweak
                 );
             }
             idx += 1;
        }
        
        // Write to inner at aligned position
        let write_pos = self.data_start_offset + (start_sector * self.sector_size);
        self.inner.seek(SeekFrom::Start(write_pos))?;
        self.inner.write_all(&self.buffer)?;
        
        // Restore position
        self.inner.seek(SeekFrom::Start(old_pos))?;
        
        self.buffer.clear();
        Ok(())
    }
}

impl<'a, W: Read + Write + Seek> Write for EncryptedVolumeWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Simple buffering strategy: append to buffer.
        // If buffer gets too large (e.g. > 1MB), flush? 
        // For formatting, writes are small.
        self.buffer.extend_from_slice(buf);
        self.current_pos += buf.len() as u64;
        
        // If buffer is multiple of sector size, we can flush to keep memory usage low
        if self.buffer.len() >= 65536 { // Flush every 64KB
             self.flush_sector()?;
        }
        
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_sector()?;
        self.inner.flush()
    }
}

impl<'a, W: Read + Write + Seek> Seek for EncryptedVolumeWriter<'a, W> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.flush_sector()?; // Flush pending writes before seeking
        
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(p) => (self.current_pos as i64 + p) as u64,
            SeekFrom::End(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "SeekFrom::End not supported in formatter")),
        };
        self.current_pos = new_pos;
        Ok(new_pos)
    }
}

// Helper to derive key (generic)
fn derive_key_generic(password: &[u8], salt: &[u8], pim: i32, key: &mut [u8], prf: PrfAlgorithm) {
    let iter = if pim > 0 {
         // Standard: 15000 + (pim * 1000)
         // Note: RIPEMD-160 usually follows the same formula if PIM > 0
         15000 + (pim as u32) * 1000
    } else {
        // Defaults
        match prf {
            PrfAlgorithm::Ripemd160 => 655331,
            PrfAlgorithm::Sha1 => 2000, // Legacy
            PrfAlgorithm::Sha256 => 500_000, // SHA-256 default
            PrfAlgorithm::Sha512 => 500_000, 
            PrfAlgorithm::Whirlpool => 500_000,
            PrfAlgorithm::Streebog => 500_000,
            PrfAlgorithm::Blake2s => 500_000,
        }
    };

    match prf {
        PrfAlgorithm::Sha512 => { pbkdf2::<Hmac<Sha512>>(password, salt, iter, key).ok(); },
        PrfAlgorithm::Sha256 => { pbkdf2::<Hmac<Sha256>>(password, salt, iter, key).ok(); },
        PrfAlgorithm::Whirlpool => { pbkdf2::<Hmac<Whirlpool>>(password, salt, iter, key).ok(); },
        PrfAlgorithm::Ripemd160 => { pbkdf2::<Hmac<Ripemd160>>(password, salt, iter, key).ok(); },
        PrfAlgorithm::Streebog => { pbkdf2::<SimpleHmac<Streebog512>>(password, salt, iter, key).ok(); },
        PrfAlgorithm::Blake2s => { pbkdf2::<SimpleHmac<Blake2s256>>(password, salt, iter, key).ok(); },
        PrfAlgorithm::Sha1 => { pbkdf2::<Hmac<Sha1>>(password, salt, iter, key).ok(); },
    }
}

pub fn create_volume(
    path: &str,
    password: &[u8],
    pim: i32,
    size: u64,
    salt: &[u8],
    master_key: &[u8],
    cipher_type: CipherType,
    prf: PrfAlgorithm,
    sector_size_opt: Option<u32>,
) -> Result<(), VolumeError> {
    let mut file = OpenOptions::new().write(true).create(true).open(path)?;

    // We can't trust the passed master_key length alone for cascaded ciphers if they are truncated.
    // We expect the caller to provide enough bytes for the chosen cipher.
    let required_key_size = required_key_size_for_cipher(cipher_type);

    if master_key.len() < required_key_size {
         return Err(VolumeError::CryptoError(format!("Master key too short for chosen cipher. Need {}", required_key_size)));
    }

    let mut mk_arr = Zeroizing::new([0u8; 256]);
    mk_arr[..required_key_size].copy_from_slice(&master_key[..required_key_size]);
    
    let mut salt_arr = Zeroizing::new([0u8; 64]);
    if salt.len() <= 64 { salt_arr[..salt.len()].copy_from_slice(salt); } else { salt_arr.copy_from_slice(&salt[..64]); }

    // Check for weak keys (simplified - checking all 32-byte chunks)
    for i in (0..required_key_size).step_by(XTS_KEY_SIZE) {
         if i + XTS_KEY_SIZE <= required_key_size && mk_arr[i..i+XTS_KEY_SIZE].iter().all(|&x| x == 0) {
             return Err(VolumeError::CryptoError("Weak Key Generated (All Zeros)".to_string()));
         }
    }

    if has_vulnerable_xts_key_material(&mk_arr[..required_key_size], cipher_type) {
         return Err(VolumeError::CryptoError("Weak XTS Key Generated".to_string()));
    }

    let sector_size = sector_size_opt.unwrap_or(512);
    if sector_size < 512 || sector_size > 4096 || !sector_size.is_power_of_two() {
        return Err(VolumeError::CryptoError(format!("Invalid sector size: {}", sector_size)));
    }

    if size < MIN_FILE_HOSTED_VOLUME_SIZE {
        return Err(VolumeError::CryptoError(format!(
            "Volume too small. Need at least {} bytes for a VeraCrypt-compatible file-hosted volume",
            MIN_FILE_HOSTED_VOLUME_SIZE
        )));
    }

    if size % sector_size as u64 != 0 {
        return Err(VolumeError::CryptoError(format!(
            "Volume size {} is not aligned to sector size {}",
            size,
            sector_size
        )));
    }

    file.set_len(size)?;

    // VeraCrypt Layout:
    // Header: 128KB (Offset 0)
    // Data: Size - 256KB
    // Backup Header: 128KB (End)
    
    let encrypted_area_start = PRIMARY_VOLUME_HEADER_AREA_SIZE;
    let encrypted_area_length = size.checked_sub(TOTAL_VOLUME_HEADER_AREA_SIZE).ok_or_else(|| {
        VolumeError::CryptoError("Volume too small for primary and backup header areas".to_string())
    })?;

    let mut header = VolumeHeader::new(
        5, 0x011a, 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or(std::time::Duration::ZERO).as_secs(), 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or(std::time::Duration::ZERO).as_secs(), 
        0,
        encrypted_area_length, // Data size
        encrypted_area_start, // encrypted_area_start
        encrypted_area_length, // encrypted_area_length
        0, // flags
        sector_size, // sector_size
        *mk_arr,
        *salt_arr,
        pim
    ).map_err(|e| VolumeError::CryptoError(e))?;

    // Serialize
    let raw_header_vec = header.serialize()?;
    let mut encrypted_header = vec![0u8; 512];
    encrypted_header.copy_from_slice(&raw_header_vec);
    
    // Encrypt header with derived key using SELECTED cipher and PRF
    // Header Key size depends on cipher type (same as master key size usually)
    let mut header_key = Zeroizing::new([0u8; 192]);
    derive_key_generic(password, salt, pim, &mut *header_key, prf);
    
    let header_cipher = create_cipher(cipher_type, &*header_key)?;
    encrypt_effective_header(&header_cipher, &mut encrypted_header)?;
    
    // Write Primary Header
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&encrypted_header)?;
    
    // Write Backup Header (at End - 128KB)
    if size >= TOTAL_VOLUME_HEADER_AREA_SIZE {
        file.seek(SeekFrom::Start(size - PRIMARY_VOLUME_HEADER_AREA_SIZE))?;
        file.write_all(&encrypted_header)?;
    }
    
    // Format Filesystem (FAT32)
    // We need Volume Cipher (Using Master Key)
    let volume_cipher = create_cipher(cipher_type, &mk_arr[..required_key_size])?;
    let mut writer = EncryptedVolumeWriter::new(&mut file, volume_cipher, 512, encrypted_area_start);
    
    use crate::format::format_fat32;
    format_fat32(&mut writer, encrypted_area_length).map_err(|e| VolumeError::IoError(e))?;
    
    // Ensure everything is written
    writer.flush()?;
    file.sync_all().map_err(|e| VolumeError::IoError(e))?;
    
    Ok(())
}

fn try_header_at_offset(
    password: &[u8],
    full_buffer: &[u8],
    pim: i32,
    offset: u64,
    partition_start_offset: u64,
    hidden_volume_offset: Option<u64>,
) -> Result<Volume, VolumeError> {
        // Check if buffer has enough data for the header with overflow protection.
        let offset_usize = usize::try_from(offset)
            .map_err(|_| VolumeError::CryptoError("Offset too large for architecture".to_string()))?;
            
        if offset_usize.checked_add(512).map_or(true, |end| full_buffer.len() < end) {
            // Return InvalidMagic if too short.
            return Err(VolumeError::InvalidHeader(HeaderError::InvalidMagic));
        }
    
        // Extract the header slice.
        let header_slice = &full_buffer[offset_usize..offset_usize + 512];
        // Extract salt (first 64 bytes).
        let salt = &header_slice[..64];
        // Extract encrypted header data (remaining 448 bytes).
        let encrypted_header = &header_slice[64..512];
    
        // Iteration counts to try
        let mut iterations_list = Vec::new();
    
        // If PIM is specified, calculate iterations based on PIM.
        if pim > 0 {
            // Standard iterations with PIM.
            // Formula: 15000 + (pim * 1000)
            let iter_standard = (pim as u64)
                .checked_mul(1000)
                .and_then(|val| val.checked_add(15000))
                .ok_or(VolumeError::CryptoError("PIM calculation overflow".to_string()))?;
            
            if iter_standard > u32::MAX as u64 {
                 return Err(VolumeError::CryptoError("PIM iterations too large".to_string()));
            }
            iterations_list.push(iter_standard as u32);


        // System Encryption / Boot (SHA-256, Blake2s, Streebog) with PIM.
        // Formula: pim * 2048
        let iter_boot = (pim as u64)
             .checked_mul(2048)
             .ok_or(VolumeError::CryptoError("PIM calculation overflow (boot)".to_string()))?;

        if iter_boot > u32::MAX as u64 {
             return Err(VolumeError::CryptoError("PIM iterations (boot) too large".to_string()));
        }
        iterations_list.push(iter_boot as u32);
    } else {
        // Default VeraCrypt iterations.
        iterations_list.push(500_000);
        // System Encryption (SHA-256, Blake2s, Streebog) default.
        iterations_list.push(200_000);
        // Legacy TrueCrypt iterations.
        iterations_list.push(1000);
        iterations_list.push(2000);
    }

    // Buffer for the derived header key.
    let mut header_key = Zeroizing::new([0u8; 192]);

    // Helper closure to try all supported ciphers with a derived key.
    // Captures last_debug to report specific errors (e.g. Magic mismatch)
    let mut try_unlock = |key: &[u8], prf: PrfAlgorithm, last_debug: &mut String| -> Result<Volume, VolumeError> {
        let hv_opt = hidden_volume_offset.or(if offset == 0 { None } else { Some(offset) });

        // Try AES
        if !has_vulnerable_xts_key_material(&key[..64], CipherType::Aes) {
            match try_cipher::<Aes256>(
                key,
                encrypted_header,
                partition_start_offset, hv_opt,
                offset, // Header offset
                salt,
                pim,
                Some(prf),
                |k1, k2| {
                    SupportedCipher::Aes(Xts128::new(AesWrapper::new(k1.into()), AesWrapper::new(k2.into())))
                },
            ) {
                Ok(v) => return Ok(v),
                Err(VolumeError::InvalidPassword(msg)) => *last_debug = msg,
                Err(e) => return Err(e), // Propagate other errors (e.g. CryptoError)
            }
        }

        // Try Serpent
        if !has_vulnerable_xts_key_material(&key[..64], CipherType::Serpent) {
            match try_cipher_serpent(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                Ok(v) => return Ok(v),
                Err(VolumeError::InvalidPassword(msg)) => *last_debug = msg,
                Err(e) => return Err(e), // Propagate other errors
            }
        }

        // Try Twofish
        if !has_vulnerable_xts_key_material(&key[..64], CipherType::Twofish) {
            match try_cipher::<TwofishWrapper>(
                key,
                encrypted_header,
                partition_start_offset, hv_opt,
                offset,
                salt,
                pim,
                Some(prf),
                |k1, k2| {
                    SupportedCipher::Twofish(Xts128::new(
                        TwofishWrapper::new(k1.into()),
                        TwofishWrapper::new(k2.into()),
                    ))
                },
            ) {
                Ok(v) => return Ok(v),
                Err(VolumeError::InvalidPassword(msg)) => *last_debug = msg,
                Err(e) => return Err(e),
            }
        }

        // Try Camellia
        if !has_vulnerable_xts_key_material(&key[..64], CipherType::Camellia) {
            match try_cipher_camellia(
                key,
                encrypted_header,
                partition_start_offset, hv_opt,
                offset,
                salt,
                pim,
                Some(prf),
                ) {
                Ok(v) => return Ok(v),
                Err(VolumeError::InvalidPassword(msg)) => *last_debug = msg,
                _ => {}
            }
        }

        // Try Kuznyechik
        if !has_vulnerable_xts_key_material(&key[..64], CipherType::Kuznyechik) {
            match try_cipher_kuznyechik(
                key,
                encrypted_header,
                partition_start_offset, hv_opt,
                offset,
                salt,
                pim,
                Some(prf),
                ) {
                Ok(v) => return Ok(v),
                Err(VolumeError::InvalidPassword(msg)) => *last_debug = msg,
                _ => {}
            }
        }
        
        // Cascades
        if !has_vulnerable_xts_key_material(&key[..128], CipherType::AesTwofish) {
            if let Ok(v) = try_cipher_aes_twofish(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }
        if !has_vulnerable_xts_key_material(&key[..192], CipherType::AesTwofishSerpent) {
            if let Ok(v) = try_cipher_aes_twofish_serpent(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }
        if !has_vulnerable_xts_key_material(&key[..128], CipherType::SerpentAes) {
            if let Ok(v) = try_cipher_serpent_aes(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }
        if !has_vulnerable_xts_key_material(&key[..128], CipherType::TwofishSerpent) {
            if let Ok(v) = try_cipher_twofish_serpent(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }
        // Try Serpent-Twofish-AES
        if !has_vulnerable_xts_key_material(&key[..192], CipherType::SerpentTwofishAes) {
            if let Ok(v) = try_cipher_serpent_twofish_aes(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }
        // Try Camellia-Kuznyechik
        if !has_vulnerable_xts_key_material(&key[..128], CipherType::CamelliaKuznyechik) {
            if let Ok(v) = try_cipher_camellia_kuznyechik(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }
        // Try Camellia-Serpent
        if !has_vulnerable_xts_key_material(&key[..128], CipherType::CamelliaSerpent) {
            if let Ok(v) = try_cipher_camellia_serpent(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }
        // Try Kuznyechik-AES
        if !has_vulnerable_xts_key_material(&key[..128], CipherType::KuznyechikAes) {
            if let Ok(v) = try_cipher_kuznyechik_aes(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }
        // Try Kuznyechik-Serpent-Camellia
        if !has_vulnerable_xts_key_material(&key[..192], CipherType::KuznyechikSerpentCamellia) {
            if let Ok(v) = try_cipher_kuznyechik_serpent_camellia(
                key,
                encrypted_header,
                partition_start_offset, hv_opt,
                offset,
                salt,
                pim,
                Some(prf),
            ) {
                return Ok(v);
            }
        }
        // Try Kuznyechik-Twofish
        if !has_vulnerable_xts_key_material(&key[..128], CipherType::KuznyechikTwofish) {
            if let Ok(v) = try_cipher_kuznyechik_twofish(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
                return Ok(v);
            }
        }

        // Return InvalidPassword if none work.
        Err(VolumeError::InvalidPassword("No cipher matched".to_string()))
    };

    let mut last_debug = "None".to_string();

    // Iterate through all iteration counts.
    for (idx, &iter) in iterations_list.iter().enumerate() {
        // 1. SHA-512
        // Derive key using PBKDF2-HMAC-SHA512.
        pbkdf2::<Hmac<Sha512>>(password, salt, iter, &mut *header_key).ok();
        // Try to unlock.
        match try_unlock(&*header_key, PrfAlgorithm::Sha512, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 2. SHA-256
        // Derive key using PBKDF2-HMAC-SHA256.
        pbkdf2::<Hmac<Sha256>>(password, salt, iter, &mut *header_key).ok();
        // Try to unlock.
        match try_unlock(&*header_key, PrfAlgorithm::Sha256, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 3. Whirlpool
        // Derive key using PBKDF2-HMAC-Whirlpool.
        pbkdf2::<Hmac<Whirlpool>>(password, salt, iter, &mut *header_key).ok();
        // Try to unlock.
        match try_unlock(&*header_key, PrfAlgorithm::Whirlpool, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 4. Blake2s
        // Blake2s default is 500,000. System/Boot is 200,000. PIM is pim*2048.
        // We just use `iter` from the list which covers these cases.
        // Derive key using PBKDF2-SimpleHmac-Blake2s256.
        pbkdf2::<SimpleHmac<Blake2s256>>(password, salt, iter, &mut *header_key).ok();
        // Try to unlock.
        match try_unlock(&*header_key, PrfAlgorithm::Blake2s, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 5. Streebog
        // Derive key using PBKDF2-SimpleHmac-Streebog512.
        pbkdf2::<SimpleHmac<Streebog512>>(password, salt, iter, &mut *header_key).ok();
        // Try to unlock.
        match try_unlock(&*header_key, PrfAlgorithm::Streebog, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 6. RIPEMD-160
        // Calculate specific iteration count for RIPEMD-160.
        // Map standard iteration counts to RIPEMD specific ones.
        let ripemd_iter = if iter == 500_000 {
            655_331
        } else if iter == 200_000 {
            327_661
        } else {
            iter
        };

        // Derive key using PBKDF2-HMAC-Ripemd160.
        pbkdf2::<Hmac<Ripemd160>>(password, salt, ripemd_iter, &mut *header_key).ok();
        // Try to unlock.
        match try_unlock(&*header_key, PrfAlgorithm::Ripemd160, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 7. SHA-1 (Legacy)
        // Derive key using PBKDF2-HMAC-SHA1.
        pbkdf2::<Hmac<Sha1>>(password, salt, iter, &mut *header_key).ok();
        // Try to unlock.
        match try_unlock(&*header_key, PrfAlgorithm::Sha1, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // Zeroize the header key after use.
        header_key.zeroize();
    }

    // Return InvalidPassword if all hash algorithms and iteration counts fail.
    Err(VolumeError::InvalidPassword(last_debug))
}

// Function to register a volume context in the global map.
fn register_context(vol: Volume) -> Result<i64, VolumeError> {
    // Lock the NEXT_HANDLE mutex to get a unique handle.
    let mut handle_lock = NEXT_HANDLE.lock().unwrap_or_else(|e| e.into_inner());
    // Get the current handle value.
    let handle = *handle_lock;
    // Increment the handle counter.
    *handle_lock += 1;

    // Lock the CONTEXTS mutex to insert the new volume.
    let mut contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    // Insert the volume wrapped in an Arc.
    contexts_lock.insert(handle, Arc::new(vol));

    // Return the handle.
    Ok(handle)
}

// Function to decrypt data using a volume handle.
#[allow(clippy::manual_is_multiple_of)]
pub fn decrypt(handle: i64, offset: u64, data: &mut [u8]) -> Result<(), VolumeError> {
    // Lock the contexts map.
    let volume = {
        let contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
        // Look up the volume by handle and clone the Arc.
        contexts_lock.get(&handle).cloned()
    };

    if let Some(context) = volume {
        // Check if offset is aligned to sector size.
        if offset % (context.header.sector_size as u64) != 0 {
            return Err(VolumeError::CryptoError(
                "Offset not aligned to sector size".to_string(),
            ));
        }

        // Calculate the starting sector index based on the offset.
        let start_sector = offset / (context.header.sector_size as u64);
        // Call the volume's decrypt_sector method.
        context.decrypt_sector(start_sector, data)
    } else {
        // Return error if handle is invalid.
        Err(VolumeError::CryptoError("Invalid handle".to_string()))
    }
}

// Function to encrypt data using a volume handle.
#[allow(clippy::manual_is_multiple_of)]
pub fn encrypt(handle: i64, offset: u64, data: &mut [u8]) -> Result<(), VolumeError> {
    // Lock the contexts map.
    let volume = {
        let contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
        contexts_lock.get(&handle).cloned()
    };

    if let Some(context) = volume {
        // Check if offset is aligned to sector size.
        if offset % (context.header.sector_size as u64) != 0 {
            return Err(VolumeError::CryptoError(
                "Offset not aligned to sector size".to_string(),
            ));
        }

        // Calculate the starting sector index.
        let start_sector = offset / (context.header.sector_size as u64);
        // Call the volume's encrypt_sector method.
        context.encrypt_sector(start_sector, data)
    } else {
        // Return error if handle is invalid.
        Err(VolumeError::CryptoError("Invalid handle".to_string()))
    }
}

// Function to close a volume context (unmount).
pub fn close_context(handle: i64) {
    // Lock the contexts map.
    if let Ok(mut contexts_lock) = CONTEXTS.lock() {
        // Remove the volume by handle.
        contexts_lock.remove(&handle);
    }
}

// Function to get the encrypted area start offset for a volume.
pub fn get_data_offset(handle: i64) -> Result<u64, VolumeError> {
    // Lock the contexts map.
    let contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    // Look up the volume.
    if let Some(context) = contexts_lock.get(&handle) {
        // Return the encrypted area start offset.
        Ok(context.header.encrypted_area_start)
    } else {
        // Return error if handle is invalid.
        Err(VolumeError::CryptoError("Invalid handle".to_string()))
    }
}

// --- Cipher specific try functions ---

// Generic function to try a specific cipher.
fn try_cipher<C: BlockCipher + KeySizeUser + KeyInit>(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
    create_cipher: impl Fn(&[u8], &[u8]) -> SupportedCipher,
) -> Result<Volume, VolumeError> {
    // Get the key size for the cipher.
    let key_size = C::key_size();
    // Check if the header key is long enough (need 2 keys for XTS).
    if header_key.len() < key_size * 2 {
        return Err(VolumeError::CryptoError("Key too short".into()));
    }

    // Extract the first key.
    let key_1 = &header_key[0..key_size];
    // Extract the second key.
    let key_2 = &header_key[key_size..key_size * 2];

    // We need to construct Xts128 manually or use the callback.
    // But Xts128 needs the cipher instance.
    // The callback approach is cleaner for generic XTS construction if we passed cipher instances,
    // but here we are constructing the SupportedCipher enum variant.

    // Create the cipher instance using the provided closure.
    let cipher_enum = create_cipher(key_1, key_2);

    let decrypted = decrypt_effective_header(&cipher_enum, encrypted_header)?;

    // Try to deserialize the decrypted header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        // Found it! Now derive the master keys for the volume data.
        // The master keys are in the decrypted header at offset 192.
        // We need to create the volume cipher using these keys.

        // Get master key data.
        let mk = &header.master_key_data;
        // Re-create the SAME cipher mode but with the master keys.
        let vol_cipher = create_cipher(&mk[0..key_size], &mk[key_size..key_size * 2]);

        // Check for vulnerable keys.
        if header.is_xts_key_vulnerable(0, key_size, key_size) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return the new Volume.
        return Ok(Volume::new(
            header,
            vol_cipher,
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    
    // Return generic InvalidPassword error.
    Err(VolumeError::InvalidPassword("".to_string()))
}

// Function to try Serpent cipher.
fn try_cipher_serpent(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_1 = &header_key[0..32];
    let key_2 = &header_key[32..64];
    // Create Serpent instances.
    let cipher_1 = SerpentWrapper::new(key_1.into());
    let cipher_2 = SerpentWrapper::new(key_2.into());
    // Create XTS instance.
    let xts = Xts128::new(cipher_1, cipher_2);
    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::Serpent(xts);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        // Create volume cipher with master keys.
        let mk = &header.master_key_data;
        let c1 = SerpentWrapper::new(mk[0..32].into());
        let c2 = SerpentWrapper::new(mk[32..64].into());
        let vol_cipher = SupportedCipher::Serpent(Xts128::new(c1, c2));

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 32, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            vol_cipher,
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Serpent cipher failed".to_string()))
}

// Function to try AES-Twofish cascade.
fn try_cipher_aes_twofish(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // VeraCrypt AESTwofish: Twofish then AES.
    // Key mapping: 0..32 -> Twofish, 32..64 -> AES.

    // Extract keys.
    let key_twofish_1 = &header_key[0..32];
    let key_aes_1 = &header_key[32..64];
    let key_twofish_2 = &header_key[64..96];
    let key_aes_2 = &header_key[96..128];

    // Create XTS instances.
    let cipher_aes = Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into()));
    let cipher_twofish = Xts128::new(
        TwofishWrapper::new(key_twofish_1.into()),
        TwofishWrapper::new(key_twofish_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::AesTwofish(cipher_aes, cipher_twofish);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Keys in master key area:
        // VeraCrypt AESTwofish: Key[0..32]->Twofish, Key[32..64]->AES.
        // Primary Keys: 0..64. Secondary Keys: 64..128.

        // Extract master keys.
        // Primary Keys
        let mk_twofish_1 = &mk[0..32];
        let mk_aes_1 = &mk[32..64];
        // Secondary Keys
        let mk_twofish_2 = &mk[64..96];
        let mk_aes_2 = &mk[96..128];

        // Create volume ciphers.
        let vol_twofish = Xts128::new(
            TwofishWrapper::new(mk_twofish_1.into()),
            TwofishWrapper::new(mk_twofish_2.into()),
        );
        let vol_aes = Xts128::new(AesWrapper::new(mk_aes_1.into()), AesWrapper::new(mk_aes_2.into()));

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 64, 32) || header.is_xts_key_vulnerable(32, 96, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::AesTwofish(vol_aes, vol_twofish),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("AES-Twofish cipher failed".to_string()))
}

// Function to try AES-Twofish-Serpent cascade.
fn try_cipher_aes_twofish_serpent(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_serpent_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_aes_1 = &header_key[64..96];

    let key_serpent_2 = &header_key[96..128];
    let key_twofish_2 = &header_key[128..160];
    let key_aes_2 = &header_key[160..192];

    // Create XTS instances.
    let cipher_aes = Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into()));
    let cipher_twofish = Xts128::new(
        TwofishWrapper::new(key_twofish_1.into()),
        TwofishWrapper::new(key_twofish_2.into()),
    );
    let cipher_serpent = Xts128::new(
        SerpentWrapper::new(key_serpent_1.into()),
        SerpentWrapper::new(key_serpent_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum =
        SupportedCipher::AesTwofishSerpent(cipher_aes, cipher_twofish, cipher_serpent);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_serpent_1 = &mk[0..32];
        let mk_twofish_1 = &mk[32..64];
        let mk_aes_1 = &mk[64..96];
        // Secondary Keys
        let mk_serpent_2 = &mk[96..128];
        let mk_twofish_2 = &mk[128..160];
        let mk_aes_2 = &mk[160..192];

        // Create volume ciphers.
        let vol_aes = Xts128::new(AesWrapper::new(mk_aes_1.into()), AesWrapper::new(mk_aes_2.into()));
        let vol_twofish = Xts128::new(
            TwofishWrapper::new(mk_twofish_1.into()),
            TwofishWrapper::new(mk_twofish_2.into()),
        );
        let vol_serpent = Xts128::new(
            SerpentWrapper::new(mk_serpent_1.into()),
            SerpentWrapper::new(mk_serpent_2.into()),
        );

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 96, 32) || header.is_xts_key_vulnerable(32, 128, 32) || header.is_xts_key_vulnerable(64, 160, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::AesTwofishSerpent(vol_aes, vol_twofish, vol_serpent),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("AES-Twofish-Serpent cipher failed".to_string()))
}

// Function to try Serpent-AES cascade.
fn try_cipher_serpent_aes(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_aes_1 = &header_key[0..32];
    let key_serpent_1 = &header_key[32..64];
    let key_aes_2 = &header_key[64..96];
    let key_serpent_2 = &header_key[96..128];

    // Create XTS instances.
    let cipher_serpent = Xts128::new(
        SerpentWrapper::new(key_serpent_1.into()),
        SerpentWrapper::new(key_serpent_2.into()),
    );
    let cipher_aes = Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into()));

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::SerpentAes(cipher_serpent, cipher_aes);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_aes_1 = &mk[0..32];
        let mk_serpent_1 = &mk[32..64];
        // Secondary Keys
        let mk_aes_2 = &mk[64..96];
        let mk_serpent_2 = &mk[96..128];

        // Create volume ciphers.
        let vol_serpent = Xts128::new(
            SerpentWrapper::new(mk_serpent_1.into()),
            SerpentWrapper::new(mk_serpent_2.into()),
        );
        let vol_aes = Xts128::new(AesWrapper::new(mk_aes_1.into()), AesWrapper::new(mk_aes_2.into()));

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 64, 32) || header.is_xts_key_vulnerable(32, 96, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::SerpentAes(vol_serpent, vol_aes),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Serpent-AES cipher failed".to_string()))
}

// Function to try Twofish-Serpent cascade.
fn try_cipher_twofish_serpent(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_serpent_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_serpent_2 = &header_key[64..96];
    let key_twofish_2 = &header_key[96..128];

    // Create XTS instances.
    let cipher_twofish = Xts128::new(
        TwofishWrapper::new(key_twofish_1.into()),
        TwofishWrapper::new(key_twofish_2.into()),
    );
    let cipher_serpent = Xts128::new(
        SerpentWrapper::new(key_serpent_1.into()),
        SerpentWrapper::new(key_serpent_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::TwofishSerpent(cipher_twofish, cipher_serpent);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_serpent_1 = &mk[0..32];
        let mk_twofish_1 = &mk[32..64];
        // Secondary Keys
        let mk_serpent_2 = &mk[64..96];
        let mk_twofish_2 = &mk[96..128];

        // Create volume ciphers.
        let vol_twofish = Xts128::new(
            TwofishWrapper::new(mk_twofish_1.into()),
            TwofishWrapper::new(mk_twofish_2.into()),
        );
        let vol_serpent = Xts128::new(
            SerpentWrapper::new(mk_serpent_1.into()),
            SerpentWrapper::new(mk_serpent_2.into()),
        );

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 64, 32) || header.is_xts_key_vulnerable(32, 96, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::TwofishSerpent(vol_twofish, vol_serpent),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Twofish-Serpent cipher failed".to_string()))
}

// Function to try Serpent-Twofish-AES cascade.
fn try_cipher_serpent_twofish_aes(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_aes_1 = &header_key[0..32];
    let key_twofish_1 = &header_key[32..64];
    let key_serpent_1 = &header_key[64..96];
    let key_aes_2 = &header_key[96..128];
    let key_twofish_2 = &header_key[128..160];
    let key_serpent_2 = &header_key[160..192];

    // Create XTS instances.
    let cipher_serpent = Xts128::new(
        SerpentWrapper::new(key_serpent_1.into()),
        SerpentWrapper::new(key_serpent_2.into()),
    );
    let cipher_twofish = Xts128::new(
        TwofishWrapper::new(key_twofish_1.into()),
        TwofishWrapper::new(key_twofish_2.into()),
    );
    let cipher_aes = Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into()));

    // Wrap in SupportedCipher.
    let cipher_enum =
        SupportedCipher::SerpentTwofishAes(cipher_serpent, cipher_twofish, cipher_aes);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_aes_1 = &mk[0..32];
        let mk_twofish_1 = &mk[32..64];
        let mk_serpent_1 = &mk[64..96];
        // Secondary Keys
        let mk_aes_2 = &mk[96..128];
        let mk_twofish_2 = &mk[128..160];
        let mk_serpent_2 = &mk[160..192];

        // Create volume ciphers.
        let vol_serpent = Xts128::new(
            SerpentWrapper::new(mk_serpent_1.into()),
            SerpentWrapper::new(mk_serpent_2.into()),
        );
        let vol_twofish = Xts128::new(
            TwofishWrapper::new(mk_twofish_1.into()),
            TwofishWrapper::new(mk_twofish_2.into()),
        );
        let vol_aes = Xts128::new(AesWrapper::new(mk_aes_1.into()), AesWrapper::new(mk_aes_2.into()));

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 96, 32) || header.is_xts_key_vulnerable(32, 128, 32) || header.is_xts_key_vulnerable(64, 160, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::SerpentTwofishAes(vol_serpent, vol_twofish, vol_aes),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Serpent-Twofish-AES cipher failed".to_string()))
}

// Function to try Camellia cipher.
fn try_cipher_camellia(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Use generic try_cipher with CamelliaWrapper.
    try_cipher::<CamelliaWrapper>(
        header_key,
        encrypted_header,
        partition_start_offset,
        hidden_volume_offset,
        header_offset,
        salt,
        pim,
        prf,
        |k1, k2| {
            SupportedCipher::Camellia(Xts128::new(
                CamelliaWrapper::new(k1.into()),
                CamelliaWrapper::new(k2.into()),
            ))
        },
    )
}

// Function to try Kuznyechik cipher.
fn try_cipher_kuznyechik(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Use generic try_cipher with KuznyechikWrapper.
    try_cipher::<KuznyechikWrapper>(
        header_key,
        encrypted_header,
        partition_start_offset,
        hidden_volume_offset,
        header_offset,
        salt,
        pim,
        prf,
        |k1, k2| {
            SupportedCipher::Kuznyechik(Xts128::new(
                KuznyechikWrapper::new(k1.into()),
                KuznyechikWrapper::new(k2.into()),
            ))
        },
    )
}

// Function to try Camellia-Kuznyechik cascade.
fn try_cipher_camellia_kuznyechik(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_kuznyechik_1 = &header_key[0..32];
    let key_camellia_1 = &header_key[32..64];
    let key_kuznyechik_2 = &header_key[64..96];
    let key_camellia_2 = &header_key[96..128];

    // Create XTS instances.
    let cipher_camellia = Xts128::new(
        CamelliaWrapper::new(key_camellia_1.into()),
        CamelliaWrapper::new(key_camellia_2.into()),
    );
    let cipher_kuznyechik = Xts128::new(
        KuznyechikWrapper::new(key_kuznyechik_1.into()),
        KuznyechikWrapper::new(key_kuznyechik_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::CamelliaKuznyechik(cipher_camellia, cipher_kuznyechik);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_kuznyechik_1 = &mk[0..32];
        let mk_camellia_1 = &mk[32..64];
        // Secondary Keys
        let mk_kuznyechik_2 = &mk[64..96];
        let mk_camellia_2 = &mk[96..128];

        // Create volume ciphers.
        let vol_camellia = Xts128::new(
            CamelliaWrapper::new(mk_camellia_1.into()),
            CamelliaWrapper::new(mk_camellia_2.into()),
        );
        let vol_kuznyechik = Xts128::new(
            KuznyechikWrapper::new(mk_kuznyechik_1.into()),
            KuznyechikWrapper::new(mk_kuznyechik_2.into()),
        );

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 64, 32) || header.is_xts_key_vulnerable(32, 96, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::CamelliaKuznyechik(vol_camellia, vol_kuznyechik),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Camellia-Kuznyechik cipher failed".to_string()))
}

// Function to try Camellia-Serpent cascade.
fn try_cipher_camellia_serpent(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_serpent_1 = &header_key[0..32];
    let key_camellia_1 = &header_key[32..64];
    let key_serpent_2 = &header_key[64..96];
    let key_camellia_2 = &header_key[96..128];

    // Create XTS instances.
    let cipher_camellia = Xts128::new(
        CamelliaWrapper::new(key_camellia_1.into()),
        CamelliaWrapper::new(key_camellia_2.into()),
    );
    let cipher_serpent = Xts128::new(
        SerpentWrapper::new(key_serpent_1.into()),
        SerpentWrapper::new(key_serpent_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::CamelliaSerpent(cipher_camellia, cipher_serpent);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_serpent_1 = &mk[0..32];
        let mk_camellia_1 = &mk[32..64];
        // Secondary Keys
        let mk_serpent_2 = &mk[64..96];
        let mk_camellia_2 = &mk[96..128];

        // Create volume ciphers.
        let vol_camellia = Xts128::new(
            CamelliaWrapper::new(mk_camellia_1.into()),
            CamelliaWrapper::new(mk_camellia_2.into()),
        );
        let vol_serpent = Xts128::new(
            SerpentWrapper::new(mk_serpent_1.into()),
            SerpentWrapper::new(mk_serpent_2.into()),
        );

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 64, 32) || header.is_xts_key_vulnerable(32, 96, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::CamelliaSerpent(vol_camellia, vol_serpent),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Camellia-Serpent cipher failed".to_string()))
}

// Function to try Kuznyechik-AES cascade.
fn try_cipher_kuznyechik_aes(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_aes_1 = &header_key[0..32];
    let key_kuznyechik_1 = &header_key[32..64];
    let key_aes_2 = &header_key[64..96];
    let key_kuznyechik_2 = &header_key[96..128];

    // Create XTS instances.
    let cipher_kuznyechik = Xts128::new(
        KuznyechikWrapper::new(key_kuznyechik_1.into()),
        KuznyechikWrapper::new(key_kuznyechik_2.into()),
    );
    let cipher_aes = Xts128::new(AesWrapper::new(key_aes_1.into()), AesWrapper::new(key_aes_2.into()));

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::KuznyechikAes(cipher_kuznyechik, cipher_aes);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_aes_1 = &mk[0..32];
        let mk_kuznyechik_1 = &mk[32..64];
        // Secondary Keys
        let mk_aes_2 = &mk[64..96];
        let mk_kuznyechik_2 = &mk[96..128];

        // Create volume ciphers.
        let vol_kuznyechik = Xts128::new(
            KuznyechikWrapper::new(mk_kuznyechik_1.into()),
            KuznyechikWrapper::new(mk_kuznyechik_2.into()),
        );
        let vol_aes = Xts128::new(AesWrapper::new(mk_aes_1.into()), AesWrapper::new(mk_aes_2.into()));

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 64, 32) || header.is_xts_key_vulnerable(32, 96, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::KuznyechikAes(vol_kuznyechik, vol_aes),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Kuznyechik-AES cipher failed".to_string()))
}

// Function to try Kuznyechik-Serpent-Camellia cascade.
fn try_cipher_kuznyechik_serpent_camellia(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_camellia_1 = &header_key[0..32];
    let key_serpent_1 = &header_key[32..64];
    let key_kuznyechik_1 = &header_key[64..96];

    let key_camellia_2 = &header_key[96..128];
    let key_serpent_2 = &header_key[128..160];
    let key_kuznyechik_2 = &header_key[160..192];

    // Create XTS instances.
    let cipher_kuznyechik = Xts128::new(
        KuznyechikWrapper::new(key_kuznyechik_1.into()),
        KuznyechikWrapper::new(key_kuznyechik_2.into()),
    );
    let cipher_serpent = Xts128::new(
        SerpentWrapper::new(key_serpent_1.into()),
        SerpentWrapper::new(key_serpent_2.into()),
    );
    let cipher_camellia = Xts128::new(
        CamelliaWrapper::new(key_camellia_1.into()),
        CamelliaWrapper::new(key_camellia_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::KuznyechikSerpentCamellia(
        cipher_kuznyechik,
        cipher_serpent,
        cipher_camellia,
    );

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_camellia_1 = &mk[0..32];
        let mk_serpent_1 = &mk[32..64];
        let mk_kuznyechik_1 = &mk[64..96];
        // Secondary Keys
        let mk_camellia_2 = &mk[96..128];
        let mk_serpent_2 = &mk[128..160];
        let mk_kuznyechik_2 = &mk[160..192];

        // Create volume ciphers.
        let vol_kuznyechik = Xts128::new(
            KuznyechikWrapper::new(mk_kuznyechik_1.into()),
            KuznyechikWrapper::new(mk_kuznyechik_2.into()),
        );
        let vol_serpent = Xts128::new(
            SerpentWrapper::new(mk_serpent_1.into()),
            SerpentWrapper::new(mk_serpent_2.into()),
        );
        let vol_camellia = Xts128::new(
            CamelliaWrapper::new(mk_camellia_1.into()),
            CamelliaWrapper::new(mk_camellia_2.into()),
        );

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 96, 32) || header.is_xts_key_vulnerable(32, 128, 32) || header.is_xts_key_vulnerable(64, 160, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::KuznyechikSerpentCamellia(vol_kuznyechik, vol_serpent, vol_camellia),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Kuznyechik-Serpent-Camellia cipher failed".to_string()))
}

// Function to try Kuznyechik-Twofish cascade.
fn try_cipher_kuznyechik_twofish(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64, hidden_volume_offset: Option<u64>,
    header_offset: u64,
    salt: &[u8],
    pim: i32,
    prf: Option<PrfAlgorithm>,
) -> Result<Volume, VolumeError> {
    // Extract keys.
    let key_twofish_1 = &header_key[0..32];
    let key_kuznyechik_1 = &header_key[32..64];
    let key_twofish_2 = &header_key[64..96];
    let key_kuznyechik_2 = &header_key[96..128];

    // Create XTS instances.
    let cipher_kuznyechik = Xts128::new(
        KuznyechikWrapper::new(key_kuznyechik_1.into()),
        KuznyechikWrapper::new(key_kuznyechik_2.into()),
    );
    let cipher_twofish = Xts128::new(
        TwofishWrapper::new(key_twofish_1.into()),
        TwofishWrapper::new(key_twofish_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::KuznyechikTwofish(cipher_kuznyechik, cipher_twofish);

    // Decrypt header.
    let mut decrypted = Zeroizing::new([0u8; 448]);
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut *decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&*decrypted, salt, pim) {
        let mk = &header.master_key_data;
        // Extract master keys.
        // Primary Keys
        let mk_twofish_1 = &mk[0..32];
        let mk_kuznyechik_1 = &mk[32..64];
        // Secondary Keys
        let mk_twofish_2 = &mk[64..96];
        let mk_kuznyechik_2 = &mk[96..128];

        // Create volume ciphers.
        let vol_kuznyechik = Xts128::new(
            KuznyechikWrapper::new(mk_kuznyechik_1.into()),
            KuznyechikWrapper::new(mk_kuznyechik_2.into()),
        );
        let vol_twofish = Xts128::new(
            TwofishWrapper::new(mk_twofish_1.into()),
            TwofishWrapper::new(mk_twofish_2.into()),
        );

        // Check vulnerability.
        if header.is_xts_key_vulnerable(0, 64, 32) || header.is_xts_key_vulnerable(32, 96, 32) {
            return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::KuznyechikTwofish(vol_kuznyechik, vol_twofish),
            partition_start_offset,
            hidden_volume_offset,
            header_offset,
            false,
            prf,
        ));
    }
    Err(VolumeError::InvalidPassword("Kuznyechik-Twofish cipher failed".to_string()))
}
// Function to change the password of // Implement change_password
pub fn change_password(
    path: &str,
    old_password: &[u8],
    old_pim: i32,
    new_password: &[u8],
    new_pim: i32,
    new_salt: &[u8],
    new_prf: Option<PrfAlgorithm>,
) -> Result<(), VolumeError> {
    use std::fs::OpenOptions;
    use std::io::{Read, Write, Seek, SeekFrom};
    use zeroize::Zeroize;

    let mut file = OpenOptions::new().read(true).write(true).open(path)
        .map_err(|e| VolumeError::IoError(e))?;
        
    let size = file.metadata().map_err(|e| VolumeError::IoError(e))?.len();
    
    // Read the primary header (first 65 KB to allow for hidden vol check if we wanted)
    let mut buffer = vec![0u8; 65536 + 512];
    let _read_len = file.read(&mut buffer).map_err(|e| VolumeError::IoError(e))?;
    
    // Try primary at 0
    let mut volume = try_header_at_offset(old_password, &buffer, old_pim, 0, 0, None)
         .or_else(|_| {
             // Maybe Hidden Volume at 64KB?
             if buffer.len() >= 65536 + 512 {
                 try_header_at_offset(old_password, &buffer, old_pim, 65536, 0, None)
             } else {
                 Err(VolumeError::InvalidPassword("Buffer too small".into()))
             }
         })
         .or_else(|_| {
             // Maybe Backup Header?
             if size >= 131072 {
                 let offset = size - 131072;
                 file.seek(SeekFrom::Start(offset)).map_err(|e| VolumeError::IoError(e))?;
                 let mut buf = vec![0u8; 512];
                 file.read_exact(&mut buf).map_err(|e| VolumeError::IoError(e))?;
                 try_header_at_offset(old_password, &buf, old_pim, offset, 0, None)
             } else {
                 Err(VolumeError::InvalidPassword("Failed to decrypt header".to_string()))
             }
         })?;
    
    // Update header with new salt and pim (in-memory).
    if new_salt.len() != 64 {
        return Err(VolumeError::CryptoError("Salt must be 64 bytes".into()));
    }
    let mut salt_arr = Zeroizing::new([0u8; 64]);
    salt_arr.copy_from_slice(new_salt);
    volume.header.salt = *salt_arr;
    volume.header.pim = new_pim;

    // Serialize the header.
    let serialized_header = volume.header.serialize()
        .map_err(|e| VolumeError::InvalidHeader(e))?; 
        
        let cipher_type = cipher_type_from_supported(&volume.cipher);
        let required_key_size = required_key_size_for_cipher(cipher_type);

        // Select PRF
    let active_prf = new_prf.or(volume.prf).unwrap_or(PrfAlgorithm::Sha512);

    // Derive new header key using the selected PRF
    let mut new_header_key = Zeroizing::new([0u8; 192]); 
    derive_key_generic(new_password, &*salt_arr, new_pim, &mut *new_header_key, active_prf);

    // Weak key check
    if has_vulnerable_xts_key_material(&new_header_key[..required_key_size], cipher_type) {
         return Err(VolumeError::CryptoError("Generated weak XTS key for header (change pwd)".into()));
    }
    
    let mut encrypted_header = serialized_header.clone();
        let key_slice = &new_header_key[..required_key_size];
        let header_cipher = create_cipher(cipher_type, key_slice)?;
        encrypt_effective_header(&header_cipher, &mut encrypted_header)?;
    
    // Write back to file to Standard Header position.
    file.seek(SeekFrom::Start(volume.header_offset)).map_err(|e| VolumeError::IoError(e))?;
    file.write_all(&encrypted_header).map_err(|e| VolumeError::IoError(e))?;
    file.sync_all().map_err(|e| VolumeError::IoError(e))?;
    
    // Write to Backup Header
    let size = file.metadata().map_err(|e| VolumeError::IoError(e))?.len();
    
    if volume.header_offset == 0 && size >= 131072 {
         let backup_offset = size - 131072;
         file.seek(SeekFrom::Start(backup_offset)).map_err(|e| VolumeError::IoError(e))?;
         file.write_all(&encrypted_header).map_err(|e| VolumeError::IoError(e))?;
         file.sync_all().map_err(|e| VolumeError::IoError(e))?;
    } else if volume.header_offset == 65536 {
         // Fix Bug 5: Hidden Volume should NOT have a backup header.
         // Writing to the end of the volume would reveal the hidden volume or corruption.
         log::warn!("Skipping backup header write for Hidden Volume");
    } else if size >= 65536 {
         // Fallback logic for weird cases or standard handling if offset != 0?
         // Standard is offset 0 -> Backup at End-128K
         // If offset was 0, it was handled above.
         // If logic falls here, it means header_offset != 0 and != 65536
         // This block was:
         // } else if volume.header_offset == 65536 && size >= 65536 {
         //      let backup_offset = size - 65536; ...
         // }
         // The original code tried to write backup for hidden volume at `size - 65536`? 
         // That's likely incorrect standard behavior anyway.
         // We disable it.
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequential_bytes<const N: usize>() -> [u8; N] {
        let mut bytes = [0u8; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_add(1);
        }
        bytes
    }

    #[test]
    fn test_create_cipher_aes_twofish_uses_veracrypt_key_layout() {
        let key = sequential_bytes::<128>();
        let plain = sequential_bytes::<ENCRYPTED_HEADER_SIZE>();
        let mut created_ciphertext = plain;
        let mut expected_ciphertext = plain;
        let mut legacy_ciphertext = plain;

        let created = create_cipher(CipherType::AesTwofish, &key)
            .expect("Failed to build AES-Twofish cipher");
        let expected = SupportedCipher::AesTwofish(
            Xts128::new(
                AesWrapper::new((&key[32..64]).into()),
                AesWrapper::new((&key[96..128]).into()),
            ),
            Xts128::new(
                TwofishWrapper::new((&key[0..32]).into()),
                TwofishWrapper::new((&key[64..96]).into()),
            ),
        );
        let legacy = SupportedCipher::AesTwofish(
            Xts128::new(
                AesWrapper::new((&key[0..32]).into()),
                AesWrapper::new((&key[32..64]).into()),
            ),
            Xts128::new(
                TwofishWrapper::new((&key[64..96]).into()),
                TwofishWrapper::new((&key[96..128]).into()),
            ),
        );

        created.encrypt_area(&mut created_ciphertext, ENCRYPTED_HEADER_SIZE, 0);
        expected.encrypt_area(&mut expected_ciphertext, ENCRYPTED_HEADER_SIZE, 0);
        legacy.encrypt_area(&mut legacy_ciphertext, ENCRYPTED_HEADER_SIZE, 0);

        assert_eq!(created_ciphertext, expected_ciphertext);
        assert_ne!(created_ciphertext, legacy_ciphertext);

        let decrypted = decrypt_effective_header(&created, &created_ciphertext)
            .expect("Failed to decrypt AES-Twofish header");
        assert_eq!(&*decrypted, &plain);
    }

    #[test]
    fn test_encrypt_effective_header_keeps_salt_plaintext() {
        let key = sequential_bytes::<64>();
        let cipher = create_cipher(CipherType::Aes, &key)
            .expect("Failed to build AES cipher");
        let mut effective_header = sequential_bytes::<EFFECTIVE_HEADER_SIZE>();
        let original_salt = effective_header[..HEADER_SALT_SIZE].to_vec();

        encrypt_effective_header(&cipher, &mut effective_header)
            .expect("Failed to encrypt effective header");

        assert_eq!(original_salt.as_slice(), &effective_header[..HEADER_SALT_SIZE]);
    }
}

