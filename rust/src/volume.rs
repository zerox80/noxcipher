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
#[derive(Debug, Clone)]
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
            let phys_start = self.header.encrypted_area_start.checked_add(start_offset)
                .ok_or(VolumeError::CryptoError("Protected range physical start overflow".to_string()))?;
            // Calculate physical end offset.
            let phys_end = self.header.encrypted_area_start.checked_add(end_offset)
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
                            // encrypted_area_start is data start. header_offset is header start.
                            let start = header_offset_bias + 65536;
                            // Check overflow for end
                            let end = start.checked_add(hidden_vol.header.volume_data_size)
                                .ok_or(VolumeError::CryptoError("Hidden volume size overflow".to_string()))?;
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
                 if let Ok(vol) = try_header_at_offset(
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

// Helper to create a SupportedCipher instance from keys and type
fn create_cipher(alg: CipherType, key: &[u8]) -> Result<SupportedCipher, VolumeError> {
     match alg {
        CipherType::Aes => {
            let k = &key[..64];
            Ok(SupportedCipher::Aes(Xts128::new(AesWrapper::new((&k[0..32]).into()), AesWrapper::new((&k[32..64]).into()))))
        },
        CipherType::Serpent => {
            let k = &key[..64];
            Ok(SupportedCipher::Serpent(Xts128::new(SerpentWrapper::new((&k[0..32]).into()), SerpentWrapper::new((&k[32..64]).into()))))
        },
        CipherType::Twofish => {
            let k = &key[..64];
            Ok(SupportedCipher::Twofish(Xts128::new(TwofishWrapper::new((&k[0..32]).into()), TwofishWrapper::new((&k[32..64]).into()))))
        },
        CipherType::AesTwofish => {
            let k = &key[..128];
            Ok(SupportedCipher::AesTwofish(
                Xts128::new(AesWrapper::new((&k[0..32]).into()), AesWrapper::new((&k[32..64]).into())),
                Xts128::new(TwofishWrapper::new((&k[64..96]).into()), TwofishWrapper::new((&k[96..128]).into()))
            ))
        },
        CipherType::AesTwofishSerpent => {
             let k = &key[..192];
             Ok(SupportedCipher::AesTwofishSerpent(
                Xts128::new(AesWrapper::new((&k[0..32]).into()), AesWrapper::new((&k[32..64]).into())),
                Xts128::new(TwofishWrapper::new((&k[64..96]).into()), TwofishWrapper::new((&k[96..128]).into())),
                Xts128::new(SerpentWrapper::new((&k[128..160]).into()), SerpentWrapper::new((&k[160..192]).into()))
             ))
        },
        CipherType::SerpentAes => {
            let k = &key[..128];
            Ok(SupportedCipher::SerpentAes(
                Xts128::new(SerpentWrapper::new((&k[0..32]).into()), SerpentWrapper::new((&k[32..64]).into())),
                Xts128::new(AesWrapper::new((&k[64..96]).into()), AesWrapper::new((&k[96..128]).into()))
            ))
        },
        CipherType::TwofishSerpent => {
            let k = &key[..128];
            Ok(SupportedCipher::TwofishSerpent(
                Xts128::new(TwofishWrapper::new((&k[0..32]).into()), TwofishWrapper::new((&k[32..64]).into())),
                Xts128::new(SerpentWrapper::new((&k[64..96]).into()), SerpentWrapper::new((&k[96..128]).into()))
            ))
        },
        CipherType::SerpentTwofishAes => {
             let k = &key[..192];
             Ok(SupportedCipher::SerpentTwofishAes(
                 Xts128::new(SerpentWrapper::new((&k[0..32]).into()), SerpentWrapper::new((&k[32..64]).into())),
                 Xts128::new(TwofishWrapper::new((&k[64..96]).into()), TwofishWrapper::new((&k[96..128]).into())),
                 Xts128::new(AesWrapper::new((&k[128..160]).into()), AesWrapper::new((&k[160..192]).into()))
             ))
        },
        CipherType::Camellia => {
            let k = &key[..64];
            Ok(SupportedCipher::Camellia(Xts128::new(CamelliaWrapper::new((&k[0..32]).into()), CamelliaWrapper::new((&k[32..64]).into()))))
        },
        CipherType::Kuznyechik => {
            let k = &key[..64];
            Ok(SupportedCipher::Kuznyechik(Xts128::new(KuznyechikWrapper::new((&k[0..32]).into()), KuznyechikWrapper::new((&k[32..64]).into()))))
        },
        CipherType::CamelliaKuznyechik => {
            let k = &key[..128];
            Ok(SupportedCipher::CamelliaKuznyechik(
                Xts128::new(CamelliaWrapper::new((&k[0..32]).into()), CamelliaWrapper::new((&k[32..64]).into())),
                Xts128::new(KuznyechikWrapper::new((&k[64..96]).into()), KuznyechikWrapper::new((&k[96..128]).into()))
            ))
        },
        CipherType::CamelliaSerpent => {
            let k = &key[..128];
            Ok(SupportedCipher::CamelliaSerpent(
                Xts128::new(CamelliaWrapper::new((&k[0..32]).into()), CamelliaWrapper::new((&k[32..64]).into())),
                Xts128::new(SerpentWrapper::new((&k[64..96]).into()), SerpentWrapper::new((&k[96..128]).into()))
            ))
        },
        CipherType::KuznyechikAes => {
            let k = &key[..128];
            Ok(SupportedCipher::KuznyechikAes(
                Xts128::new(KuznyechikWrapper::new((&k[0..32]).into()), KuznyechikWrapper::new((&k[32..64]).into())),
                Xts128::new(AesWrapper::new((&k[64..96]).into()), AesWrapper::new((&k[96..128]).into()))
            ))
        },
        CipherType::KuznyechikSerpentCamellia => {
             let k = &key[..192];
             Ok(SupportedCipher::KuznyechikSerpentCamellia(
                 Xts128::new(KuznyechikWrapper::new((&k[0..32]).into()), KuznyechikWrapper::new((&k[32..64]).into())),
                 Xts128::new(SerpentWrapper::new((&k[64..96]).into()), SerpentWrapper::new((&k[96..128]).into())),
                 Xts128::new(CamelliaWrapper::new((&k[128..160]).into()), CamelliaWrapper::new((&k[160..192]).into()))
             ))
        },
        CipherType::KuznyechikTwofish => {
            let k = &key[..128];
            Ok(SupportedCipher::KuznyechikTwofish(
                Xts128::new(KuznyechikWrapper::new((&k[0..32]).into()), KuznyechikWrapper::new((&k[32..64]).into())),
                Xts128::new(TwofishWrapper::new((&k[64..96]).into()), TwofishWrapper::new((&k[96..128]).into()))
            ))
        },
        _ => Err(VolumeError::CryptoError("Cipher variant not fully supported for creation yet".to_string())),
    }
}

// Encrypted Writer for Formatting
struct EncryptedVolumeWriter<'a, W: Write + Seek> {
    inner: &'a mut W,
    cipher: SupportedCipher,
    sector_size: u64,
    data_start_offset: u64,
    current_pos: u64,
    buffer: Vec<u8>,
}

impl<'a, W: Write + Seek> EncryptedVolumeWriter<'a, W> {
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
        
        if rem != 0 {
             // WARNING: Padding with zeros. This overrides existing data on disk if this is an update.
             // Safe for formatting new volumes (create_volume), but dangerous for updates.
             log::warn!("EncryptedVolumeWriter: Padding partial sector with zeros (Potential Data Loss if updating)");
             self.buffer.resize(self.buffer.len() + (self.sector_size as usize - rem), 0);
        }
        
        // Calculate sector index
        // We assume writes are sequential for formatting usually, or we track position.
        // current_pos was advanced. buffer contains data ending at current_pos.
        // Start of buffer is at current_pos - buffer.len().
        let start_pos = self.current_pos - self.buffer.len() as u64;
        let start_sector = start_pos / self.sector_size;
        
        let mut chunks = self.buffer.chunks_exact_mut(self.sector_size as usize);
        let mut idx = start_sector;
        
        for sector in chunks.by_ref() {
             // Encrypt
             self.cipher.encrypt_area(sector, self.sector_size as usize, idx);
             idx += 1;
        }
        
        // Write to inner
        self.inner.seek(SeekFrom::Start(self.data_start_offset + start_pos))?;
        self.inner.write_all(&self.buffer)?;
        
        self.buffer.clear();
        Ok(())
    }
}

impl<'a, W: Write + Seek> Write for EncryptedVolumeWriter<'a, W> {
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

impl<'a, W: Write + Seek> Seek for EncryptedVolumeWriter<'a, W> {
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
) -> Result<(), VolumeError> {
    let mut file = OpenOptions::new().write(true).create(true).open(path)?;
    file.set_len(size)?;

    // We can't trust the passed master_key length alone for cascaded ciphers if they are truncated.
    // We expect the caller to provide enough bytes for the chosen cipher.
    let required_key_size = match cipher_type {
        CipherType::Aes | CipherType::Serpent | CipherType::Twofish | CipherType::Camellia | CipherType::Kuznyechik => 64,
        CipherType::AesTwofish | CipherType::SerpentAes | CipherType::TwofishSerpent | CipherType::CamelliaKuznyechik | CipherType::CamelliaSerpent | CipherType::KuznyechikAes | CipherType::KuznyechikTwofish => 128,
        CipherType::AesTwofishSerpent | CipherType::SerpentTwofishAes | CipherType::KuznyechikSerpentCamellia => 192,
    };

    if master_key.len() < required_key_size {
         return Err(VolumeError::CryptoError(format!("Master key too short for chosen cipher. Need {}", required_key_size)));
    }

    let mut mk_arr = Zeroizing::new([0u8; 256]);
    mk_arr[..required_key_size].copy_from_slice(&master_key[..required_key_size]);
    
    let mut salt_arr = Zeroizing::new([0u8; 64]);
    if salt.len() <= 64 { salt_arr[..salt.len()].copy_from_slice(salt); } else { salt_arr.copy_from_slice(&salt[..64]); }

    // Check for weak keys (simplified - checking all 32-byte chunks)
    for i in (0..required_key_size).step_by(32) {
         if i + 32 <= required_key_size {
             // Check if this chunk is all zeros
             if mk_arr[i..i+32].iter().all(|&x| x == 0) {
                 return Err(VolumeError::CryptoError("Weak Key Generated (All Zeros)".to_string()));
             }
         }
         // XTS check: if secondary key equals primary (Constant Time)
         if i % 64 == 0 && i + 64 <= required_key_size {
             let k1 = &mk_arr[i..i+32];
             let k2 = &mk_arr[i+32..i+64];
             let mut diff = 0u8;
             for (b1, b2) in k1.iter().zip(k2.iter()) {
                 diff |= b1 ^ b2;
             }
             if diff == 0 {
                  return Err(VolumeError::CryptoError("Weak XTS Key Generated".to_string()));
             }
         }
    }

    let sector_size = 512; // TODO: Variable sector size support

    // VeraCrypt Layout:
    // Header: 128KB (Offset 0)
    // Data: Size - 256KB
    // Backup Header: 128KB (End)
    
    let encrypted_area_start = 131072;
    let encrypted_area_length = size - 262144; // Total size - headers

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
        mk_arr,
        salt_arr,
        pim
    ).map_err(|e| VolumeError::CryptoError(e))?;

    // Serialize
    let raw_header_vec = header.serialize()?;
    let mut encrypted_header = vec![0u8; 512];
    encrypted_header.copy_from_slice(&raw_header_vec);
    
    // Encrypt header with derived key using SELECTED cipher and PRF
    // Header Key size depends on cipher type (same as master key size usually)
    let mut header_key = Zeroizing::new([0u8; 192]);
    derive_key_generic(password, salt, pim, &mut header_key, prf);
    
    let enc_part = &mut encrypted_header[64..512];
    
    // Encrypt Header
    let header_cipher = create_cipher(cipher_type, &header_key)?;
    header_cipher.encrypt_area(enc_part, 448, 0); // Tweak 0 for header
    
    // Write Primary Header
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&encrypted_header)?;
    
    // Write Backup Header (at End - 128KB)
    if size >= 131072 {
        file.seek(SeekFrom::Start(size - 131072))?;
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
            _ => {}
        }

        // Try Serpent
        match try_cipher_serpent(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
            Ok(v) => return Ok(v),
            Err(VolumeError::InvalidPassword(msg)) => *last_debug = msg,
            _ => {}
        }

        // Try Twofish
        match try_cipher_twofish(
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
            _ => {}
        }

        // Try Camellia
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

        // Try Kuznyechik
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
        
        // Cascades
        if let Ok(v) = try_cipher_aes_twofish(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
            return Ok(v);
        }
        if let Ok(v) = try_cipher_aes_twofish_serpent(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
            return Ok(v);
        }
        if let Ok(v) = try_cipher_serpent_aes(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
            return Ok(v);
        }
        if let Ok(v) = try_cipher_twofish_serpent(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf)) {
            return Ok(v);
        }
        // Try Serpent-Twofish-AES
        if let Ok(v) =
            try_cipher_serpent_twofish_aes(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf))
        {
            return Ok(v);
        }
        // Try Camellia-Kuznyechik
        if let Ok(v) =
            try_cipher_camellia_kuznyechik(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf))
        {
            return Ok(v);
        }
        // Try Camellia-Serpent
        if let Ok(v) =
            try_cipher_camellia_serpent(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf))
        {
            return Ok(v);
        }
        // Try Kuznyechik-AES
        if let Ok(v) =
            try_cipher_kuznyechik_aes(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf))
        {
            return Ok(v);
        }
        // Try Kuznyechik-Serpent-Camellia
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
        // Try Kuznyechik-Twofish
        if let Ok(v) =
            try_cipher_kuznyechik_twofish(key, encrypted_header, partition_start_offset, hv_opt, offset, salt, pim, Some(prf))
        {
            return Ok(v);
        }

        // Return InvalidPassword if none work.
        Err(VolumeError::InvalidPassword("No cipher matched".to_string()))
    };

    let mut last_debug = "None".to_string();

    // Iterate through all iteration counts.
    for (idx, &iter) in iterations_list.iter().enumerate() {
        // 1. SHA-512
        // Derive key using PBKDF2-HMAC-SHA512.
        pbkdf2::<Hmac<Sha512>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        match try_unlock(&header_key, PrfAlgorithm::Sha512, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 2. SHA-256
        // Derive key using PBKDF2-HMAC-SHA256.
        pbkdf2::<Hmac<Sha256>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        match try_unlock(&header_key, PrfAlgorithm::Sha256, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 3. Whirlpool
        // Derive key using PBKDF2-HMAC-Whirlpool.
        pbkdf2::<Hmac<Whirlpool>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        match try_unlock(&header_key, PrfAlgorithm::Whirlpool, &mut last_debug) {
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
        pbkdf2::<SimpleHmac<Blake2s256>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        match try_unlock(&header_key, PrfAlgorithm::Blake2s, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 5. Streebog
        // Derive key using PBKDF2-SimpleHmac-Streebog512.
        pbkdf2::<SimpleHmac<Streebog512>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        match try_unlock(&header_key, PrfAlgorithm::Streebog, &mut last_debug) {
            Ok(vol) => {
                header_key.zeroize();
                return Ok(vol);
            },
            _ => {}
        }

        // 6. RIPEMD-160
        // Calculate specific iteration count for RIPEMD-160.
        let ripemd_iter = if pim > 0 {
            // For RIPEMD-160, PIM formula is same as others.
            // Use checked arithmetic to prevent overflow. Return error if overflow.
            let iter = 15000u64.checked_add((pim as u64).checked_mul(1000).ok_or(VolumeError::CryptoError("PIM RIPEMD overflow".to_string()))?)
                .ok_or(VolumeError::CryptoError("PIM RIPEMD overflow".to_string()))?;
            if iter > u32::MAX as u64 { 
                return Err(VolumeError::CryptoError("PIM iterations (RIPEMD) too large".to_string())); 
            } else { 
                iter as u32 
            }
        } else {
            // Map standard iteration counts to RIPEMD specific ones.
            if iter == 500_000 {
                655_331
            } else if iter == 200_000 {
                327_661
            } else {
                iter
            }
        };

        // Optimized: Only run RIPEMD if not redundant (when pim > 0, ripemd_iter is constant)
        let run_ripemd = if pim > 0 { iter == iterations_list[0] } else { true };

        if run_ripemd {
            // Derive key using PBKDF2-HMAC-Ripemd160.
            pbkdf2::<Hmac<Ripemd160>>(password, salt, ripemd_iter, &mut header_key).ok();
            // Try to unlock.
            match try_unlock(&header_key, PrfAlgorithm::Ripemd160, &mut last_debug) {
                Ok(vol) => {
                    header_key.zeroize();
                    return Ok(vol);
                },
                _ => {}
            }
        }

        // 7. SHA-1 (Legacy)
        // Derive key using PBKDF2-HMAC-SHA1.
        pbkdf2::<Hmac<Sha1>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        match try_unlock(&header_key, PrfAlgorithm::Sha1, &mut last_debug) {
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

    // Create a buffer for the full sector (512 bytes) to ensure correct XTS tweak application.
    // The header is the last 448 bytes of the first 512-byte sector.
    let mut sector_buffer = Zeroizing::new([0u8; 512]);
    // Copy the encrypted header data to offset 64.
    sector_buffer[64..512].copy_from_slice(encrypted_header);

    // Decrypt the full 512-byte sector using tweak 0.
    cipher_enum.decrypt_area(&mut sector_buffer, 512, 0);

    // Create a buffer for the decrypted header (448 bytes).
    let mut decrypted = Zeroizing::new([0u8; 448]);
    // Copy the decrypted part back.
    decrypted.copy_from_slice(&sector_buffer[64..512]);

    // Try to deserialize the decrypted header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted, salt, pim) {
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
// Function to change the password of an existing volume.
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
    use xts_mode::Xts128; // Ensure imports if not global

    // Open the file with read and write permissions.
    let mut file = OpenOptions::new().read(true).write(true).open(path)
        .map_err(|e| VolumeError::IoError(e))?;

    // Read the primary header (first 65 KB to allow for hidden vol check if we wanted, but here just standard)
    // VeraCrypt reads first 128KB usually.
    let mut buffer = vec![0u8; 65536 + 512];
    let read_len = file.read(&mut buffer).map_err(|e| VolumeError::IoError(e))?;

    // Try to decrypt the header with the old password.
    let mut volume = try_header_at_offset(old_password, &buffer, old_pim, 0, 0, None)
         .or_else(|_| {
             // Maybe Backup Header?
             let size = file.metadata()?.len();
             if size >= 131072 {
                 let offset = size - 131072;
                 file.seek(SeekFrom::Start(offset))?;
                 let mut buf = vec![0u8; 512];
                 file.read_exact(&mut buf)?;
                 try_header_at_offset(old_password, &buf, old_pim, 0, 0, None) // 0 offset for backup header buffer
             } else {
                 Err(VolumeError::InvalidPassword("Failed to decrypt header".to_string()))
             }
         })?;
    
    // Update header with new salt and pim (in-memory).
    if new_salt.len() != 64 {
        return Err(VolumeError::CryptoError("Salt must be 64 bytes".into()));
    }
    let mut salt_arr = [0u8; 64];
    salt_arr.copy_from_slice(new_salt);
    volume.header.salt = salt_arr;
    volume.header.pim = new_pim;

    // Serialize the header.
    let serialized_header = volume.header.serialize()
        .map_err(|e| VolumeError::InvalidHeader(e))?; 
        
    // Select PRF
    let active_prf = new_prf.or(volume.prf).unwrap_or(PrfAlgorithm::Sha512);

    // Derive new header key using the selected PRF
    let mut new_header_key = Zeroizing::new([0u8; 192]); 
    derive_key_generic(new_password, &salt_arr, new_pim, &mut new_header_key, active_prf);

    // Weak key check
    for i in (0..192).step_by(64) {
        if i + 64 <= 192 {
            if new_header_key[i..i+32] == new_header_key[i+32..i+64] {
                 return Err(VolumeError::CryptoError("Generated weak XTS key for header (change pwd)".into()));
            }
        }
    }
    
    let mut encrypted_header = serialized_header.clone();
    let key_slice = &new_header_key[..];

    // Encryption: Re-encrypt using the SAME cipher that the volume uses.
    let encrypt_header_ops = |cipher: &SupportedCipher, buffer: &mut [u8]| {
         let mut sector_buf = [0u8; 512];
         // We only encrypt offset 64..512 (448 bytes)
         sector_buf[0..64].copy_from_slice(&buffer[0..64]); // Salt is plain
         sector_buf[64..512].copy_from_slice(&buffer[64..512]);
         
         cipher.encrypt_area(&mut sector_buf, 448, 0); // Tweak 0 for header
         
         buffer[64..512].copy_from_slice(&sector_buf[64..512]);
    };

    match &volume.cipher {
        SupportedCipher::Aes(_) => {
             let key = &key_slice[0..64];
             let c1 = AesWrapper::new((&key[0..32]).into());
             let c2 = AesWrapper::new((&key[32..64]).into());
             let xts = Xts128::<AesWrapper>::new(c1, c2);
             encrypt_header_ops(&SupportedCipher::Aes(xts), &mut encrypted_header);
        },
        SupportedCipher::Serpent(_) => {
             let key = &key_slice[0..64];
             let c1 = SerpentWrapper::new((&key[0..32]).into());
             let c2 = SerpentWrapper::new((&key[32..64]).into());
             let xts = Xts128::<SerpentWrapper>::new(c1, c2);
             encrypt_header_ops(&SupportedCipher::Serpent(xts), &mut encrypted_header);
        },
        SupportedCipher::Twofish(_) => {
             let key = &key_slice[0..64];
             let c1 = TwofishWrapper::new((&key[0..32]).into());
             let c2 = TwofishWrapper::new((&key[32..64]).into());
             let xts = Xts128::<TwofishWrapper>::new(c1, c2);
             encrypt_header_ops(&SupportedCipher::Twofish(xts), &mut encrypted_header);
        },
        SupportedCipher::AesTwofish(_, _) => {
             let k_tf = &key_slice[0..64];  // Twofish first in encryption
             let k_aes = &key_slice[64..128]; // AES second in encryption?
             // Wait, AES-Twofish Decrypt means AES then Twofish.
             // Encrypt means Twofish then AES.
             // supported_cipher.encrypt_area handles the order!
             // We just need to construct the SupportedCipher correctly with correct keys.
             // But valid `SupportedCipher` requires constructed XTS objects.
             let k = &key_slice[0..128]; // 64 bytes each? No, 64 bytes total XTS per cipher.
             // XTS key size for each is 64 bytes.
             // AES-Twofish uses 128 bytes total header key? Yes.
             
             let c = SupportedCipher::AesTwofish(
                 Xts128::new(AesWrapper::new((&k[0..32]).into()), AesWrapper::new((&k[32..64]).into())),
                 Xts128::new(TwofishWrapper::new((&k[64..96]).into()), TwofishWrapper::new((&k[96..128]).into()))
             );
             encrypt_header_ops(&c, &mut encrypted_header);
        },
        SupportedCipher::AesTwofishSerpent(_,_,_) => {
             let k = &key_slice[0..192];
             let c = SupportedCipher::AesTwofishSerpent(
                 Xts128::new(AesWrapper::new((&k[0..32]).into()), AesWrapper::new((&k[32..64]).into())),
                 Xts128::new(TwofishWrapper::new((&k[64..96]).into()), TwofishWrapper::new((&k[96..128]).into())),
                 Xts128::new(SerpentWrapper::new((&k[128..160]).into()), SerpentWrapper::new((&k[160..192]).into()))
             );
             encrypt_header_ops(&c, &mut encrypted_header);
        },
        SupportedCipher::SerpentAes(_,_) => {
             let k = &key_slice[0..128];
             let c = SupportedCipher::SerpentAes(
                Xts128::new(SerpentWrapper::new((&k[0..32]).into()), SerpentWrapper::new((&k[32..64]).into())),
                Xts128::new(AesWrapper::new((&k[64..96]).into()), AesWrapper::new((&k[96..128]).into()))
             );
             encrypt_header_ops(&c, &mut encrypted_header);
        },
        SupportedCipher::TwofishSerpent(_,_) => {
             let k = &key_slice[0..128];
             let c = SupportedCipher::TwofishSerpent(
                Xts128::new(TwofishWrapper::new((&k[0..32]).into()), TwofishWrapper::new((&k[32..64]).into())),
                Xts128::new(SerpentWrapper::new((&k[64..96]).into()), SerpentWrapper::new((&k[96..128]).into()))
             );
             encrypt_header_ops(&c, &mut encrypted_header);
        },
        SupportedCipher::SerpentTwofishAes(_,_,_) => {
             let k = &key_slice[0..192];
             let c = SupportedCipher::SerpentTwofishAes(
                 Xts128::new(SerpentWrapper::new((&k[0..32]).into()), SerpentWrapper::new((&k[32..64]).into())),
                 Xts128::new(TwofishWrapper::new((&k[64..96]).into()), TwofishWrapper::new((&k[96..128]).into())),
                 Xts128::new(AesWrapper::new((&k[128..160]).into()), AesWrapper::new((&k[160..192]).into()))
             );
             encrypt_header_ops(&c, &mut encrypted_header);
        },
        // Legacy/Other support if needed (Camellia etc)
        // For brevity implementing common ones, assuming Camellia variants follow same pattern
        _ => return Err(VolumeError::CryptoError("Cipher variant not fully supported for re-encryption yet".to_string())),
    }

    // Write Primary
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&encrypted_header)?;
    
    // Write Backup
    let size = file.metadata()?.len();
    if size >= 131072 {
        file.seek(SeekFrom::Start(size - 131072))?;
        file.write_all(&encrypted_header)?;
    }
    
    Ok(())
}
             let c_aes = Xts128::new(AesWrapper::new(k_aes1.into()), AesWrapper::new(k_aes2.into()));
             let c_tf = Xts128::new(TwofishWrapper::new(k_tf1.into()), TwofishWrapper::new(k_tf2.into()));
             encrypt_header_ops(&SupportedCipher::AesTwofish(c_aes, c_tf), &mut encrypted_header);
        },
        SupportedCipher::AesTwofishSerpent(_, _, _) => {
            // Serpent(0-32), Twofish(32-64), AES(64-96)
             let k_s1 = &key_slice[0..32];
             let k_t1 = &key_slice[32..64];
             let k_a1 = &key_slice[64..96];
             let k_s2 = &key_slice[96..128];
             let k_t2 = &key_slice[128..160];
             let k_a2 = &key_slice[160..192];

             let c_aes = Xts128::new(AesWrapper::new(k_a1.into()), AesWrapper::new(k_a2.into()));
             let c_tf = Xts128::new(TwofishWrapper::new(k_t1.into()), TwofishWrapper::new(k_t2.into()));
             let c_s = Xts128::new(SerpentWrapper::new(k_s1.into()), SerpentWrapper::new(k_s2.into()));
             encrypt_header_ops(&SupportedCipher::AesTwofishSerpent(c_aes, c_tf, c_s), &mut encrypted_header);
        },
        SupportedCipher::SerpentAes(_, _) => {
             // AES(0-32), Serpent(32-64)
             let k_a1 = &key_slice[0..32];
             let k_s1 = &key_slice[32..64];
             let k_a2 = &key_slice[64..96];
             let k_s2 = &key_slice[96..128];
             let c_aes = Xts128::new(AesWrapper::new(k_a1.into()), AesWrapper::new(k_a2.into()));
             let c_s = Xts128::new(SerpentWrapper::new(k_s1.into()), SerpentWrapper::new(k_s2.into()));
             encrypt_header_ops(&SupportedCipher::SerpentAes(c_s, c_aes), &mut encrypted_header);
        },
        SupportedCipher::TwofishSerpent(_, _) => {
             // Serpent(0-32), Twofish(32-64)
             let k_s1 = &key_slice[0..32];
             let k_t1 = &key_slice[32..64];
             let k_s2 = &key_slice[64..96];
             let k_t2 = &key_slice[96..128];
             let c_tf = Xts128::new(TwofishWrapper::new(k_t1.into()), TwofishWrapper::new(k_t2.into()));
             let c_s = Xts128::new(SerpentWrapper::new(k_s1.into()), SerpentWrapper::new(k_s2.into()));
             encrypt_header_ops(&SupportedCipher::TwofishSerpent(c_tf, c_s), &mut encrypted_header);
        },
        // Add others (SerpentTwofishAes, CamelliaKuznyechik, etc.) if needed. 
        // For brevity in this fix, we cover the common ones. 
        // If an algorithm is not supported here, it will error, which is better than wrong encryption.
        SupportedCipher::SerpentTwofishAes(_, _, _) => {
             // Serpent(0-32), Twofish(32-64), AES(64-96)
             let k_s1 = &key_slice[0..32];
             let k_t1 = &key_slice[32..64];
             let k_a1 = &key_slice[64..96];
             let k_s2 = &key_slice[96..128];
             let k_t2 = &key_slice[128..160];
             let k_a2 = &key_slice[160..192];

             let c_aes = Xts128::new(AesWrapper::new(k_a1.into()), AesWrapper::new(k_a2.into()));
             let c_tf = Xts128::new(TwofishWrapper::new(k_t1.into()), TwofishWrapper::new(k_t2.into()));
             let c_s = Xts128::new(SerpentWrapper::new(k_s1.into()), SerpentWrapper::new(k_s2.into()));
             encrypt_header_ops(&SupportedCipher::SerpentTwofishAes(c_s, c_tf, c_aes), &mut encrypted_header);
        },
        SupportedCipher::CamelliaKuznyechik(_, _) => {
             // Camellia(0), Kuznyechik(32)
             let k_c1 = &key_slice[0..32];
             let k_k1 = &key_slice[32..64];
             let k_c2 = &key_slice[64..96];
             let k_k2 = &key_slice[96..128];
             let c_k = Xts128::new(KuznyechikWrapper::new(k_k1.into()), KuznyechikWrapper::new(k_k2.into()));
             let c_c = Xts128::new(CamelliaWrapper::new(k_c1.into()), CamelliaWrapper::new(k_c2.into()));
             encrypt_header_ops(&SupportedCipher::CamelliaKuznyechik(c_c, c_k), &mut encrypted_header);
        },
        SupportedCipher::CamelliaSerpent(_, _) => {
             // Camellia(0), Serpent(32)
             let k_c1 = &key_slice[0..32];
             let k_s1 = &key_slice[32..64];
             let k_c2 = &key_slice[64..96];
             let k_s2 = &key_slice[96..128];
             let c_s = Xts128::new(SerpentWrapper::new(k_s1.into()), SerpentWrapper::new(k_s2.into()));
             let c_c = Xts128::new(CamelliaWrapper::new(k_c1.into()), CamelliaWrapper::new(k_c2.into()));
             encrypt_header_ops(&SupportedCipher::CamelliaSerpent(c_c, c_s), &mut encrypted_header);
        },
        SupportedCipher::KuznyechikAes(_, _) => {
             // Kuznyechik(0), AES(32)
             let k_k1 = &key_slice[0..32];
             let k_a1 = &key_slice[32..64];
             let k_k2 = &key_slice[64..96];
             let k_a2 = &key_slice[96..128];
             let c_a = Xts128::new(AesWrapper::new(k_a1.into()), AesWrapper::new(k_a2.into()));
             let c_k = Xts128::new(KuznyechikWrapper::new(k_k1.into()), KuznyechikWrapper::new(k_k2.into()));
             encrypt_header_ops(&SupportedCipher::KuznyechikAes(c_k, c_a), &mut encrypted_header);
        },
        SupportedCipher::KuznyechikSerpentCamellia(_, _, _) => {
             // Kuznyechik(0), Serpent(32), Camellia(64)
             let k_k1 = &key_slice[0..32];
             let k_s1 = &key_slice[32..64];
             let k_c1 = &key_slice[64..96];
             let k_k2 = &key_slice[96..128];
             let k_s2 = &key_slice[128..160];
             let k_c2 = &key_slice[160..192];
             
             let c_c = Xts128::new(CamelliaWrapper::new(k_c1.into()), CamelliaWrapper::new(k_c2.into()));
             let c_s = Xts128::new(SerpentWrapper::new(k_s1.into()), SerpentWrapper::new(k_s2.into()));
             let c_k = Xts128::new(KuznyechikWrapper::new(k_k1.into()), KuznyechikWrapper::new(k_k2.into()));
             encrypt_header_ops(&SupportedCipher::KuznyechikSerpentCamellia(c_k, c_s, c_c), &mut encrypted_header);
        },
        SupportedCipher::KuznyechikTwofish(_, _) => {
             // Kuznyechik(0), Twofish(32)
             let k_k1 = &key_slice[0..32];
             let k_t1 = &key_slice[32..64];
             let k_k2 = &key_slice[64..96];
             let k_t2 = &key_slice[96..128];
             let c_t = Xts128::new(TwofishWrapper::new(k_t1.into()), TwofishWrapper::new(k_t2.into()));
             let c_k = Xts128::new(KuznyechikWrapper::new(k_k1.into()), KuznyechikWrapper::new(k_k2.into()));
             encrypt_header_ops(&SupportedCipher::KuznyechikTwofish(c_k, c_t), &mut encrypted_header);
        },
        _ => {
            return Err(VolumeError::CryptoError(format!("Cipher {:?} not supported for password change yet", volume.cipher)));
        }
    }
    
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
    } else if volume.header_offset == 65536 && size >= 65536 {
         let backup_offset = size - 65536;
         file.seek(SeekFrom::Start(backup_offset)).map_err(|e| VolumeError::IoError(e))?;
         file.write_all(&encrypted_header).map_err(|e| VolumeError::IoError(e))?;
         file.sync_all().map_err(|e| VolumeError::IoError(e))?;
    }
    
    Ok(())
}

