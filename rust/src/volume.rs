// Import supported cipher wrappers from the crypto module.
use crate::crypto::{CamelliaWrapper, KuznyechikWrapper, SupportedCipher};
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
use zeroize::{Zeroize, ZeroizeOnDrop};
// Import standard library types.
use std::sync::{Arc, Mutex};
// Import formatting traits.
use std::fmt;
// Import cipher traits.
use cipher::{BlockCipher, KeyInit, KeySizeUser};

// Define an enumeration for volume-related errors.
#[derive(Debug, Clone)]
#[allow(dead_code)]
#[allow(unused_assignments)]
pub enum VolumeError {
    // Error indicating an invalid password or PIM.
    InvalidPassword,
    // Error indicating an invalid volume header.
    InvalidHeader(HeaderError),
    // Generic cryptographic error with a message.
    CryptoError(String),
    // Error indicating the volume is not initialized.
    NotInitialized,
}

// Implement conversion from HeaderError to VolumeError.
impl From<HeaderError> for VolumeError {
    fn from(e: HeaderError) -> Self {
        // Wrap the HeaderError in VolumeError::InvalidHeader.
        VolumeError::InvalidHeader(e)
    }
}

// Implement Display trait for VolumeError to provide user-friendly messages.
impl fmt::Display for VolumeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // Write "Invalid password or PIM" for InvalidPassword.
            VolumeError::InvalidPassword => write!(f, "Invalid password or PIM"),
            // Write "Invalid volume header: " followed by the header error.
            VolumeError::InvalidHeader(e) => write!(f, "Invalid volume header: {}", e),
            // Write "Crypto Error: " followed by the message.
            VolumeError::CryptoError(msg) => write!(f, "Crypto Error: {}", msg),
            // Write "Volume not initialized" for NotInitialized.
            VolumeError::NotInitialized => write!(f, "Volume not initialized"),
        }
    }
}

// Define the Volume struct representing a mounted volume.
// Derive Zeroize and ZeroizeOnDrop to securely clear sensitive data.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Volume {
    // The parsed volume header.
    header: VolumeHeader,
    // The cipher used for encryption/decryption. Skipped for zeroization as it might contain non-zeroizable types or is handled separately.
    #[zeroize(skip)]
    cipher: SupportedCipher,
    // The offset where the partition starts.
    partition_start_offset: u64,
    // The offset of the hidden volume, if any.
    hidden_volume_offset: u64,
    // Flag indicating if the volume is read-only.
    read_only: bool,
    // Start of the protected range (for hidden volume protection).
    protected_range_start: u64,
    // End of the protected range.
    protected_range_end: u64,
}

// Implement Send trait for Volume to allow it to be sent across threads.
// This is unsafe because we are asserting it is safe to send.
unsafe impl Send for Volume {}

// Implementation block for Volume methods.
impl Volume {
    // Constructor to create a new Volume instance.
    pub fn new(
        header: VolumeHeader,
        cipher: SupportedCipher,
        partition_start_offset: u64,
        hidden_volume_offset: u64,
        read_only: bool,
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

    // Method to decrypt a sector of data.
    #[allow(clippy::manual_is_multiple_of)]
    pub fn decrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<(), VolumeError> {
        // Get the sector size as usize.
        let sector_size = self.header.sector_size as usize;

        // Ensure the data length is a multiple of the sector size.
        if data.len() % sector_size != 0 {
            // Return an error if not aligned.
            return Err(VolumeError::CryptoError(format!(
                "Data length {} is not a multiple of sector size {}",
                data.len(),
                sector_size
            )));
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
                let start_unit_no = (self.partition_start_offset
                    + self.header.encrypted_area_start
                    + current_sector * sector_size as u64)
                    / 512;
                // Calculate the specific unit number for this 512-byte block.
                let unit_no = start_unit_no + i as u64;

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
        let start_offset = sector_index * sector_size as u64;
        // Calculate the end offset of the write operation.
        let end_offset = start_offset + data.len() as u64;

        // Check hidden volume protection
        if self.protected_range_end > 0 {
            // Check overlap
            // protected_range is physical offset? Or logical?
            // In create_context, we set it using `hidden_vol.header.encrypted_area_start`.
            // That is physical offset relative to volume start.
            // Here start_offset is logical.
            // We must convert start_offset to physical.
            // Calculate physical start offset.
            let phys_start = self.header.encrypted_area_start + start_offset;
            // Calculate physical end offset.
            let phys_end = self.header.encrypted_area_start + end_offset;

            // Check if the write operation overlaps with the protected range.
            if (phys_start < self.protected_range_end) && (phys_end > self.protected_range_start) {
                // Return error if it overlaps, blocking the write.
                return Err(VolumeError::CryptoError(
                    "Write operation blocked by Hidden Volume Protection".to_string(),
                ));
            }
        }
        // Ensure data length is a multiple of the sector size.
        if data.len() % sector_size != 0 {
            // Return error if not aligned.
            return Err(VolumeError::CryptoError(format!(
                "Data length {} is not a multiple of sector size {}",
                data.len(),
                sector_size
            )));
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
                let start_unit_no = (self.partition_start_offset
                    + self.header.encrypted_area_start
                    + current_sector * sector_size as u64)
                    / 512;
                let unit_no = start_unit_no + i as u64;

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
pub fn create_context(
    password: &[u8],
    header_bytes: &[u8],
    pim: i32,
    partition_start_offset: u64,
    protection_password: Option<&[u8]>,
    protection_pim: i32,
) -> Result<i64, VolumeError> {
    // Try Standard Header at offset 0
    // Attempt to decrypt the header at the beginning of the buffer.
    if let Ok(mut vol) =
        try_header_at_offset(password, header_bytes, pim, 0, partition_start_offset)
    {
        // If protection is requested, try to mount hidden volume
        if let Some(prot_pass) = protection_password {
            // Check if buffer is large enough for hidden volume header (at 64KB).
            if header_bytes.len() >= 65536 + 512 {
                // Attempt to decrypt the hidden volume header.
                match try_header_at_offset(
                    prot_pass,
                    header_bytes,
                    protection_pim,
                    65536,
                    partition_start_offset,
                ) {
                    Ok(hidden_vol) => {
                        // Log success.
                        log::info!("Hidden Volume Protection Enabled");
                        // Calculate protected range
                        // Hidden volume is at the end of the outer volume?
                        // No, hidden volume is within the outer volume.
                        // We need to protect the area occupied by the hidden volume.
                        // The hidden volume header is at 65536.
                        // The hidden volume data starts at `hidden_vol.header.encrypted_area_start`?
                        // Actually, for hidden volume, `encrypted_area_start` is the offset relative to the start of the *host* volume (outer volume).
                        // So we protect from `encrypted_area_start` to `encrypted_area_start + encrypted_area_length`.

                        // Get start of protected area.
                        let start = hidden_vol.header.encrypted_area_start;
                        // Get end of protected area.
                        let end = start + hidden_vol.header.volume_data_size;
                        // Set protection on the outer volume.
                        vol.set_protection(start, end);
                    }
                    Err(_) => {
                        // If protection password provided but failed to mount hidden volume, fail the whole operation?
                        // VeraCrypt behavior: "Incorrect protection password" or similar.
                        // Return error if hidden volume mount fails.
                        return Err(VolumeError::CryptoError(
                            "Failed to mount hidden volume for protection".to_string(),
                        ));
                    }
                }
            } else {
                // Return error if buffer is too small.
                return Err(VolumeError::CryptoError(
                    "Buffer too small for hidden volume check".to_string(),
                ));
            }
        }
        // Register the volume context and return the handle.
        return register_context(vol);
    }

    // Try Hidden Volume Header at offset 65536 (64KB)
    // Only if NOT protecting (if protecting, we expect outer volume at 0)
    if protection_password.is_none() && header_bytes.len() >= 65536 + 512 {
        // Attempt to decrypt header at 64KB offset.
        if let Ok(vol) =
            try_header_at_offset(password, header_bytes, pim, 65536, partition_start_offset)
        {
            // Log success.
            log::info!("Mounted Hidden Volume");
            // Register context.
            return register_context(vol);
        }
    }

    // Return InvalidPassword if all attempts fail.
    Err(VolumeError::InvalidPassword)
}

// Renamed helper to return Volume
// Helper function to try decrypting a header at a specific offset.
fn try_header_at_offset(
    password: &[u8],
    full_buffer: &[u8],
    pim: i32,
    offset: usize,
    partition_start_offset: u64,
) -> Result<Volume, VolumeError> {
    // Check if buffer has enough data for the header.
    if full_buffer.len() < offset + 512 {
        // Return InvalidMagic if too short.
        return Err(VolumeError::InvalidHeader(HeaderError::InvalidMagic));
    }

    // Extract the header slice.
    let header_slice = &full_buffer[offset..offset + 512];
    // Extract salt (first 64 bytes).
    let salt = &header_slice[..64];
    // Extract encrypted header data (remaining 448 bytes).
    let encrypted_header = &header_slice[64..512];

    // Iteration counts to try
    let mut iterations_list = Vec::new();

    // If PIM is specified, calculate iterations based on PIM.
    if pim > 0 {
        // Standard iterations with PIM.
        iterations_list.push(15000 + (pim as u32 * 1000));
        // System Encryption / Boot (SHA-256, Blake2s, Streebog) with PIM.
        iterations_list.push(pim as u32 * 2048);
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
    let mut header_key = [0u8; 192];

    // Helper closure to try all supported ciphers with a derived key.
    let try_unlock = |key: &[u8]| -> Result<Volume, VolumeError> {
        let hv_offset = offset as u64;
        // Try AES
        if let Ok(v) = try_cipher::<Aes256>(
            key,
            encrypted_header,
            partition_start_offset,
            hv_offset,
            |k1, k2| {
                SupportedCipher::Aes(Xts128::new(AesWrapper::new(k1.into()), AesWrapper::new(k2.into())))
            },
        ) {
            return Ok(v);
        }
        // Try Serpent
        if let Ok(v) = try_cipher_serpent(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Twofish
        if let Ok(v) = try_cipher::<Twofish>(
            key,
            encrypted_header,
            partition_start_offset,
            hv_offset,
            |k1, k2| {
                SupportedCipher::Twofish(Xts128::new(
                    TwofishWrapper::new(k1.into()),
                    TwofishWrapper::new(k2.into()),
                ))
            },
        ) {
            return Ok(v);
        }

        // Cascades
        // Try AES-Twofish
        if let Ok(v) =
            try_cipher_aes_twofish(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try AES-Twofish-Serpent
        if let Ok(v) =
            try_cipher_aes_twofish_serpent(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Serpent-AES
        if let Ok(v) =
            try_cipher_serpent_aes(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Twofish-Serpent
        if let Ok(v) =
            try_cipher_twofish_serpent(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Serpent-Twofish-AES
        if let Ok(v) =
            try_cipher_serpent_twofish_aes(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Camellia
        if let Ok(v) = try_cipher_camellia(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Kuznyechik
        if let Ok(v) =
            try_cipher_kuznyechik(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Camellia-Kuznyechik
        if let Ok(v) =
            try_cipher_camellia_kuznyechik(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Camellia-Serpent
        if let Ok(v) =
            try_cipher_camellia_serpent(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Kuznyechik-AES
        if let Ok(v) =
            try_cipher_kuznyechik_aes(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }
        // Try Kuznyechik-Serpent-Camellia
        if let Ok(v) = try_cipher_kuznyechik_serpent_camellia(
            key,
            encrypted_header,
            partition_start_offset,
            hv_offset,
        ) {
            return Ok(v);
        }
        // Try Kuznyechik-Twofish
        if let Ok(v) =
            try_cipher_kuznyechik_twofish(key, encrypted_header, partition_start_offset, hv_offset)
        {
            return Ok(v);
        }

        // Return InvalidPassword if none work.
        Err(VolumeError::InvalidPassword)
    };

    // Iterate through all iteration counts.
    for &iter in &iterations_list {
        // 1. SHA-512
        // Derive key using PBKDF2-HMAC-SHA512.
        pbkdf2::<Hmac<Sha512>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock with this key.
        if let Ok(vol) = try_unlock(&header_key) {
            return Ok(vol);
        }

        // 2. SHA-256
        // Derive key using PBKDF2-HMAC-SHA256.
        pbkdf2::<Hmac<Sha256>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        if let Ok(vol) = try_unlock(&header_key) {
            return Ok(vol);
        }

        // 3. Whirlpool
        // Derive key using PBKDF2-HMAC-Whirlpool.
        pbkdf2::<Hmac<Whirlpool>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        if let Ok(vol) = try_unlock(&header_key) {
            return Ok(vol);
        }

        // 4. Blake2s
        // Blake2s default is 500,000. System/Boot is 200,000. PIM is pim*2048.
        // We just use `iter` from the list which covers these cases.
        // Derive key using PBKDF2-SimpleHmac-Blake2s256.
        pbkdf2::<SimpleHmac<Blake2s256>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        if let Ok(vol) = try_unlock(&header_key) {
            return Ok(vol);
        }

        // 5. Streebog
        // Derive key using PBKDF2-SimpleHmac-Streebog512.
        pbkdf2::<SimpleHmac<Streebog512>>(password, salt, iter, &mut header_key).ok();
        // Try to unlock.
        if let Ok(vol) = try_unlock(&header_key) {
            return Ok(vol);
        }

        // 6. RIPEMD-160
        // VC Default: 655331. TC Legacy: 1000 or 2000. System Encryption: 327661. PIM: 15000 + pim*1000.
        // If PIM is provided, we use the calculated iter (15000+...).
        // If PIM=0, we need to map 500,000 -> 655,331 and 200,000 -> 327,661.
        // Calculate specific iteration count for RIPEMD-160.
        let ripemd_iter = if pim > 0 {
            // For RIPEMD-160, PIM formula is same as others? Yes.
            15000 + (pim as u32 * 1000)
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

        // Derive key using PBKDF2-HMAC-Ripemd160.
        pbkdf2::<Hmac<Ripemd160>>(password, salt, ripemd_iter, &mut header_key).ok();
        // Try to unlock.
        let res = try_unlock(&header_key);
        // Zeroize the header key after use.
        header_key.zeroize();
        // Return result if successful.
        if let Ok(vol) = res {
            return Ok(vol);
        }
    }

    // Return InvalidPassword if all hash algorithms and iteration counts fail.
    Err(VolumeError::InvalidPassword)
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
    let contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    // Look up the volume by handle.
    if let Some(context) = contexts_lock.get(&handle) {
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
    let contexts_lock = CONTEXTS.lock().unwrap_or_else(|e| e.into_inner());
    // Look up the volume by handle.
    if let Some(context) = contexts_lock.get(&handle) {
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
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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

    // Create a buffer for the decrypted header.
    let mut decrypted = [0u8; 448];
    // Copy the encrypted header data.
    decrypted.copy_from_slice(encrypted_header);

    // Decrypt header using sector 0, tweak 0?
    // Header is not sector 0. Header is encrypted with XTS using 0 as tweak?
    // VeraCrypt: "The header is encrypted in XTS mode... The secondary key... is used to encrypt the 64-bit data unit number... which is 0 for the volume header."
    // Decrypt the header area (512 bytes, but we only have 448 here? Wait, decrypt_area takes length).
    // The header data is 448 bytes (512 - 64 salt).
    // But XTS works on blocks. 448 is multiple of 16 (28 blocks).
    // decrypt_area expects the full sector size to calculate tweaks internally?
    // No, it takes `sector_size` to know when to increment tweak?
    // Here we pass 512 as sector size, and tweak 0.
    cipher_enum.decrypt_area(&mut decrypted, 448, 0); // Sector size 512 for header? Yes.

    // Try to deserialize the decrypted header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        // Found it! Now derive the master keys for the volume data.
        // The master keys are in the decrypted header at offset 192.
        // We need to create the volume cipher using these keys.

        // Get master key data.
        let mk = &header.master_key_data;
        // Re-create the SAME cipher mode but with the master keys.
        let vol_cipher = create_cipher(&mk[0..key_size], &mk[key_size..key_size * 2]);

        // Check for vulnerable keys.
        if header.is_key_vulnerable(key_size) {
            // return Err(VolumeError::CryptoError("XTS Key Vulnerable".into()));
            log::warn!("XTS Key Vulnerable");
        }

        // Return the new Volume.
        return Ok(Volume::new(
            header,
            vol_cipher,
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    // Return InvalidPassword if deserialization fails.
    Err(VolumeError::InvalidPassword)
}

// Function to try Serpent cipher.
fn try_cipher_serpent(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
        // Create volume cipher with master keys.
        let mk = &header.master_key_data;
        let c1 = SerpentWrapper::new(mk[0..32].into());
        let c2 = SerpentWrapper::new(mk[32..64].into());
        let vol_cipher = SupportedCipher::Serpent(Xts128::new(c1, c2));

        // Check vulnerability.
        if header.is_key_vulnerable(32) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            vol_cipher,
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try AES-Twofish cascade.
fn try_cipher_aes_twofish(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
) -> Result<Volume, VolumeError> {
    // VeraCrypt AESTwofish: Twofish then AES.
    // Key mapping: 0..32 -> Twofish, 32..64 -> AES.

    // Extract keys.
    let key_twofish_1 = &header_key[0..32];
    let key_aes_1 = &header_key[32..64];
    let key_twofish_2 = &header_key[64..96];
    let key_aes_2 = &header_key[96..128];

    // Create XTS instances.
    let cipher_aes = Xts128::new(Aes256::new(key_aes_1.into()), Aes256::new(key_aes_2.into()));
    let cipher_twofish = Xts128::new(
        Twofish::new(key_twofish_1.into()),
        Twofish::new(key_twofish_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::AesTwofish(cipher_aes, cipher_twofish);

    // Decrypt header.
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
        if header.is_key_vulnerable(64) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::AesTwofish(vol_aes, vol_twofish),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try AES-Twofish-Serpent cascade.
fn try_cipher_aes_twofish_serpent(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
        if header.is_key_vulnerable(96) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::AesTwofishSerpent(vol_aes, vol_twofish, vol_serpent),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try Serpent-AES cascade.
fn try_cipher_serpent_aes(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
        if header.is_key_vulnerable(64) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::SerpentAes(vol_serpent, vol_aes),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try Twofish-Serpent cascade.
fn try_cipher_twofish_serpent(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
        if header.is_key_vulnerable(64) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::TwofishSerpent(vol_twofish, vol_serpent),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try Serpent-Twofish-AES cascade.
fn try_cipher_serpent_twofish_aes(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
        if header.is_key_vulnerable(96) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::SerpentTwofishAes(vol_serpent, vol_twofish, vol_aes),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try Camellia cipher.
fn try_cipher_camellia(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
) -> Result<Volume, VolumeError> {
    // Use generic try_cipher with CamelliaWrapper.
    try_cipher::<CamelliaWrapper>(
        header_key,
        encrypted_header,
        partition_start_offset,
        hidden_volume_offset,
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
    partition_start_offset: u64,
    hidden_volume_offset: u64,
) -> Result<Volume, VolumeError> {
    // Use generic try_cipher with KuznyechikWrapper.
    try_cipher::<KuznyechikWrapper>(
        header_key,
        encrypted_header,
        partition_start_offset,
        hidden_volume_offset,
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
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
        if header.is_key_vulnerable(64) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::CamelliaKuznyechik(vol_camellia, vol_kuznyechik),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try Camellia-Serpent cascade.
fn try_cipher_camellia_serpent(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
        Serpent::new_from_slice(key_serpent_1).unwrap(),
        Serpent::new_from_slice(key_serpent_2).unwrap(),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::CamelliaSerpent(cipher_camellia, cipher_serpent);

    // Decrypt header.
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
            Serpent::new_from_slice(mk_serpent_1).unwrap(),
            Serpent::new_from_slice(mk_serpent_2).unwrap(),
        );

        // Check vulnerability.
        if header.is_key_vulnerable(64) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::CamelliaSerpent(vol_camellia, vol_serpent),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try Kuznyechik-AES cascade.
fn try_cipher_kuznyechik_aes(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
        if header.is_key_vulnerable(64) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::KuznyechikAes(vol_kuznyechik, vol_aes),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try Kuznyechik-Serpent-Camellia cascade.
fn try_cipher_kuznyechik_serpent_camellia(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
        if header.is_key_vulnerable(96) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::KuznyechikSerpentCamellia(vol_kuznyechik, vol_serpent, vol_camellia),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}

// Function to try Kuznyechik-Twofish cascade.
fn try_cipher_kuznyechik_twofish(
    header_key: &[u8],
    encrypted_header: &[u8],
    partition_start_offset: u64,
    hidden_volume_offset: u64,
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
        Twofish::new(key_twofish_1.into()),
        Twofish::new(key_twofish_2.into()),
    );

    // Wrap in SupportedCipher.
    let cipher_enum = SupportedCipher::KuznyechikTwofish(cipher_kuznyechik, cipher_twofish);

    // Decrypt header.
    let mut decrypted = [0u8; 448];
    decrypted.copy_from_slice(encrypted_header);
    cipher_enum.decrypt_area(&mut decrypted, 448, 0);

    // Deserialize header.
    if let Ok(header) = VolumeHeader::deserialize(&decrypted) {
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
            Twofish::new(mk_twofish_1.into()),
            Twofish::new(mk_twofish_2.into()),
        );

        // Check vulnerability.
        if header.is_key_vulnerable(64) {
            log::warn!("XTS Key Vulnerable");
        }

        // Return volume.
        return Ok(Volume::new(
            header,
            SupportedCipher::KuznyechikTwofish(vol_kuznyechik, vol_twofish),
            partition_start_offset,
            hidden_volume_offset,
            false,
        ));
    }
    Err(VolumeError::InvalidPassword)
}
