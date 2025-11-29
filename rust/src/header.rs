// Import the ByteOrder trait and BigEndian struct from the byteorder crate to handle byte order conversions.
use byteorder::{BigEndian, ByteOrder};
// Import the fmt module from the standard library for formatting traits.
use std::fmt;
// Import Zeroize and ZeroizeOnDrop traits to securely clear memory when it goes out of scope.
use zeroize::{Zeroize, ZeroizeOnDrop};

// Define an enumeration for possible errors that can occur when parsing the volume header.
// Derive Debug and Clone traits for easy printing and copying.
#[derive(Debug, Clone)]
pub enum HeaderError {
    // Error indicating the magic bytes "VERA" or "TRUE" were not found.
    InvalidMagic,
    // Error indicating the calculated CRC32 checksum does not match the stored one.
    InvalidCrc,
    // Error indicating the header version is not supported by this implementation.
    UnsupportedVersion,
    // Error indicating the minimum program version required is higher than supported.
    UnsupportedProgramVersion,
    // Error indicating the sector size is invalid (not 512, 1024, 2048, or 4096).
    InvalidSectorSize,
    // Error indicating the key size is invalid.
    InvalidKeySize,
}

// Implement the Display trait for HeaderError to provide user-friendly error messages.
impl fmt::Display for HeaderError {
    // The fmt method defines how the error is formatted as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Match on the error variant to determine the message.
        match self {
            // Write "Invalid Magic 'VERA'" for InvalidMagic error.
            HeaderError::InvalidMagic => write!(f, "Invalid Magic 'VERA'"),
            // Write "Header CRC mismatch" for InvalidCrc error.
            HeaderError::InvalidCrc => write!(f, "Header CRC mismatch"),
            // Write "Unsupported Header Version" for UnsupportedVersion error.
            HeaderError::UnsupportedVersion => write!(f, "Unsupported Header Version"),
            // Write "Unsupported Min Program Version" for UnsupportedProgramVersion error.
            HeaderError::UnsupportedProgramVersion => write!(f, "Unsupported Min Program Version"),
            // Write "Invalid Sector Size" for InvalidSectorSize error.
            HeaderError::InvalidSectorSize => write!(f, "Invalid Sector Size"),
            // Write "Invalid Key Size" for InvalidKeySize error.
            HeaderError::InvalidKeySize => write!(f, "Invalid Key Size"),
        }
    }
}

// Define the VolumeHeader struct which represents the decrypted volume header.
// Derive Debug and Clone for utility.
// Derive Zeroize and ZeroizeOnDrop to ensure sensitive data (like keys) is wiped from memory.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VolumeHeader {
    // The version of the volume header.
    pub version: u16,
    // The minimum program version required to mount this volume.
    pub min_program_version: u16,
    // The CRC32 checksum of the header. Skipped for zeroization as it's not sensitive.
    #[zeroize(skip)]
    pub crc32: u32,
    // The timestamp when the volume was created.
    pub volume_creation_time: u64,
    // The timestamp when the header was created.
    pub header_creation_time: u64,
    // The size of the hidden volume, if any.
    pub hidden_volume_size: u64,
    // The size of the volume data area.
    pub volume_data_size: u64,
    // The starting offset of the encrypted area.
    pub encrypted_area_start: u64,
    // The length of the encrypted area.
    pub encrypted_area_length: u64,
    // Flags indicating various volume options.
    pub flags: u32,
    // The sector size of the volume.
    pub sector_size: u32,
    // The CRC32 checksum of the key area. Skipped for zeroization.
    #[zeroize(skip)]
    pub key_area_crc32: u32,
    // The master key data, fixed at 256 bytes (max key area size).
    pub master_key_data: [u8; 256], // Max key area size
}

// Implementation block for VolumeHeader methods.
impl VolumeHeader {
    // Function to deserialize a decrypted byte slice into a VolumeHeader struct.
    pub fn deserialize(decrypted: &[u8]) -> Result<Self, HeaderError> {
        // Check if the decrypted data is large enough to contain a valid header.
        if decrypted.len() < 448 {
            // Should be at least 448 bytes (512 bytes total - 64 bytes salt).
            // Return InvalidMagic error if too short.
            return Err(HeaderError::InvalidMagic); 
        }

        // Extract the first 4 bytes to check the magic signature.
        // Check Magic "VERA" or "TRUE"
        let magic = &decrypted[0..4];
        // Verify if the magic bytes match "VERA" or "TRUE".
        if magic != b"VERA" && magic != b"TRUE" {
            // Return InvalidMagic error if they don't match.
            return Err(HeaderError::InvalidMagic);
        }

        // Read the version (2 bytes) from offset 4 using BigEndian byte order.
        let version = BigEndian::read_u16(&decrypted[4..6]);
        // Verify that the version is at least 1.
        if version < 1 {
             // Return UnsupportedVersion error if version is less than 1.
             return Err(HeaderError::UnsupportedVersion);
        }

        // Check Header CRC (offset 252 - 64 = 188).
        // The CRC check is only mandatory for version 4 and above.
        // Only for version >= 4
        if version >= 4 {
            // Read the stored CRC32 (4 bytes) from offset 188.
            let header_crc_stored = BigEndian::read_u32(&decrypted[188..192]);
            // Calculate the CRC32 of the first 188 bytes of the decrypted header.
            let header_crc_calc = crc32fast::hash(&decrypted[0..188]);
            
            // Compare the stored CRC with the calculated CRC.
            if header_crc_stored != header_crc_calc {
                // Return InvalidCrc error if they don't match.
                return Err(HeaderError::InvalidCrc);
            }
        }
        
        // For older versions, we might rely on other checks or proceed.
        // But we still need to read the stored CRC for the struct.
        // Read the stored CRC32 again (or for the first time if version < 4).
        let header_crc_stored = BigEndian::read_u32(&decrypted[188..192]);

        // Read the minimum program version (2 bytes) from offset 6.
        let min_program_version = BigEndian::read_u16(&decrypted[6..8]);
        
        // Check Min Program Version (0x011a = 1.26).
        // If the required version is greater than 1.26, we don't support it.
        if min_program_version > 0x011a {
             // Return UnsupportedProgramVersion error.
             return Err(HeaderError::UnsupportedProgramVersion);
        }

        // Read the key area CRC32 (4 bytes) from offset 8.
        let key_area_crc32 = BigEndian::read_u32(&decrypted[8..12]);
        // Read the volume creation time (8 bytes) from offset 12.
        let volume_creation_time = BigEndian::read_u64(&decrypted[12..20]);
        // Read the header creation time (8 bytes) from offset 20.
        let header_creation_time = BigEndian::read_u64(&decrypted[20..28]);
        // Read the hidden volume size (8 bytes) from offset 28.
        let hidden_volume_size = BigEndian::read_u64(&decrypted[28..36]);
        // Read the volume data size (8 bytes) from offset 36.
        let volume_data_size = BigEndian::read_u64(&decrypted[36..44]);
        // Read the encrypted area start offset (8 bytes) from offset 44.
        let encrypted_area_start = BigEndian::read_u64(&decrypted[44..52]);
        // Read the encrypted area length (8 bytes) from offset 52.
        let encrypted_area_length = BigEndian::read_u64(&decrypted[52..60]);
        // Read the flags (4 bytes) from offset 60.
        let flags = BigEndian::read_u32(&decrypted[60..64]);
        // Read the sector size (4 bytes) from offset 64.
        let mut sector_size = BigEndian::read_u32(&decrypted[64..68]);

        // For versions older than 5, the sector size is fixed at 512 bytes.
        if version < 5 {
            sector_size = 512;
        }

        // VeraCrypt supports sector sizes: 512, 1024, 2048, 4096.
        // Must be multiple of 128 (XTS block size) which is implied by 512 alignment.
        // Validate that the sector size is within the valid range and a multiple of 512.
        if sector_size < 512 || sector_size > 4096 || sector_size % 512 != 0 {
            // Return InvalidSectorSize error if validation fails.
            return Err(HeaderError::InvalidSectorSize);
        }

        // Validate Key Area CRC
        // Key area starts at offset 192 (256 - 64) and is 256 bytes long.
        // In VeraCrypt:
        // if (VolumeKeyAreaCrc32 != Crc32::ProcessBuffer (header.GetRange (offset, DataKeyAreaMaxSize)))
        // offset is DataAreaKeyOffset which is 192 (relative to decrypted start).
        // DataKeyAreaMaxSize is 256.
        
        // Calculate the CRC32 of the key area (bytes 192 to 448).
        let key_area_crc_calc = crc32fast::hash(&decrypted[192..448]);
        // Compare the stored key area CRC with the calculated one.
        if key_area_crc32 != key_area_crc_calc {
             // This is not strictly a fatal error for *mounting* if we trust the header CRC,
             // but it indicates corruption of the master keys.
             // VeraCrypt returns false here, so we treat it as an error.
             return Err(HeaderError::InvalidCrc);
        }

        // Initialize a 256-byte array for the master key data.
        let mut master_key_data = [0u8; 256];
        // Copy the key area data from the decrypted buffer into the array.
        master_key_data.copy_from_slice(&decrypted[192..448]);

        // Return the successfully constructed VolumeHeader struct.
        Ok(VolumeHeader {
            version,
            min_program_version,
            crc32: header_crc_stored,
            volume_creation_time,
            header_creation_time,
            hidden_volume_size,
            volume_data_size,
            encrypted_area_start,
            encrypted_area_length,
            flags,
            sector_size,
            key_area_crc32,
            master_key_data,
        })
    }

    // Function to check if the XTS key is vulnerable.
    // XTS keys are vulnerable if the two halves are identical.
    pub fn is_key_vulnerable(&self, key_size: usize) -> bool {
        // Check if the XTS key is vulnerable by comparing the two parts of the key
        // XtsKeyVulnerable = (memcmp (options.DataKey.Get() + options.EA->GetKeySize(), options.DataKey.Get(), options.EA->GetKeySize()) == 0);
        // master_key_data contains the concatenated keys.
        // We need to check if the first half equals the second half of the *primary* key?
        // No, XTS key is (Key1, Key2). Vulnerable if Key1 == Key2.
        // The `key_size` passed here should be the size of ONE key (e.g. 32 for AES-256).
        // The XTS key is 2 * key_size.
        
        // Ensure that the master key data is large enough to contain the full XTS key (2 * key_size).
        if key_size * 2 > self.master_key_data.len() {
            return true; // Should not happen if key_size is correct, but treat as vulnerable/error.
        }

        // Extract the first half of the XTS key (Key1).
        let key1 = &self.master_key_data[0..key_size];
        // Extract the second half of the XTS key (Key2).
        let key2 = &self.master_key_data[key_size..key_size*2];

        // Return true if Key1 is identical to Key2, indicating a vulnerability.
        key1 == key2
    }
}
