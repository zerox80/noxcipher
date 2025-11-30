// Import the ByteOrder trait and BigEndian struct from the byteorder crate.
// These are used to handle big-endian byte order conversions, which is common in cryptographic headers.
use byteorder::{BigEndian, ByteOrder};
// Import the fmt module from the standard library.
// This is used for implementing formatting traits like Display and Debug.
use std::fmt;
// Import Zeroize and ZeroizeOnDrop traits from the zeroize crate.
// These are used to securely clear memory containing sensitive data (like keys) when it goes out of scope.
use zeroize::{Zeroize, ZeroizeOnDrop};

// Define an enumeration named HeaderError to represent possible errors during header parsing.
// Derive Debug and Clone traits for easy printing and copying of error values.
#[derive(Debug, Clone)]
pub enum HeaderError {
    // Error variant indicating that the magic bytes ("VERA" or "TRUE") were not found in the header.
    InvalidMagic,
    // Error variant indicating that the calculated CRC32 checksum does not match the stored checksum.
    InvalidCrc,
    // Error variant indicating that the header version is not supported by this implementation.
    UnsupportedVersion,
    // Error variant indicating that the minimum program version required by the volume is higher than supported.
    UnsupportedProgramVersion,
    // Error variant indicating that the sector size specified in the header is invalid.
    InvalidSectorSize,
    // Error variant indicating that the key size is invalid.
    InvalidKeySize,
}

// Implement the fmt::Display trait for HeaderError to provide user-friendly error messages.
impl fmt::Display for HeaderError {
    // The fmt method defines how the error is formatted as a string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Match on the error variant (self) to determine the message string.
        match self {
            // For InvalidMagic, write "Invalid Magic 'VERA'" to the formatter.
            HeaderError::InvalidMagic => write!(f, "Invalid Magic 'VERA'"),
            // For InvalidCrc, write "Header CRC mismatch" to the formatter.
            HeaderError::InvalidCrc => write!(f, "Header CRC mismatch"),
            // For UnsupportedVersion, write "Unsupported Header Version" to the formatter.
            HeaderError::UnsupportedVersion => write!(f, "Unsupported Header Version"),
            // For UnsupportedProgramVersion, write "Unsupported Min Program Version" to the formatter.
            HeaderError::UnsupportedProgramVersion => write!(f, "Unsupported Min Program Version"),
            // For InvalidSectorSize, write "Invalid Sector Size" to the formatter.
            HeaderError::InvalidSectorSize => write!(f, "Invalid Sector Size"),
            // For InvalidKeySize, write "Invalid Key Size" to the formatter.
            HeaderError::InvalidKeySize => write!(f, "Invalid Key Size"),
        }
    }
}

// Define the VolumeHeader struct which represents the decrypted volume header.
// Derive Debug and Clone for utility purposes.
// Derive Zeroize and ZeroizeOnDrop to ensure sensitive data is wiped from memory when the struct is dropped.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VolumeHeader {
    // The version of the volume header (2 bytes).
    pub version: u16,
    // The minimum program version required to mount this volume (2 bytes).
    pub min_program_version: u16,
    // The CRC32 checksum of the header (4 bytes).
    // This field is skipped for zeroization as it does not contain sensitive information.
    #[zeroize(skip)]
    pub crc32: u32,
    // The timestamp when the volume was created (8 bytes).
    pub volume_creation_time: u64,
    // The timestamp when the header was created (8 bytes).
    pub header_creation_time: u64,
    // The size of the hidden volume, if any (8 bytes).
    pub hidden_volume_size: u64,
    // The size of the volume data area (8 bytes).
    pub volume_data_size: u64,
    // The starting offset of the encrypted area (8 bytes).
    pub encrypted_area_start: u64,
    // The length of the encrypted area (8 bytes).
    pub encrypted_area_length: u64,
    // Flags indicating various volume options (4 bytes).
    pub flags: u32,
    // The sector size of the volume (4 bytes).
    pub sector_size: u32,
    // The CRC32 checksum of the key area (4 bytes).
    // This field is skipped for zeroization.
    #[zeroize(skip)]
    pub key_area_crc32: u32,
    // The master key data, fixed at 256 bytes.
    // This contains the concatenated master keys for the volume.
    pub master_key_data: [u8; 256], // Max key area size
}

// Implementation block for VolumeHeader methods.
impl VolumeHeader {
    // Function to deserialize a decrypted byte slice into a VolumeHeader struct.
    // Returns a Result containing the VolumeHeader or a HeaderError.
    pub fn deserialize(decrypted: &[u8]) -> Result<Self, HeaderError> {
        // Check if the decrypted data is large enough to contain a valid header.
        // A valid header must be at least 448 bytes (512 bytes total - 64 bytes salt).
        if decrypted.len() < 448 {
            // If the data is too short, return an InvalidMagic error.
            return Err(HeaderError::InvalidMagic); 
        }

        // Extract the first 4 bytes to check the magic signature.
        let magic = &decrypted[0..4];
        // Verify if the magic bytes match "VERA" (VeraCrypt) or "TRUE" (TrueCrypt).
        if magic != b"VERA" && magic != b"TRUE" {
            // If the magic bytes do not match, return an InvalidMagic error.
            return Err(HeaderError::InvalidMagic);
        }

        // Read the version (2 bytes) from offset 4 using BigEndian byte order.
        let version = BigEndian::read_u16(&decrypted[4..6]);
        // Verify that the version is at least 1.
        if version < 1 {
             // If the version is less than 1, return an UnsupportedVersion error.
             return Err(HeaderError::UnsupportedVersion);
        }

        // Check the Header CRC. The CRC check is only mandatory for version 4 and above.
        // The CRC is stored at offset 188 (relative to the decrypted block start).
        if version >= 4 {
            // Read the stored CRC32 (4 bytes) from offset 188.
            let header_crc_stored = BigEndian::read_u32(&decrypted[188..192]);
            // Calculate the CRC32 of the first 188 bytes of the decrypted header.
            // This covers the header fields up to the CRC itself.
            let header_crc_calc = crc32fast::hash(&decrypted[0..188]);
            
            // Compare the stored CRC with the calculated CRC.
            if header_crc_stored != header_crc_calc {
                // If they don't match, return an InvalidCrc error.
                return Err(HeaderError::InvalidCrc);
            }
        }
        
        // Read the stored CRC32 again (or for the first time if version < 4).
        // We need this value to populate the struct field.
        let header_crc_stored = BigEndian::read_u32(&decrypted[188..192]);

        // Read the minimum program version (2 bytes) from offset 6.
        let min_program_version = BigEndian::read_u16(&decrypted[6..8]);
        
        // Check if the minimum program version is supported.
        // 0x011a corresponds to version 1.26.
        if min_program_version > 0x011a {
             // If the required version is greater than supported, return UnsupportedProgramVersion error.
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
            // Force sector size to 512.
            sector_size = 512;
        }

        // Validate that the sector size is within the valid range (512 to 4096) and is a multiple of 512.
        // VeraCrypt supports sector sizes: 512, 1024, 2048, 4096.
        if sector_size < 512 || sector_size > 4096 || sector_size % 512 != 0 {
            // If validation fails, return an InvalidSectorSize error.
            return Err(HeaderError::InvalidSectorSize);
        }

        // Validate the Key Area CRC.
        // The key area starts at offset 192 (relative to decrypted start) and is 256 bytes long.
        // Calculate the CRC32 of the key area (bytes 192 to 448).
        let key_area_crc_calc = crc32fast::hash(&decrypted[192..448]);
        // Compare the stored key area CRC with the calculated one.
        if key_area_crc32 != key_area_crc_calc {
             // If they don't match, return an InvalidCrc error.
             // This indicates potential corruption of the master keys.
             return Err(HeaderError::InvalidCrc);
        }

        // Initialize a 256-byte array for the master key data, filled with zeros.
        let mut master_key_data = [0u8; 256];
        // Copy the key area data from the decrypted buffer (offset 192 to 448) into the array.
        master_key_data.copy_from_slice(&decrypted[192..448]);

        // Return the successfully constructed VolumeHeader struct wrapped in Ok.
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
    // XTS keys are considered vulnerable if the two halves (Key1 and Key2) are identical.
    pub fn is_key_vulnerable(&self, key_size: usize) -> bool {
        // Ensure that the master key data is large enough to contain the full XTS key (2 * key_size).
        if key_size * 2 > self.master_key_data.len() {
            // If the key size is invalid for the buffer, return true (treat as vulnerable/error).
            return true; 
        }

        // Extract the first half of the XTS key (Key1) as a slice.
        let key1 = &self.master_key_data[0..key_size];
        // Extract the second half of the XTS key (Key2) as a slice.
        let key2 = &self.master_key_data[key_size..key_size*2];

        // Return true if Key1 is identical to Key2, indicating a vulnerability.
        // Otherwise, return false.
        key1 == key2
    }
}
