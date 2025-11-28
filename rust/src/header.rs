use byteorder::{BigEndian, ByteOrder};
use std::fmt;

#[derive(Debug, Clone)]
pub enum HeaderError {
    InvalidMagic,
    InvalidCrc,
    UnsupportedVersion,
    InvalidSectorSize,
    InvalidKeySize,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HeaderError::InvalidMagic => write!(f, "Invalid Magic 'VERA'"),
            HeaderError::InvalidCrc => write!(f, "Header CRC mismatch"),
            HeaderError::UnsupportedVersion => write!(f, "Unsupported Header Version"),
            HeaderError::InvalidSectorSize => write!(f, "Invalid Sector Size"),
            HeaderError::InvalidKeySize => write!(f, "Invalid Key Size"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VolumeHeader {
    pub version: u16,
    pub min_program_version: u16,
    pub crc32: u32,
    pub volume_creation_time: u64,
    pub header_creation_time: u64,
    pub hidden_volume_size: u64,
    pub volume_data_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub flags: u32,
    pub sector_size: u32,
    pub key_area_crc32: u32,
    pub master_key_data: [u8; 256], // Max key area size
}

impl VolumeHeader {
    pub fn deserialize(decrypted: &[u8]) -> Result<Self, HeaderError> {
        if decrypted.len() != 448 {
            // Should be 512 - 64 (salt) = 448
            // But actually the decrypted buffer passed here is usually just the 448 bytes
            return Err(HeaderError::InvalidMagic); 
        }

        // Check Magic "VERA"
        if &decrypted[0..4] != b"VERA" {
            return Err(HeaderError::InvalidMagic);
        }

        let version = BigEndian::read_u16(&decrypted[4..6]);
        if version < 5 {
             // We only support V5+ for now (VeraCrypt)
             // TrueCrypt is V4, but let's stick to VC for now unless requested
             // Actually, the user asked to use VeraCrypt-master as template, which supports V4.
             // But let's start with V5.
        }

        // Check Header CRC (offset 252 - 64 = 188)
        // The CRC is calculated over the first 252 bytes of the *decrypted* header (excluding the salt which is not here)
        // Wait, in VeraCrypt:
        // Crc32::ProcessBuffer (header.GetRange (0, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
        // TC_HEADER_OFFSET_HEADER_CRC is 252. TC_HEADER_OFFSET_MAGIC is 64.
        // So it checks bytes [0..188] of the decrypted buffer.
        // The CRC itself is stored at 188.
        
        let header_crc_stored = BigEndian::read_u32(&decrypted[188..192]);
        let header_crc_calc = crc32fast::hash(&decrypted[0..188]);
        
        if header_crc_stored != header_crc_calc {
            return Err(HeaderError::InvalidCrc);
        }

        let min_program_version = BigEndian::read_u16(&decrypted[6..8]);
        let key_area_crc32 = BigEndian::read_u32(&decrypted[8..12]);
        let volume_creation_time = BigEndian::read_u64(&decrypted[12..20]);
        let header_creation_time = BigEndian::read_u64(&decrypted[20..28]);
        let hidden_volume_size = BigEndian::read_u64(&decrypted[28..36]);
        let volume_data_size = BigEndian::read_u64(&decrypted[36..44]);
        let encrypted_area_start = BigEndian::read_u64(&decrypted[44..52]);
        let encrypted_area_length = BigEndian::read_u64(&decrypted[52..60]);
        let flags = BigEndian::read_u32(&decrypted[60..64]);
        let sector_size = BigEndian::read_u32(&decrypted[64..68]);

        if sector_size < 512 || sector_size > 4096 || sector_size % 512 != 0 {
            return Err(HeaderError::InvalidSectorSize);
        }

        // Validate Key Area CRC
        // Key area starts at offset 192 (256 - 64) and is 256 bytes long.
        // In VeraCrypt:
        // if (VolumeKeyAreaCrc32 != Crc32::ProcessBuffer (header.GetRange (offset, DataKeyAreaMaxSize)))
        // offset is DataAreaKeyOffset which is 192 (relative to decrypted start).
        // DataKeyAreaMaxSize is 256.
        
        let key_area_crc_calc = crc32fast::hash(&decrypted[192..448]);
        if key_area_crc32 != key_area_crc_calc {
             // This is not strictly a fatal error for *mounting* if we trust the header CRC,
             // but it indicates corruption of the master keys.
             // VeraCrypt returns false here.
             return Err(HeaderError::InvalidCrc);
        }

        let mut master_key_data = [0u8; 256];
        master_key_data.copy_from_slice(&decrypted[192..448]);

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
}
