use byteorder::{BigEndian, ByteOrder};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone)]
pub enum HeaderError {
    InvalidMagic,
    InvalidCrc,
    UnsupportedVersion,
    UnsupportedProgramVersion,
    InvalidSectorSize,
    InvalidKeySize,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HeaderError::InvalidMagic => write!(f, "Invalid Magic 'VERA'"),
            HeaderError::InvalidCrc => write!(f, "Header CRC mismatch"),
            HeaderError::UnsupportedVersion => write!(f, "Unsupported Header Version"),
            HeaderError::UnsupportedProgramVersion => write!(f, "Unsupported Min Program Version"),
            HeaderError::InvalidSectorSize => write!(f, "Invalid Sector Size"),
            HeaderError::InvalidKeySize => write!(f, "Invalid Key Size"),
        }
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct VolumeHeader {
    pub version: u16,
    pub min_program_version: u16,
    #[zeroize(skip)]
    pub crc32: u32,
    pub volume_creation_time: u64,
    pub header_creation_time: u64,
    pub hidden_volume_size: u64,
    pub volume_data_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub flags: u32,
    pub sector_size: u32,
    #[zeroize(skip)]
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
        if version < 1 {
             return Err(HeaderError::UnsupportedVersion);
        }

        // Check Header CRC (offset 252 - 64 = 188)
        let header_crc_stored = BigEndian::read_u32(&decrypted[188..192]);
        let header_crc_calc = crc32fast::hash(&decrypted[0..188]);
        
        if header_crc_stored != header_crc_calc {
            return Err(HeaderError::InvalidCrc);
        }

        let min_program_version = BigEndian::read_u16(&decrypted[6..8]);
        
        // Check Min Program Version (0x011a = 1.26)
        if min_program_version > 0x011a {
             return Err(HeaderError::UnsupportedProgramVersion);
        }

        let key_area_crc32 = BigEndian::read_u32(&decrypted[8..12]);
        let volume_creation_time = BigEndian::read_u64(&decrypted[12..20]);
        let header_creation_time = BigEndian::read_u64(&decrypted[20..28]);
        let hidden_volume_size = BigEndian::read_u64(&decrypted[28..36]);
        let volume_data_size = BigEndian::read_u64(&decrypted[36..44]);
        let encrypted_area_start = BigEndian::read_u64(&decrypted[44..52]);
        let encrypted_area_length = BigEndian::read_u64(&decrypted[52..60]);
        let flags = BigEndian::read_u32(&decrypted[60..64]);
        let mut sector_size = BigEndian::read_u32(&decrypted[64..68]);

        if version < 5 {
            sector_size = 512;
        }

        // VeraCrypt supports sector sizes: 512, 1024, 2048, 4096.
        // Must be multiple of 128 (XTS block size) which is implied by 512 alignment.
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

    pub fn is_key_vulnerable(&self, key_size: usize) -> bool {
        // Check if the XTS key is vulnerable by comparing the two parts of the key
        // XtsKeyVulnerable = (memcmp (options.DataKey.Get() + options.EA->GetKeySize(), options.DataKey.Get(), options.EA->GetKeySize()) == 0);
        // master_key_data contains the concatenated keys.
        // We need to check if the first half equals the second half of the *primary* key?
        // No, XTS key is (Key1, Key2). Vulnerable if Key1 == Key2.
        // The `key_size` passed here should be the size of ONE key (e.g. 32 for AES-256).
        // The XTS key is 2 * key_size.
        
        if key_size * 2 > self.master_key_data.len() {
            return true; // Should not happen if key_size is correct
        }

        let key1 = &self.master_key_data[0..key_size];
        let key2 = &self.master_key_data[key_size..key_size*2];

        key1 == key2
    }
}
