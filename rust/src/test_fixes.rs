
#[cfg(test)]
mod tests {
    use crate::header::{VolumeHeader, HeaderError};
    use crate::volume::{self, VolumeError, Volume, CipherType, PrfAlgorithm};
    use crate::crypto::SupportedCipher;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_header_sector_size_validation() {
        // Test Version 4 (Must be 512)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut header = VolumeHeader::new(
            4, 0x0100, now, now, 0, 10000, 131072, 10000, 0, 512, [0u8; 256], [0u8; 64], 0
        ).unwrap();
        assert_eq!(header.sector_size, 512);

        // Test Version 5 (Can be 4096)
        let header_v5 = VolumeHeader::new(
            5, 0x0100, now, now, 0, 10000, 131072, 10000, 0, 4096, [0u8; 256], [0u8; 64], 0
        ).unwrap();
        assert_eq!(header_v5.sector_size, 4096);
    }
    
    #[test]
    fn test_is_xts_key_vulnerable_logic() {
         let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
         let mut mk = [0u8; 256];
         // Case 1: Keys are different
         for i in 0..256 { mk[i] = i as u8; }
         
         let header = VolumeHeader::new(
             5, 0x0100, now, now, 0, 10000, 131072, 10000, 0, 512, mk, [0u8; 64], 0
         ).unwrap();
         
         // Not vulnerable
         assert!(!header.is_xts_key_vulnerable(0, 32, 32));
         
         // Case 2: Keys are same
         let mut mk_same = [0u8; 256];
         // Set 0..32 to As
         for i in 0..32 { mk_same[i] = 0xAA; }
         // Set 32..64 to As
         for i in 32..64 { mk_same[i] = 0xAA; }
         
         let header_same = VolumeHeader::new(
             5, 0x0100, now, now, 0, 10000, 131072, 10000, 0, 512, mk_same, [0u8; 64], 0
         ).unwrap();
         
         assert!(header_same.is_xts_key_vulnerable(0, 32, 32));
    }

    #[test]
    fn test_create_volume_buffer_size() {
        // Just ensure it doesn't panic
        let mut path = std::env::temp_dir();
        path.push("test_create_vol.hc");
        let _ = std::fs::remove_file(path);
        let password = b"password";
        let pim = 0;
        let size = 1024 * 1024; // 1MB
        
        let salt = [1u8; 64];
        let master_key = [2u8; 64];
        let res = volume::create_volume(
            path, 
            password, 
            pim, 
            size,
            &salt,
            &master_key,
            CipherType::Aes,
            PrfAlgorithm::Sha512,
            None
        );
        assert!(res.is_ok());
        
        // Cleanup
        let _ = std::fs::remove_file(path);
    }

    // test_encrypted_writer_partial_flush moved to volume.rs due to visibility
}
