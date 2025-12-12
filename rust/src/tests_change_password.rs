
#[cfg(test)]
mod tests {
    use crate::volume::{create_volume, change_password, create_context, CipherType, PrfAlgorithm, close_context};
    use std::fs;
    use std::path::Path;
    use std::io::{Read, Write, Seek, SeekFrom};

    const TEST_VOL: &str = "test_vol_inner.hc";
    const PASS_OLD: &[u8] = b"password123";
    const PASS_NEW: &[u8] = b"newsecret456";
    const SALT_OLD: [u8; 64] = [1u8; 64];
    const SALT_NEW: [u8; 64] = [2u8; 64];
    const MASTER_KEY: [u8; 64] = [3u8; 64]; 

    fn cleanup() {
        if Path::new(TEST_VOL).exists() {
            let _ = fs::remove_file(TEST_VOL);
        }
    }

    #[test]
    fn test_change_password_flow() {
        cleanup();
        
        let pim = 0;
        let size = 1024 * 1024; // 1MB
        
        // 1. Create Volume
        println!("Creating volume...");
        create_volume(
            TEST_VOL, 
            PASS_OLD, 
            pim, 
            size, 
            &SALT_OLD, 
            &MASTER_KEY, 
            CipherType::Aes, 
            PrfAlgorithm::Sha512,
            None
        ).expect("Failed to create volume");

        // 2. Change Password
        println!("Changing password...");
        change_password(
            TEST_VOL,
            PASS_OLD,
            pim,
            PASS_NEW,
            pim,
            &SALT_NEW,
            Some(PrfAlgorithm::Sha512)
        ).expect("Failed to change password");

        // 3. Verify New Password Works (Primary)
        println!("Verifying new password works (Primary)...");
        let file_content_new = fs::read(TEST_VOL).expect("Failed to read updated volume");
        let header_slice_new = &file_content_new[0..131072];
        
        let handle_new = create_context(
            PASS_NEW,
            header_slice_new,
            pim,
            0,
            None,
            0,
            None,
            0,
            size,
            None
        ).expect("Failed to open with new password");
        close_context(handle_new);

        // 4. Verify Backup Header Updated
        println!("Verifying Backup Header works with new password...");
        // Corrupt primary header
        let mut file = fs::OpenOptions::new().write(true).open(TEST_VOL).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[0u8; 512]).unwrap(); // Zero out primary header
        drop(file);

        let file_content_backup = fs::read(TEST_VOL).unwrap();
        // Backup header is at end - 128KB.
        // But create_context logic for backup header usually expects us to pass the backup buffer OR rely on internal fallback.
        // Let's pass the backup buffer explicitly.
        let backup_offset = size - 131072;
        let backup_slice = &file_content_backup[backup_offset as usize..(backup_offset + 512) as usize];

        let handle_backup = create_context(
            PASS_NEW,
            &[0u8; 512], // Invalid primary
            pim,
            0,
            None,
            0,
            None,
            0,
            size,
            Some(backup_slice)
        ).expect("Failed to open with backup header and new password");
        close_context(handle_backup);

        cleanup();
    }
}
