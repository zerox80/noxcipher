
#[cfg(test)]
mod tests {
    use crate::volume::{create_volume, change_password, create_context, CipherType, PrfAlgorithm, FilesystemType, close_context};
    use std::fs;
    use std::path::Path;
    use std::io::{Write, Seek, SeekFrom};

    const TEST_VOL: &str = "test_vol_inner.hc";
    const TEST_VOL_TWOFISH: &str = "test_vol_twofish.hc";
    const TEST_VOL_AES_TWOFISH: &str = "test_vol_aes_twofish.hc";
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

    fn cleanup_path(path: &str) {
        if Path::new(path).exists() {
            let _ = fs::remove_file(path);
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
            None,
            FilesystemType::Fat32,
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

    #[test]
    fn test_twofish_volume_mount_flow() {
        cleanup_path(TEST_VOL_TWOFISH);

        let size = 1024 * 1024;
        let password = b"twofish-pass";
        let salt = [7u8; 64];
        let mut master_key = [0u8; 64];
        for (index, byte) in master_key.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(3).wrapping_add(1);
        }

        create_volume(
            TEST_VOL_TWOFISH,
            password,
            0,
            size,
            &salt,
            &master_key,
            CipherType::Twofish,
            PrfAlgorithm::Sha512,
            None,
            FilesystemType::Fat32,
        ).expect("Failed to create Twofish volume");

        let file_content = fs::read(TEST_VOL_TWOFISH).expect("Failed to read Twofish volume");
        let handle = create_context(
            password,
            &file_content[..131072],
            0,
            0,
            None,
            0,
            None,
            0,
            size,
            None,
        ).expect("Failed to mount standard Twofish volume");
        close_context(handle);

        cleanup_path(TEST_VOL_TWOFISH);
    }

    #[test]
    fn test_aes_twofish_change_password_flow() {
        cleanup_path(TEST_VOL_AES_TWOFISH);

        let size = 2 * 1024 * 1024;
        let old_password = b"cascade-old-pass";
        let new_password = b"cascade-new-pass";
        let old_salt = [5u8; 64];
        let new_salt = [6u8; 64];
        let mut master_key = [0u8; 128];
        for (index, byte) in master_key.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(5).wrapping_add(1);
        }

        create_volume(
            TEST_VOL_AES_TWOFISH,
            old_password,
            0,
            size,
            &old_salt,
            &master_key,
            CipherType::AesTwofish,
            PrfAlgorithm::Sha512,
            None,
            FilesystemType::Fat32,
        ).expect("Failed to create AES-Twofish volume");

        change_password(
            TEST_VOL_AES_TWOFISH,
            old_password,
            0,
            new_password,
            0,
            &new_salt,
            Some(PrfAlgorithm::Sha512),
        ).expect("Failed to change AES-Twofish password");

        let file_content = fs::read(TEST_VOL_AES_TWOFISH)
            .expect("Failed to read AES-Twofish volume after password change");
        let handle = create_context(
            new_password,
            &file_content[..131072],
            0,
            0,
            None,
            0,
            None,
            0,
            size,
            None,
        ).expect("Failed to mount AES-Twofish volume with new password");
        close_context(handle);

        let mut file = fs::OpenOptions::new().write(true).open(TEST_VOL_AES_TWOFISH).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&[0u8; 512]).unwrap();
        drop(file);

        let file_content = fs::read(TEST_VOL_AES_TWOFISH)
            .expect("Failed to reread AES-Twofish volume for backup header test");
        let backup_offset = size - 131072;
        let backup_slice = &file_content[backup_offset as usize..(backup_offset + 512) as usize];

        let handle = create_context(
            new_password,
            &[0u8; 512],
            0,
            0,
            None,
            0,
            None,
            0,
            size,
            Some(backup_slice),
        ).expect("Failed to mount AES-Twofish backup header with new password");
        close_context(handle);

        cleanup_path(TEST_VOL_AES_TWOFISH);
    }
}
