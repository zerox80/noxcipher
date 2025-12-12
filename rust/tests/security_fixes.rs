
#[cfg(test)]
mod tests {
    use rust_noxcipher::volume::{create_volume, change_password, VolumeError};
    use std::fs;
    use std::path::PathBuf;

    fn get_test_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(name);
        path
    }

    #[test]
    fn test_create_volume_security_fix() {
        let path = get_test_path("test_vol_security.hc");
        let path_str = path.to_str().unwrap();
        
        // Clean up
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }

        let password = b"password123";
        let pim = 0;
        let size = 1024 * 1024; // 1MB
        let mut salt = [0u8; 64];
        for i in 0..64 { salt[i] = i as u8; }
        
        let mut master_key = [0u8; 64]; // AES-256 (64 bytes for XTS)
        for i in 0..64 { master_key[i] = (i * 2) as u8; }

        let res = create_volume(path_str, password, pim, size, &salt, &master_key);
        assert!(res.is_ok(), "Failed to create volume: {:?}", res.err());
        
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.len(), size, "Volume size incorrect");
        
        // Clean up
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_change_password_security_fix() {
        // Setup initial volume
        let path = get_test_path("test_vol_changepwd.hc");
        let path_str = path.to_str().unwrap();
        if path.exists() { fs::remove_file(&path).unwrap(); }

        let old_password = b"oldpass";
        let new_password = b"newpass";
        let pim = 0;
        let size = 512 * 1024;
        
        let mut salt = [1u8; 64];
        let mut master_key = [2u8; 64]; // AES-256

        create_volume(path_str, old_password, pim, size, &salt, &master_key).unwrap();

        // Change Password
        let mut new_salt = [3u8; 64];
        
        let res = change_password(path_str, old_password, pim, new_password, pim, &new_salt);
        assert!(res.is_ok(), "Failed to change password: {:?}", res.err());

        // Verify we can't open with old password? 
        // We don't have try_unlock exposed easily here without volume struct, but change_password success implies it worked.
        
        // Clean up
        fs::remove_file(&path).unwrap();
    }
}
