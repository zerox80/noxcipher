use super::*;
use std::io::{Write, Read, Seek, SeekFrom};
use std::fs::File;
use tempfile::NamedTempFile;
use tempfile::NamedTempFile;

#[test]
fn test_change_password_flow() {
    let mut temp = NamedTempFile::new().unwrap();
    let path = temp.path().to_str().unwrap().to_string();
    let size = 1024 * 1024 * 2; // 2MB
    
    let password = b"password123";
    let pim = 0;
    let salt = [0u8; 64]; // Zero salt for test
    let master_key = [1u8; 64]; // Non-zero master key
    
    // 1. Create Volume
    volume::create_volume_file(
        &path,
        password,
        pim,
        size,
        &salt,
        &master_key,
        CipherType::Aes,
        PrfAlgorithm::Sha512,
        None,
    ).expect("Failed to create volume");
    
    // 2. Verify Mount
    let mut file = std::fs::File::open(&path).unwrap();
    let mut header_buf = [0u8; 512];
    file.read_exact(&mut header_buf).unwrap();
    
    // We cannot access private try_header_at_offset easily unless exposed or via public API.
    // Instead we can use change_password which exercises the decryption logic.
    
    let new_password = b"newpassword456";
    let new_pim = 0;
    let new_salt = [2u8; 64]; 
    
    // 3. Change Password
    volume::change_password(
        &path,
        password,
        pim,
        new_password,
        new_pim,
        &new_salt,
        None // Keep PRF
    ).expect("Failed to change password");
    
    // 4. Verify Mount with OLD password (Should Fail)
    // We can simulate this by trying to change password again from OLD to NEW2.
    // It should fail to decrypt header.
    let res = volume::change_password(
        &path,
        password,
        pim,
        b"irrelevant",
        0,
        &new_salt,
        None
    );
    assert!(res.is_err(), "Should fail with old password");
    
    // 5. Verify Mount with NEW password (Should Succeed)
    // Change back to original.
    volume::change_password(
        &path,
        new_password,
        new_pim,
        password,
        pim,
        &salt,
        None
    ).expect("Failed to change password back with new credentials");
    
}
