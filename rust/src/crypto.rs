// Import the Aes256 struct from the aes crate for AES encryption.
use aes::Aes256;
// Import the Xts128 struct from the xts-mode crate for XTS mode operations.
use xts_mode::Xts128;
// Import the Serpent struct from the serpent crate for Serpent encryption.
use serpent::Serpent;
// Import the Twofish struct from the twofish crate for Twofish encryption.
use twofish::Twofish;
// Import various traits from the cipher crate that are needed for implementing block ciphers.
// KeyInit: for initializing with a key.
// BlockCipher: marker trait for block ciphers.
// BlockEncrypt/BlockDecrypt: for encryption and decryption operations.
// Key, Block: type aliases for key and block byte arrays.
// KeySizeUser, BlockSizeUser: for defining key and block sizes.
// ParBlocksSizeUser: for defining parallel block sizes.
// BlockBackend: for low-level block processing.
use cipher::{KeyInit, BlockCipher, BlockEncrypt, BlockDecrypt, Key, Block, KeySizeUser, BlockSizeUser, ParBlocksSizeUser, BlockBackend};
// Import constant types U32, U16, U1 from the cipher::consts module to specify sizes at compile time.
use cipher::consts::{U32, U16, U1};
// Import the InOut type from cipher::inout to handle input/output buffers for block processing.
use cipher::inout::InOut;
// Import traits from the kuznyechik crate to adapt the Kuznyechik cipher.
// NewBlockCipher is an older trait name, aliased here if needed, and BlockCipher as OldBlockCipher.
use kuznyechik::block_cipher::{NewBlockCipher, BlockCipher as OldBlockCipher};
// Import Zeroize and ZeroizeOnDrop traits to securely clear memory containing sensitive key material.
use zeroize::{Zeroize, ZeroizeOnDrop};

// Wrapper structs for ciphers that don't implement the exact traits we need or need adaptation to the latest RustCrypto traits.

// Define a wrapper struct for the Kuznyechik cipher.
// It wraps the inner kuznyechik::Kuznyechik struct.
// Derive Zeroize and ZeroizeOnDrop to ensure the inner cipher state is wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct KuznyechikWrapper(#[zeroize(skip)] kuznyechik::Kuznyechik);

// Implement the KeySizeUser trait for KuznyechikWrapper.
// This defines the key size for the cipher.
impl KeySizeUser for KuznyechikWrapper {
    // Set the key size to 32 bytes (256 bits), represented by U32.
    type KeySize = U32;
}

// Implement the KeyInit trait for KuznyechikWrapper.
// This allows initializing the cipher with a key.
impl KeyInit for KuznyechikWrapper {
    // Define the new method to create a new instance.
    fn new(key: &Key<Self>) -> Self {
        // Initialize the inner Kuznyechik cipher with the provided key and wrap it.
        KuznyechikWrapper(kuznyechik::Kuznyechik::new(key))
    }
}

// Implement the BlockSizeUser trait for KuznyechikWrapper.
// This defines the block size for the cipher.
impl BlockSizeUser for KuznyechikWrapper {
    // Set the block size to 16 bytes (128 bits), represented by U16.
    type BlockSize = U16;
}

// Implement the BlockCipher marker trait for KuznyechikWrapper.
// This indicates that the struct is a block cipher.
impl BlockCipher for KuznyechikWrapper {}

// Define a backend struct for Kuznyechik encryption.
// It holds a reference to the inner Kuznyechik instance.
struct KuznyechikEncryptBackend<'a>(&'a kuznyechik::Kuznyechik);

// Implement BlockSizeUser for the encryption backend.
impl<'a> BlockSizeUser for KuznyechikEncryptBackend<'a> {
    // The block size matches the cipher's block size (16 bytes).
    type BlockSize = U16;
}
// Implement ParBlocksSizeUser for the encryption backend.
// This defines how many blocks can be processed in parallel.
impl<'a> ParBlocksSizeUser for KuznyechikEncryptBackend<'a> {
    // Set to 1 block at a time (U1).
    type ParBlocksSize = U1;
}
// Implement the BlockBackend trait for the encryption backend.
// This defines the actual block processing logic.
impl<'a> BlockBackend for KuznyechikEncryptBackend<'a> {
    // Define the proc_block method to process a single block.
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        // Call the encrypt_block method on the inner cipher instance with the output block.
        self.0.encrypt_block(block.get_out());
    }
}

// Implement the BlockEncrypt trait for KuznyechikWrapper.
// This provides the high-level encryption interface.
impl BlockEncrypt for KuznyechikWrapper {
    // Define the encrypt_with_backend method.
    fn encrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        // Create an instance of the encryption backend with a reference to the inner cipher.
        let mut backend = KuznyechikEncryptBackend(&self.0);
        // Call the closure with the backend to perform the operation.
        f.call(&mut backend);
    }
}

// Define a backend struct for Kuznyechik decryption.
// It holds a reference to the inner Kuznyechik instance.
struct KuznyechikDecryptBackend<'a>(&'a kuznyechik::Kuznyechik);

// Implement BlockSizeUser for the decryption backend.
impl<'a> BlockSizeUser for KuznyechikDecryptBackend<'a> {
    // The block size is 16 bytes (U16).
    type BlockSize = U16;
}
// Implement ParBlocksSizeUser for the decryption backend.
impl<'a> ParBlocksSizeUser for KuznyechikDecryptBackend<'a> {
    // Set to 1 block at a time (U1).
    type ParBlocksSize = U1;
}
// Implement the BlockBackend trait for the decryption backend.
impl<'a> BlockBackend for KuznyechikDecryptBackend<'a> {
    // Define the proc_block method to process a single block.
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        // Call the decrypt_block method on the inner cipher instance with the output block.
        self.0.decrypt_block(block.get_out());
    }
}

// Implement the BlockDecrypt trait for KuznyechikWrapper.
// This provides the high-level decryption interface.
impl BlockDecrypt for KuznyechikWrapper {
    // Define the decrypt_with_backend method.
    fn decrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        // Create an instance of the decryption backend with a reference to the inner cipher.
        let mut backend = KuznyechikDecryptBackend(&self.0);
        // Call the closure with the backend.
        f.call(&mut backend);
    }
}

// Define a wrapper struct for the Camellia cipher.
// It wraps the inner camellia::Camellia256 struct.
// Derive Zeroize and ZeroizeOnDrop for security.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct CamelliaWrapper(#[zeroize(skip)] camellia::Camellia256);

// Implement KeySizeUser for CamelliaWrapper.
impl KeySizeUser for CamelliaWrapper {
    // Set the key size to 32 bytes (256 bits), represented by U32.
    type KeySize = U32;
}

// Implement KeyInit for CamelliaWrapper.
impl KeyInit for CamelliaWrapper {
    // Define the new method to create a new instance.
    fn new(key: &Key<Self>) -> Self {
        // Initialize the inner Camellia256 cipher with the provided key and wrap it.
        CamelliaWrapper(camellia::Camellia256::new(key))
    }
}

// Implement BlockSizeUser for CamelliaWrapper.
impl BlockSizeUser for CamelliaWrapper {
    // Set the block size to 16 bytes (128 bits), represented by U16.
    type BlockSize = U16;
}

// Implement the BlockCipher marker trait for CamelliaWrapper.
impl BlockCipher for CamelliaWrapper {}

// Define a backend struct for Camellia encryption.
struct CamelliaEncryptBackend<'a>(&'a camellia::Camellia256);

// Implement BlockSizeUser for the encryption backend.
impl<'a> BlockSizeUser for CamelliaEncryptBackend<'a> {
    // The block size is 16 bytes.
    type BlockSize = U16;
}
// Implement ParBlocksSizeUser for the encryption backend.
impl<'a> ParBlocksSizeUser for CamelliaEncryptBackend<'a> {
    // Set to 1 block at a time.
    type ParBlocksSize = U1;
}
// Implement BlockBackend for the encryption backend.
impl<'a> BlockBackend for CamelliaEncryptBackend<'a> {
    // Define the proc_block method.
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        // Call the encrypt_block method on the inner cipher.
        self.0.encrypt_block(block.get_out());
    }
}

// Implement BlockEncrypt for CamelliaWrapper.
impl BlockEncrypt for CamelliaWrapper {
    // Define the encrypt_with_backend method.
    fn encrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        // Create the backend instance.
        let mut backend = CamelliaEncryptBackend(&self.0);
        // Call the closure.
        f.call(&mut backend);
    }
}

// Define a backend struct for Camellia decryption.
struct CamelliaDecryptBackend<'a>(&'a camellia::Camellia256);

// Implement BlockSizeUser for the decryption backend.
impl<'a> BlockSizeUser for CamelliaDecryptBackend<'a> {
    // The block size is 16 bytes.
    type BlockSize = U16;
}
// Implement ParBlocksSizeUser for the decryption backend.
impl<'a> ParBlocksSizeUser for CamelliaDecryptBackend<'a> {
    // Set to 1 block at a time.
    type ParBlocksSize = U1;
}
// Implement BlockBackend for the decryption backend.
impl<'a> BlockBackend for CamelliaDecryptBackend<'a> {
    // Define the proc_block method.
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        // Call the decrypt_block method on the inner cipher.
        self.0.decrypt_block(block.get_out());
    }
}

// Implement BlockDecrypt for CamelliaWrapper.
impl BlockDecrypt for CamelliaWrapper {
    // Define the decrypt_with_backend method.
    fn decrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        // Create the backend instance.
        let mut backend = CamelliaDecryptBackend(&self.0);
        // Call the closure.
        f.call(&mut backend);
    }
}

// Define an enum named SupportedCipher representing all supported cipher combinations.
// Derive Zeroize and ZeroizeOnDrop to securely wipe key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SupportedCipher {
    // Single cipher variants.
    // AES-256 in XTS mode.
    Aes(#[zeroize(skip)] Xts128<Aes256>),
    // Serpent in XTS mode.
    Serpent(#[zeroize(skip)] Xts128<Serpent>),
    // Twofish in XTS mode.
    Twofish(#[zeroize(skip)] Xts128<Twofish>),
    
    // Cascade cipher variants (Order matters: Outer -> Inner).
    // AES then Twofish cascade.
    AesTwofish(#[zeroize(skip)] Xts128<Aes256>, #[zeroize(skip)] Xts128<Twofish>),
    // AES then Twofish then Serpent cascade.
    AesTwofishSerpent(#[zeroize(skip)] Xts128<Aes256>, #[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Serpent>),
    // Serpent then AES cascade.
    SerpentAes(#[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<Aes256>),
    // Twofish then Serpent cascade.
    TwofishSerpent(#[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Serpent>),
    // Serpent then Twofish then AES cascade.
    SerpentTwofishAes(#[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Aes256>),
    
    // Other single ciphers.
    // Camellia in XTS mode.
    Camellia(#[zeroize(skip)] Xts128<CamelliaWrapper>),
    // Kuznyechik in XTS mode.
    Kuznyechik(#[zeroize(skip)] Xts128<KuznyechikWrapper>),
    
    // Other cascade variants.
    // Camellia then Kuznyechik cascade.
    CamelliaKuznyechik(#[zeroize(skip)] Xts128<CamelliaWrapper>, #[zeroize(skip)] Xts128<KuznyechikWrapper>),
    // Camellia then Serpent cascade.
    CamelliaSerpent(#[zeroize(skip)] Xts128<CamelliaWrapper>, #[zeroize(skip)] Xts128<Serpent>),
    // Kuznyechik then AES cascade.
    KuznyechikAes(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Aes256>),
    // Kuznyechik then Serpent then Camellia cascade.
    KuznyechikSerpentCamellia(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<CamelliaWrapper>),
    // Kuznyechik then Twofish cascade.
    KuznyechikTwofish(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Twofish>),
}

// Implementation of encryption and decryption methods for SupportedCipher.
impl SupportedCipher {
    // Define the decrypt_area method to decrypt a sector (or data unit) using XTS mode.
    // It takes a mutable data buffer, the sector size, and the sector index.
    pub fn decrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u64) {
        // Tweak calculation:
        // Convert the sector index to a 16-byte array in little-endian order.
        // This is the standard XTS tweak generation method.
        let tweak = sector_index.to_le_bytes();
        
        // Define a closure to provide the tweak to the XTS implementation.
        // It takes a u128 index (unused here as we use the pre-calculated tweak) and returns a [u8; 16].
        let get_tweak = |_i: u128| -> [u8; 16] {
            // Initialize a 16-byte array with zeros.
            let mut t = [0u8; 16];
            // Copy the 8 bytes of the sector index into the first 8 bytes of the tweak array.
            t[..8].copy_from_slice(&tweak);
            // Return the tweak array.
            t
        };

        // Dispatch the decryption operation to the appropriate cipher variant.
        // For cascades, decryption is applied in the order defined in the enum variant.
        // Based on the implementation, the enum variants seem to store ciphers in the order they should be applied for DECRYPTION.
        match self {
            // For single AES, call decrypt_area on the XTS instance.
            SupportedCipher::Aes(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            // For single Serpent, call decrypt_area.
            SupportedCipher::Serpent(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            // For single Twofish, call decrypt_area.
            SupportedCipher::Twofish(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            
            // For AesTwofish cascade:
            SupportedCipher::AesTwofish(xts_aes, xts_twofish) => {
                // First decrypt with AES.
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
                // Then decrypt with Twofish.
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For AesTwofishSerpent cascade:
            SupportedCipher::AesTwofishSerpent(xts_aes, xts_twofish, xts_serpent) => {
                // Decrypt with AES.
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Twofish.
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Serpent.
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For SerpentAes cascade:
            SupportedCipher::SerpentAes(xts_serpent, xts_aes) => {
                // Decrypt with Serpent.
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with AES.
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For TwofishSerpent cascade:
            SupportedCipher::TwofishSerpent(xts_twofish, xts_serpent) => {
                // Decrypt with Twofish.
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Serpent.
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For SerpentTwofishAes cascade:
            SupportedCipher::SerpentTwofishAes(xts_serpent, xts_twofish, xts_aes) => {
                // Decrypt with Serpent.
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Twofish.
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with AES.
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For single Camellia:
            SupportedCipher::Camellia(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            // For single Kuznyechik:
            SupportedCipher::Kuznyechik(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            // For CamelliaKuznyechik cascade:
            SupportedCipher::CamelliaKuznyechik(xts_camellia, xts_kuznyechik) => {
                // Decrypt with Camellia.
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Kuznyechik.
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For CamelliaSerpent cascade:
            SupportedCipher::CamelliaSerpent(xts_camellia, xts_serpent) => {
                // Decrypt with Camellia.
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Serpent.
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For KuznyechikAes cascade:
            SupportedCipher::KuznyechikAes(xts_kuznyechik, xts_aes) => {
                // Decrypt with Kuznyechik.
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with AES.
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For KuznyechikSerpentCamellia cascade:
            SupportedCipher::KuznyechikSerpentCamellia(xts_kuznyechik, xts_serpent, xts_camellia) => {
                // Decrypt with Kuznyechik.
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Serpent.
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Camellia.
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
            },
            // For KuznyechikTwofish cascade:
            SupportedCipher::KuznyechikTwofish(xts_kuznyechik, xts_twofish) => {
                // Decrypt with Kuznyechik.
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
                // Decrypt with Twofish.
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
            },
        }
    }

    // Define the encrypt_area method to encrypt a sector (or data unit) using XTS mode.
    // It takes a mutable data buffer, the sector size, and the sector index.
    pub fn encrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u64) {
        // Convert sector index to little-endian bytes for the tweak.
        let tweak = sector_index.to_le_bytes();
        // Define a closure to provide the tweak to the XTS implementation.
        let get_tweak = |_i: u128| -> [u8; 16] {
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&tweak);
            t
        };

        // Dispatch the encryption operation.
        // Encryption order must be the reverse of the decryption order.
        // If Decrypt is A then B, Encrypt must be B then A.
        match self {
            // For single AES, call encrypt_area.
            SupportedCipher::Aes(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            // For single Serpent, call encrypt_area.
            SupportedCipher::Serpent(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            // For single Twofish, call encrypt_area.
            SupportedCipher::Twofish(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            
            // For AesTwofish cascade (Decrypt: Aes -> Twofish):
            SupportedCipher::AesTwofish(xts_aes, xts_twofish) => {
                // Encrypt with Twofish first.
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                // Then encrypt with AES.
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For AesTwofishSerpent cascade (Decrypt: Aes -> Twofish -> Serpent):
            SupportedCipher::AesTwofishSerpent(xts_aes, xts_twofish, xts_serpent) => {
                // Encrypt with Serpent.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Twofish.
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with AES.
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For SerpentAes cascade (Decrypt: Serpent -> Aes):
            SupportedCipher::SerpentAes(xts_serpent, xts_aes) => {
                // Encrypt with AES.
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Serpent.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For TwofishSerpent cascade (Decrypt: Twofish -> Serpent):
            SupportedCipher::TwofishSerpent(xts_twofish, xts_serpent) => {
                // Encrypt with Serpent.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Twofish.
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For SerpentTwofishAes cascade (Decrypt: Serpent -> Twofish -> Aes):
            SupportedCipher::SerpentTwofishAes(xts_serpent, xts_twofish, xts_aes) => {
                // Encrypt with AES.
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Twofish.
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Serpent.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For single Camellia:
            SupportedCipher::Camellia(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            // For single Kuznyechik:
            SupportedCipher::Kuznyechik(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            // For CamelliaKuznyechik cascade (Decrypt: Camellia -> Kuznyechik):
            SupportedCipher::CamelliaKuznyechik(xts_camellia, xts_kuznyechik) => {
                // Encrypt with Kuznyechik.
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Camellia.
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For CamelliaSerpent cascade (Decrypt: Camellia -> Serpent):
            SupportedCipher::CamelliaSerpent(xts_camellia, xts_serpent) => {
                // Encrypt with Serpent.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Camellia.
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For KuznyechikAes cascade (Decrypt: Kuznyechik -> Aes):
            SupportedCipher::KuznyechikAes(xts_kuznyechik, xts_aes) => {
                // Encrypt with AES.
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Kuznyechik.
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For KuznyechikSerpentCamellia cascade (Decrypt: Kuznyechik -> Serpent -> Camellia):
            SupportedCipher::KuznyechikSerpentCamellia(xts_kuznyechik, xts_serpent, xts_camellia) => {
                // Encrypt with Camellia.
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Serpent.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Kuznyechik.
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
            },
            // For KuznyechikTwofish cascade (Decrypt: Kuznyechik -> Twofish):
            SupportedCipher::KuznyechikTwofish(xts_kuznyechik, xts_twofish) => {
                // Encrypt with Twofish.
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                // Encrypt with Kuznyechik.
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
            },
        }
    }
}
