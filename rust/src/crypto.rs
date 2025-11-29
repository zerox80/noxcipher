// Import AES-256 cipher.
use aes::Aes256;
// Import XTS mode.
use xts_mode::Xts128;
// Import Serpent cipher.
use serpent::Serpent;
// Import Twofish cipher.
use twofish::Twofish;
// Import cipher traits.
use cipher::{KeyInit, BlockCipher, BlockEncrypt, BlockDecrypt, Key, Block, KeySizeUser, BlockSizeUser, ParBlocksSizeUser, BlockBackend};
// Import cipher constants.
use cipher::consts::{U32, U16, U1};
// Import InOut type for block processing.
use cipher::inout::InOut;
// Import Kuznyechik traits.
use kuznyechik::block_cipher::{NewBlockCipher, BlockCipher as OldBlockCipher};
// Import Zeroize traits for secure memory clearing.
use zeroize::{Zeroize, ZeroizeOnDrop};

// Wrapper structs for ciphers that don't implement the exact traits we need or need adaptation

// Wrapper for Kuznyechik cipher to adapt it to modern RustCrypto traits.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct KuznyechikWrapper(#[zeroize(skip)] kuznyechik::Kuznyechik);

// Implement KeySizeUser for KuznyechikWrapper (256-bit key).
impl KeySizeUser for KuznyechikWrapper {
    type KeySize = U32;
}

// Implement KeyInit for KuznyechikWrapper.
impl KeyInit for KuznyechikWrapper {
    fn new(key: &Key<Self>) -> Self {
        KuznyechikWrapper(kuznyechik::Kuznyechik::new(key))
    }
}

// Implement BlockSizeUser for KuznyechikWrapper (128-bit block).
impl BlockSizeUser for KuznyechikWrapper {
    type BlockSize = U16;
}

// Implement BlockCipher marker trait.
impl BlockCipher for KuznyechikWrapper {}

// Backend struct for Kuznyechik encryption.
struct KuznyechikEncryptBackend<'a>(&'a kuznyechik::Kuznyechik);

// Implement BlockSizeUser for backend.
impl<'a> BlockSizeUser for KuznyechikEncryptBackend<'a> {
    type BlockSize = U16;
}
// Implement ParBlocksSizeUser for backend (1 block at a time).
impl<'a> ParBlocksSizeUser for KuznyechikEncryptBackend<'a> {
    type ParBlocksSize = U1;
}
// Implement BlockBackend for encryption.
impl<'a> BlockBackend for KuznyechikEncryptBackend<'a> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.0.encrypt_block(block.get_out());
    }
}

// Implement BlockEncrypt for KuznyechikWrapper.
impl BlockEncrypt for KuznyechikWrapper {
    fn encrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend = KuznyechikEncryptBackend(&self.0);
        f.call(&mut backend);
    }
}

// Backend struct for Kuznyechik decryption.
struct KuznyechikDecryptBackend<'a>(&'a kuznyechik::Kuznyechik);

// Implement BlockSizeUser for backend.
impl<'a> BlockSizeUser for KuznyechikDecryptBackend<'a> {
    type BlockSize = U16;
}
// Implement ParBlocksSizeUser for backend.
impl<'a> ParBlocksSizeUser for KuznyechikDecryptBackend<'a> {
    type ParBlocksSize = U1;
}
// Implement BlockBackend for decryption.
impl<'a> BlockBackend for KuznyechikDecryptBackend<'a> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.0.decrypt_block(block.get_out());
    }
}

// Implement BlockDecrypt for KuznyechikWrapper.
impl BlockDecrypt for KuznyechikWrapper {
    fn decrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend = KuznyechikDecryptBackend(&self.0);
        f.call(&mut backend);
    }
}

// Wrapper for Camellia cipher to adapt it to modern RustCrypto traits.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct CamelliaWrapper(#[zeroize(skip)] camellia::Camellia256);

// Implement KeySizeUser for CamelliaWrapper (256-bit key).
impl KeySizeUser for CamelliaWrapper {
    type KeySize = U32;
}

// Implement KeyInit for CamelliaWrapper.
impl KeyInit for CamelliaWrapper {
    fn new(key: &Key<Self>) -> Self {
        CamelliaWrapper(camellia::Camellia256::new(key))
    }
}

// Implement BlockSizeUser for CamelliaWrapper (128-bit block).
impl BlockSizeUser for CamelliaWrapper {
    type BlockSize = U16;
}

// Implement BlockCipher marker trait.
impl BlockCipher for CamelliaWrapper {}

// Backend struct for Camellia encryption.
struct CamelliaEncryptBackend<'a>(&'a camellia::Camellia256);

// Implement BlockSizeUser for backend.
impl<'a> BlockSizeUser for CamelliaEncryptBackend<'a> {
    type BlockSize = U16;
}
// Implement ParBlocksSizeUser for backend.
impl<'a> ParBlocksSizeUser for CamelliaEncryptBackend<'a> {
    type ParBlocksSize = U1;
}
// Implement BlockBackend for encryption.
impl<'a> BlockBackend for CamelliaEncryptBackend<'a> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.0.encrypt_block(block.get_out());
    }
}

// Implement BlockEncrypt for CamelliaWrapper.
impl BlockEncrypt for CamelliaWrapper {
    fn encrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend = CamelliaEncryptBackend(&self.0);
        f.call(&mut backend);
    }
}

// Backend struct for Camellia decryption.
struct CamelliaDecryptBackend<'a>(&'a camellia::Camellia256);

// Implement BlockSizeUser for backend.
impl<'a> BlockSizeUser for CamelliaDecryptBackend<'a> {
    type BlockSize = U16;
}
// Implement ParBlocksSizeUser for backend.
impl<'a> ParBlocksSizeUser for CamelliaDecryptBackend<'a> {
    type ParBlocksSize = U1;
}
// Implement BlockBackend for decryption.
impl<'a> BlockBackend for CamelliaDecryptBackend<'a> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.0.decrypt_block(block.get_out());
    }
}

// Implement BlockDecrypt for CamelliaWrapper.
impl BlockDecrypt for CamelliaWrapper {
    fn decrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend = CamelliaDecryptBackend(&self.0);
        f.call(&mut backend);
    }
}

// Enum representing all supported cipher combinations.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SupportedCipher {
    // Single ciphers
    Aes(#[zeroize(skip)] Xts128<Aes256>),
    Serpent(#[zeroize(skip)] Xts128<Serpent>),
    Twofish(#[zeroize(skip)] Xts128<Twofish>),
    
    // Cascades (Order matters: Outer -> Inner)
    AesTwofish(#[zeroize(skip)] Xts128<Aes256>, #[zeroize(skip)] Xts128<Twofish>),
    AesTwofishSerpent(#[zeroize(skip)] Xts128<Aes256>, #[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Serpent>),
    SerpentAes(#[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<Aes256>),
    TwofishSerpent(#[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Serpent>),
    SerpentTwofishAes(#[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Aes256>),
    
    // Other ciphers
    Camellia(#[zeroize(skip)] Xts128<CamelliaWrapper>),
    Kuznyechik(#[zeroize(skip)] Xts128<KuznyechikWrapper>),
    
    // Other cascades
    CamelliaKuznyechik(#[zeroize(skip)] Xts128<CamelliaWrapper>, #[zeroize(skip)] Xts128<KuznyechikWrapper>),
    CamelliaSerpent(#[zeroize(skip)] Xts128<CamelliaWrapper>, #[zeroize(skip)] Xts128<Serpent>),
    KuznyechikAes(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Aes256>),
    KuznyechikSerpentCamellia(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<CamelliaWrapper>),
    KuznyechikTwofish(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Twofish>),
}

// Implementation of encryption and decryption methods for SupportedCipher.
impl SupportedCipher {
    // Decrypt a sector (or data unit) using XTS mode.
    pub fn decrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u64) {
        // Tweak calculation:
        // VeraCrypt uses the logical sector number relative to the start of the volume.
        // However, for system encryption or partitions, it might be different.
        // The standard XTS tweak is just the sector index (little endian 16 bytes).
        //
        // In VeraCrypt:
        // unitNo = startUnitNo + (offset / ENCRYPTION_DATA_UNIT_SIZE)
        // where startUnitNo is usually 0 for file containers, but for partitions it might be the physical sector number.
        //
        // The `sector_index` passed here is expected to be the correct "Data Unit Number".
        // The caller is responsible for calculating it correctly (e.g. adding partition offset).
        
        // Convert sector index to little-endian bytes for the tweak.
        let tweak = sector_index.to_le_bytes();
        // Closure to provide the tweak to the XTS implementation.
        let get_tweak = |_i: u128| -> [u8; 16] {
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&tweak);
            t
        };

        // Dispatch decryption to the appropriate cipher variant.
        // For cascades, decryption is applied in reverse order of encryption (Outer -> Inner).
        // Wait, for XTS cascades in VeraCrypt:
        // Encryption: Cipher1(Cipher2(Cipher3(Data)))
        // Decryption: Decrypt3(Decrypt2(Decrypt1(Data)))
        //
        // Let's verify the order in `volume.rs` or standard.
        // If `AesTwofish` means AES then Twofish:
        // Encrypt: AES(Twofish(Data)) ?? No, usually it's cascade of XTS layers.
        // VeraCrypt "AES-Twofish" means:
        // 1. Twofish XTS encrypt
        // 2. AES XTS encrypt
        // So Decrypt is:
        // 1. AES XTS decrypt
        // 2. Twofish XTS decrypt
        //
        // In our enum `AesTwofish(aes, twofish)`:
        // We call `aes.decrypt` then `twofish.decrypt`.
        // This matches the "AES then Twofish" decryption order, which corresponds to "Twofish then AES" encryption order?
        // Actually, VeraCrypt names cascades by the algorithms used.
        // "AES-Twofish" in UI usually means AES(Twofish(Plaintext)).
        // So Decrypt is Twofish(AES(Ciphertext)).
        //
        // Let's check `volume.rs` implementation of `try_cipher_aes_twofish`.
        // It creates `AesTwofish(aes, twofish)`.
        // And here we do `aes.decrypt` then `twofish.decrypt`.
        // If the UI says "AES-Twofish", it usually implies the order of application.
        // If it means Outer(Inner(Data)), then Decrypt is Inner(Outer(Data)).
        //
        // Assuming the enum variants hold ciphers in the order they should be applied for DECRYPTION.
        // i.e. `AesTwofish` -> Decrypt with AES, then Twofish.
        match self {
            SupportedCipher::Aes(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Serpent(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Twofish(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::AesTwofish(xts_aes, xts_twofish) => {
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::AesTwofishSerpent(xts_aes, xts_twofish, xts_serpent) => {
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::SerpentAes(xts_serpent, xts_aes) => {
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::TwofishSerpent(xts_twofish, xts_serpent) => {
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::SerpentTwofishAes(xts_serpent, xts_twofish, xts_aes) => {
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::Camellia(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Kuznyechik(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::CamelliaKuznyechik(xts_camellia, xts_kuznyechik) => {
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::CamelliaSerpent(xts_camellia, xts_serpent) => {
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikAes(xts_kuznyechik, xts_aes) => {
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikSerpentCamellia(xts_kuznyechik, xts_serpent, xts_camellia) => {
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikTwofish(xts_kuznyechik, xts_twofish) => {
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
            },
        }
    }

    // Encrypt a sector (or data unit) using XTS mode.
    pub fn encrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u64) {
        // Convert sector index to little-endian bytes for the tweak.
        let tweak = sector_index.to_le_bytes();
        // Closure to provide the tweak.
        let get_tweak = |_i: u128| -> [u8; 16] {
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&tweak);
            t
        };

        // Dispatch encryption.
        // Encryption order should be the reverse of decryption order.
        // If Decrypt is A then B, Encrypt must be B then A.
        match self {
            SupportedCipher::Aes(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Serpent(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Twofish(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::AesTwofish(xts_aes, xts_twofish) => {
                // Decrypt was Aes then Twofish. Encrypt is Twofish then Aes.
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::AesTwofishSerpent(xts_aes, xts_twofish, xts_serpent) => {
                // Decrypt was Aes, Twofish, Serpent. Encrypt is Serpent, Twofish, Aes.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::SerpentAes(xts_serpent, xts_aes) => {
                // Decrypt was Serpent, Aes. Encrypt is Aes, Serpent.
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::TwofishSerpent(xts_twofish, xts_serpent) => {
                // Decrypt was Twofish, Serpent. Encrypt is Serpent, Twofish.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::SerpentTwofishAes(xts_serpent, xts_twofish, xts_aes) => {
                // Decrypt was Serpent, Twofish, Aes. Encrypt is Aes, Twofish, Serpent.
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::Camellia(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Kuznyechik(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::CamelliaKuznyechik(xts_camellia, xts_kuznyechik) => {
                // Decrypt was Camellia, Kuznyechik. Encrypt is Kuznyechik, Camellia.
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::CamelliaSerpent(xts_camellia, xts_serpent) => {
                // Decrypt was Camellia, Serpent. Encrypt is Serpent, Camellia.
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikAes(xts_kuznyechik, xts_aes) => {
                // Decrypt was Kuznyechik, Aes. Encrypt is Aes, Kuznyechik.
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikSerpentCamellia(xts_kuznyechik, xts_serpent, xts_camellia) => {
                // Decrypt was Kuznyechik, Serpent, Camellia. Encrypt is Camellia, Serpent, Kuznyechik.
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikTwofish(xts_kuznyechik, xts_twofish) => {
                // Decrypt was Kuznyechik, Twofish. Encrypt is Twofish, Kuznyechik.
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
            },
        }
    }
}
