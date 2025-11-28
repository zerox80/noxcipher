use aes::Aes256;
use xts_mode::Xts128;
use serpent::Serpent;
use twofish::Twofish;
use cipher::{KeyInit, BlockCipher, BlockEncrypt, BlockDecrypt, Key, Block, KeySizeUser, BlockSizeUser, ParBlocksSizeUser, BlockBackend};
use cipher::consts::{U32, U16, U1};
use cipher::inout::InOut;
use kuznyechik::block_cipher::{NewBlockCipher, BlockCipher as OldBlockCipher};
use zeroize::{Zeroize, ZeroizeOnDrop};

// Wrapper structs for ciphers that don't implement the exact traits we need or need adaptation

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct KuznyechikWrapper(#[zeroize(skip)] kuznyechik::Kuznyechik);

impl KeySizeUser for KuznyechikWrapper {
    type KeySize = U32;
}

impl KeyInit for KuznyechikWrapper {
    fn new(key: &Key<Self>) -> Self {
        KuznyechikWrapper(kuznyechik::Kuznyechik::new(key))
    }
}

impl BlockSizeUser for KuznyechikWrapper {
    type BlockSize = U16;
}

impl BlockCipher for KuznyechikWrapper {}

struct KuznyechikEncryptBackend<'a>(&'a kuznyechik::Kuznyechik);

impl<'a> BlockSizeUser for KuznyechikEncryptBackend<'a> {
    type BlockSize = U16;
}
impl<'a> ParBlocksSizeUser for KuznyechikEncryptBackend<'a> {
    type ParBlocksSize = U1;
}
impl<'a> BlockBackend for KuznyechikEncryptBackend<'a> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.0.encrypt_block(block.get_out());
    }
}

impl BlockEncrypt for KuznyechikWrapper {
    fn encrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend = KuznyechikEncryptBackend(&self.0);
        f.call(&mut backend);
    }
}

struct KuznyechikDecryptBackend<'a>(&'a kuznyechik::Kuznyechik);

impl<'a> BlockSizeUser for KuznyechikDecryptBackend<'a> {
    type BlockSize = U16;
}
impl<'a> ParBlocksSizeUser for KuznyechikDecryptBackend<'a> {
    type ParBlocksSize = U1;
}
impl<'a> BlockBackend for KuznyechikDecryptBackend<'a> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.0.decrypt_block(block.get_out());
    }
}

impl BlockDecrypt for KuznyechikWrapper {
    fn decrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend = KuznyechikDecryptBackend(&self.0);
        f.call(&mut backend);
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct CamelliaWrapper(#[zeroize(skip)] camellia::Camellia256);

impl KeySizeUser for CamelliaWrapper {
    type KeySize = U32;
}

impl KeyInit for CamelliaWrapper {
    fn new(key: &Key<Self>) -> Self {
        CamelliaWrapper(camellia::Camellia256::new(key))
    }
}

impl BlockSizeUser for CamelliaWrapper {
    type BlockSize = U16;
}

impl BlockCipher for CamelliaWrapper {}

struct CamelliaEncryptBackend<'a>(&'a camellia::Camellia256);

impl<'a> BlockSizeUser for CamelliaEncryptBackend<'a> {
    type BlockSize = U16;
}
impl<'a> ParBlocksSizeUser for CamelliaEncryptBackend<'a> {
    type ParBlocksSize = U1;
}
impl<'a> BlockBackend for CamelliaEncryptBackend<'a> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.0.encrypt_block(block.get_out());
    }
}

impl BlockEncrypt for CamelliaWrapper {
    fn encrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend = CamelliaEncryptBackend(&self.0);
        f.call(&mut backend);
    }
}

struct CamelliaDecryptBackend<'a>(&'a camellia::Camellia256);

impl<'a> BlockSizeUser for CamelliaDecryptBackend<'a> {
    type BlockSize = U16;
}
impl<'a> ParBlocksSizeUser for CamelliaDecryptBackend<'a> {
    type ParBlocksSize = U1;
}
impl<'a> BlockBackend for CamelliaDecryptBackend<'a> {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.0.decrypt_block(block.get_out());
    }
}

impl BlockDecrypt for CamelliaWrapper {
    fn decrypt_with_backend(&self, f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend = CamelliaDecryptBackend(&self.0);
        f.call(&mut backend);
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub enum SupportedCipher {
    Aes(#[zeroize(skip)] Xts128<Aes256>),
    Serpent(#[zeroize(skip)] Xts128<Serpent>),
    Twofish(#[zeroize(skip)] Xts128<Twofish>),
    AesTwofish(#[zeroize(skip)] Xts128<Aes256>, #[zeroize(skip)] Xts128<Twofish>),
    AesTwofishSerpent(#[zeroize(skip)] Xts128<Aes256>, #[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Serpent>),
    SerpentAes(#[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<Aes256>),
    TwofishSerpent(#[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Serpent>),
    SerpentTwofishAes(#[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<Twofish>, #[zeroize(skip)] Xts128<Aes256>),
    Camellia(#[zeroize(skip)] Xts128<CamelliaWrapper>),
    Kuznyechik(#[zeroize(skip)] Xts128<KuznyechikWrapper>),
    CamelliaKuznyechik(#[zeroize(skip)] Xts128<CamelliaWrapper>, #[zeroize(skip)] Xts128<KuznyechikWrapper>),
    CamelliaSerpent(#[zeroize(skip)] Xts128<CamelliaWrapper>, #[zeroize(skip)] Xts128<Serpent>),
    KuznyechikAes(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Aes256>),
    KuznyechikSerpentCamellia(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Serpent>, #[zeroize(skip)] Xts128<CamelliaWrapper>),
    KuznyechikTwofish(#[zeroize(skip)] Xts128<KuznyechikWrapper>, #[zeroize(skip)] Xts128<Twofish>),
}

impl SupportedCipher {
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
        
        let tweak = sector_index.to_le_bytes();
        let get_tweak = |_i: u128| -> [u8; 16] {
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&tweak);
            t
        };

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
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::TwofishSerpent(xts_twofish, xts_serpent) => {
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::SerpentTwofishAes(xts_serpent, xts_twofish, xts_aes) => {
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::Camellia(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Kuznyechik(xts) => xts.decrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::CamelliaKuznyechik(xts_camellia, xts_kuznyechik) => {
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::CamelliaSerpent(xts_camellia, xts_serpent) => {
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikAes(xts_kuznyechik, xts_aes) => {
                xts_aes.decrypt_area(data, sector_size, 0, get_tweak);
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikSerpentCamellia(xts_kuznyechik, xts_serpent, xts_camellia) => {
                xts_camellia.decrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.decrypt_area(data, sector_size, 0, get_tweak);
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikTwofish(xts_kuznyechik, xts_twofish) => {
                xts_twofish.decrypt_area(data, sector_size, 0, get_tweak);
                xts_kuznyechik.decrypt_area(data, sector_size, 0, get_tweak);
            },
        }
    }

    pub fn encrypt_area(&self, data: &mut [u8], sector_size: usize, sector_index: u64) {
        let tweak = sector_index.to_le_bytes();
        let get_tweak = |_i: u128| -> [u8; 16] {
            let mut t = [0u8; 16];
            t[..8].copy_from_slice(&tweak);
            t
        };

        match self {
            SupportedCipher::Aes(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Serpent(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Twofish(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::AesTwofish(xts_aes, xts_twofish) => {
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::AesTwofishSerpent(xts_aes, xts_twofish, xts_serpent) => {
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::SerpentAes(xts_serpent, xts_aes) => {
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::TwofishSerpent(xts_twofish, xts_serpent) => {
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::SerpentTwofishAes(xts_serpent, xts_twofish, xts_aes) => {
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::Camellia(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::Kuznyechik(xts) => xts.encrypt_area(data, sector_size, 0, get_tweak),
            SupportedCipher::CamelliaKuznyechik(xts_camellia, xts_kuznyechik) => {
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::CamelliaSerpent(xts_camellia, xts_serpent) => {
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikAes(xts_kuznyechik, xts_aes) => {
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
                xts_aes.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikSerpentCamellia(xts_kuznyechik, xts_serpent, xts_camellia) => {
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
                xts_serpent.encrypt_area(data, sector_size, 0, get_tweak);
                xts_camellia.encrypt_area(data, sector_size, 0, get_tweak);
            },
            SupportedCipher::KuznyechikTwofish(xts_kuznyechik, xts_twofish) => {
                xts_kuznyechik.encrypt_area(data, sector_size, 0, get_tweak);
                xts_twofish.encrypt_area(data, sector_size, 0, get_tweak);
            },
        }
    }
}
