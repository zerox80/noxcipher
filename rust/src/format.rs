use byteorder::{ByteOrder, LittleEndian};
use getrandom::fill as getrandom_fill;
use std::io::{self, Write, Seek, SeekFrom};

// Minimal FAT32 Formatter
// Creates a valid FAT32 filesystem structure in the provided writer.
// We strictly follow Microsoft FAT32 specification for maximum compatibility.

const SECTOR_SIZE: u64 = 512;
const RESERVED_SECTORS: u64 = 32;
const FAT_COUNT: u64 = 2;
const SECTORS_PER_CLUSTER: u64 = 8;
const FAT_ENTRY_SIZE: u64 = 4;
const ROOT_DIR_CLUSTER: u64 = 2;
const FAT_RESERVED_ENTRIES: u64 = 3;

struct Fat32Geometry {
    total_sectors: u32,
    fat_sectors: u32,
    cluster_size: u64,
    fat_size_bytes: u64,
    fat1_offset: u64,
    fat2_offset: u64,
    root_dir_offset: u64,
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn derive_volume_id(seed: [u8; 16]) -> u32 {
    let volume_id = crc32fast::hash(&seed);
    if volume_id == 0 { 1 } else { volume_id }
}

fn generate_volume_id() -> io::Result<u32> {
    let mut seed = [0u8; 16];
    getrandom_fill(&mut seed).map_err(io::Error::other)?;
    Ok(derive_volume_id(seed))
}

fn calculate_geometry(volume_size: u64) -> io::Result<Fat32Geometry> {
    if volume_size < SECTOR_SIZE {
        return Err(invalid_input("Volume too small for FAT32 formatting"));
    }

    let total_sectors = volume_size / SECTOR_SIZE;
    if total_sectors > u32::MAX as u64 {
        return Err(invalid_input("Volume too large for FAT32 sector fields"));
    }

    let usable_sectors = total_sectors
        .checked_sub(RESERVED_SECTORS)
        .ok_or_else(|| invalid_input("Volume too small for FAT32 reserved sectors"))?;
    let approx_clusters = usable_sectors / SECTORS_PER_CLUSTER;
    if approx_clusters < ROOT_DIR_CLUSTER + 1 {
        return Err(invalid_input("Volume too small for FAT32 data area"));
    }

    let fat_entries = approx_clusters
        .checked_add(FAT_RESERVED_ENTRIES)
        .ok_or_else(|| invalid_input("FAT32 cluster count overflow"))?;
    let fat_size_bytes = fat_entries
        .checked_mul(FAT_ENTRY_SIZE)
        .ok_or_else(|| invalid_input("FAT32 table size overflow"))?;
    let fat_sectors = fat_size_bytes
        .checked_add(SECTOR_SIZE - 1)
        .ok_or_else(|| invalid_input("FAT32 sector rounding overflow"))?
        / SECTOR_SIZE;

    if fat_sectors > u32::MAX as u64 {
        return Err(invalid_input("FAT32 table too large for boot sector fields"));
    }

    let data_start_sectors = RESERVED_SECTORS
        .checked_add(
            FAT_COUNT
                .checked_mul(fat_sectors)
                .ok_or_else(|| invalid_input("FAT32 FAT region overflow"))?,
        )
        .ok_or_else(|| invalid_input("FAT32 layout overflow"))?;

    let cluster_size = SECTORS_PER_CLUSTER
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| invalid_input("FAT32 cluster size overflow"))?;
    let root_dir_offset = data_start_sectors
        .checked_mul(SECTOR_SIZE)
        .ok_or_else(|| invalid_input("FAT32 root directory offset overflow"))?;
    let required_size = root_dir_offset
        .checked_add(cluster_size)
        .ok_or_else(|| invalid_input("FAT32 layout exceeds address space"))?;

    if required_size > volume_size {
        return Err(invalid_input("Volume too small for FAT32 metadata and root directory"));
    }

    Ok(Fat32Geometry {
        total_sectors: total_sectors as u32,
        fat_sectors: fat_sectors as u32,
        cluster_size,
        fat_size_bytes,
        fat1_offset: RESERVED_SECTORS * SECTOR_SIZE,
        fat2_offset: (RESERVED_SECTORS + fat_sectors) * SECTOR_SIZE,
        root_dir_offset,
    })
}

pub fn format_fat32<W: Write + Seek>(writer: &mut W, volume_size: u64) -> io::Result<()> {
    let geometry = calculate_geometry(volume_size)?;
    let volume_id = generate_volume_id()?;
    
    // Align FAT sectors? Not strictly needed but good practice.
    
    // 2. Write Boot Sector (Sector 0)
    let mut boot_sector = [0u8; 512];
    
    // Jump Instruction (EB 58 90)
    boot_sector[0] = 0xEB;
    boot_sector[1] = 0x58;
    boot_sector[2] = 0x90;
    
    // OEM Name "MSDOS5.0"
    boot_sector[3..11].copy_from_slice(b"MSDOS5.0");
    
    // Bytes Per Sector
    LittleEndian::write_u16(&mut boot_sector[11..13], SECTOR_SIZE as u16);
    // Sectors Per Cluster
    boot_sector[13] = SECTORS_PER_CLUSTER as u8;
    // Reserved Sectors
    LittleEndian::write_u16(&mut boot_sector[14..16], RESERVED_SECTORS as u16);
    // Number of FATs
    boot_sector[16] = FAT_COUNT as u8;
    // Root Entries (0 for FAT32)
    LittleEndian::write_u16(&mut boot_sector[17..19], 0);
    // Total Sectors 16 (0 for FAT32)
    LittleEndian::write_u16(&mut boot_sector[19..21], 0);
    // Media Descriptor (F8 for HDD)
    boot_sector[21] = 0xF8;
    // Sectors Per FAT 16 (0, used large field below)
    LittleEndian::write_u16(&mut boot_sector[22..24], 0);
    // Sectors Per Track & Heads (Mock geometry)
    LittleEndian::write_u16(&mut boot_sector[24..26], 32);
    LittleEndian::write_u16(&mut boot_sector[26..28], 64);
    // Hidden Sectors (0)
    LittleEndian::write_u32(&mut boot_sector[28..32], 0);
    // Total Sectors 32
    LittleEndian::write_u32(&mut boot_sector[32..36], geometry.total_sectors);
    
    // FAT32 Extended Fields
    // Sectors Per FAT 32
    LittleEndian::write_u32(&mut boot_sector[36..40], geometry.fat_sectors);
    // Ext Flags (0 - Mirror active, bit 7 = 0)
    LittleEndian::write_u16(&mut boot_sector[40..42], 0);
    // FS Version (0.0)
    LittleEndian::write_u16(&mut boot_sector[42..44], 0);
    // Root Cluster (Usually 2)
    LittleEndian::write_u32(&mut boot_sector[44..48], 2);
    // FS Info Sector (1)
    LittleEndian::write_u16(&mut boot_sector[48..50], 1);
    // Backup Boot Sector (6) ensuring it doesn't overlap anywhere
    LittleEndian::write_u16(&mut boot_sector[50..52], 6);
    
    // Drive Number (0x80)
    boot_sector[64] = 0x80;
    // Boot Sig (0x29)
    boot_sector[66] = 0x29;
    // Volume ID
    LittleEndian::write_u32(&mut boot_sector[67..71], volume_id);
    // Volume Label "NOXCIPHER  "
    boot_sector[71..82].copy_from_slice(b"NOXCIPHER  ");
    // File System Type "FAT32   "
    boot_sector[82..90].copy_from_slice(b"FAT32   ");
    
    // Signature 0xAA55
    boot_sector[510] = 0x55;
    boot_sector[511] = 0xAA;
    
    writer.seek(SeekFrom::Start(0))?;
    writer.write_all(&boot_sector)?;
    
    // 3. Write FS Info Sector (Sector 1)
    let mut fs_info = [0u8; 512];
    // Signature 1
    LittleEndian::write_u32(&mut fs_info[0..4], 0x41615252);
    // Signature 2
    LittleEndian::write_u32(&mut fs_info[484..488], 0x61417272);
    // Free Cluster Count (Approx -1 known)
    LittleEndian::write_u32(&mut fs_info[488..492], 0xFFFFFFFF);
    // Next Free Cluster (Usually 2)
    LittleEndian::write_u32(&mut fs_info[492..496], 2);
    // Trailer
    LittleEndian::write_u32(&mut fs_info[508..512], 0xAA550000);
    
    writer.write_all(&fs_info)?;
    
    // 4. Write Backup Boot Sector (Sector 6)
    writer.seek(SeekFrom::Start(6 * SECTOR_SIZE))?;
    writer.write_all(&boot_sector)?;
    
    // 5. Initialize FAT Tables
    // FAT1 starts at Reserved Sectors
    writer.seek(SeekFrom::Start(geometry.fat1_offset))?;
    
    // First 2 entries are reserved
    // Entry 0: 0x0FFFFFF8 (Media Type)
    // Entry 1: 0x0FFFFFFF (EOC) -> Actually usually same as entry 0 high bytes? No.
    // Entry 0: F8 FF FF 0F (for F8 media)
    // Entry 1: FF FF FF 0F (Clean Shutdown mask? 0FFFFFFF)
    // Entry 2: 0FFFFFFF (EOC) - Root Dir Chain End
    
    let mut fat_start = [0u8; 12];
    // F8 FF FF 0F
    fat_start[0] = 0xF8; fat_start[1] = 0xFF; fat_start[2] = 0xFF; fat_start[3] = 0x0F;
    // FF FF FF 0F
    fat_start[4] = 0xFF; fat_start[5] = 0xFF; fat_start[6] = 0xFF; fat_start[7] = 0x0F;
    // FF FF FF 0F (Root Dir End)
    fat_start[8] = 0xFF; fat_start[9] = 0xFF; fat_start[10] = 0xFF; fat_start[11] = 0x0F;
    
    // Write FAT1
    writer.seek(SeekFrom::Start(geometry.fat1_offset))?;
    writer.write_all(&fat_start)?;
    
    // Zero out the rest of FAT1 (padding to full FAT sectors)
    let zeros = vec![0u8; 4096];
    let fat_sector_bytes = geometry.fat_sectors as u64 * SECTOR_SIZE;
    let mut remaining = fat_sector_bytes.saturating_sub(fat_start.len() as u64);
    while remaining > 0 {
        let to_write = std::cmp::min(remaining, zeros.len() as u64);
        writer.write_all(&zeros[..to_write as usize])?;
        remaining -= to_write;
    }
    
    // Write FAT2
    writer.seek(SeekFrom::Start(geometry.fat2_offset))?;
    writer.write_all(&fat_start)?;
    
    // Zero out the rest of FAT2
    let mut remaining = fat_sector_bytes.saturating_sub(fat_start.len() as u64);
    while remaining > 0 {
        let to_write = std::cmp::min(remaining, zeros.len() as u64);
        writer.write_all(&zeros[..to_write as usize])?;
        remaining -= to_write;
    }
    
    // Initialize Root Directory (Cluster 2)
    // Cluster 2 starts at Data Start.
    // Data Start = Reserved + (FATs * FAT_Size).
    // Note: FAT_Size in sectors.
    
    writer.seek(SeekFrom::Start(geometry.root_dir_offset))?;
    
    // Zero out one cluster for Root Directory
    let mut remaining = geometry.cluster_size;
    while remaining > 0 {
        let to_write = std::cmp::min(remaining, zeros.len() as u64);
        writer.write_all(&zeros[..to_write as usize])?;
        remaining -= to_write;
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{calculate_geometry, derive_volume_id, format_fat32, RESERVED_SECTORS, SECTOR_SIZE};
    use byteorder::{ByteOrder, LittleEndian};
    use std::io::Cursor;

    #[test]
    fn rejects_too_small_volume() {
        let err = format_fat32(&mut Cursor::new(vec![0u8; 4096]), 4096).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_volume_larger_than_fat32_boot_fields() {
        let too_large = (u32::MAX as u64 + 1) * SECTOR_SIZE;
        let err = calculate_geometry(too_large).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn writes_boot_sector_with_computed_geometry() {
        let volume_size = 32 * 1024 * 1024;
        let mut image = Cursor::new(vec![0u8; volume_size as usize]);

        format_fat32(&mut image, volume_size).unwrap();

        let bytes = image.into_inner();
        let boot_sector = &bytes[..SECTOR_SIZE as usize];

        assert_eq!(LittleEndian::read_u16(&boot_sector[11..13]), SECTOR_SIZE as u16);
        assert_eq!(LittleEndian::read_u16(&boot_sector[14..16]), RESERVED_SECTORS as u16);
        assert_ne!(LittleEndian::read_u32(&boot_sector[67..71]), 0x12345678);
        assert_eq!(boot_sector[510], 0x55);
        assert_eq!(boot_sector[511], 0xAA);
    }

    #[test]
    fn derives_non_zero_volume_id() {
        let volume_id = derive_volume_id([0u8; 16]);
        assert_ne!(volume_id, 0);
    }
}
