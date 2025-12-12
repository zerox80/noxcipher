use byteorder::{ByteOrder, LittleEndian};
use std::io::{self, Write, Seek, SeekFrom};

// Minimal FAT32 Formatter
// Creates a valid FAT32 filesystem structure in the provided writer.
// We strictly follow Microsoft FAT32 specification for maximum compatibility.

pub fn format_fat32<W: Write + Seek>(writer: &mut W, volume_size: u64) -> io::Result<()> {
    // 1. Calculate Geometry
    let sector_size: u64 = 512;
    let total_sectors = volume_size / sector_size;
    
    // Reserve sectors (Boot sector + FSInfo + Backup Boot)
    let reserved_sectors = 32;
    let fat_count = 2;
    
    // Cluster size (4KB is standard for < 32GB)
    let sectors_per_cluster = 8; 
    let cluster_size = sectors_per_cluster * sector_size;
    
    // Determine FAT size
    // Total Clusters ~= (Total Sectors - Reserved) / SPC
    // FAT Entry = 4 bytes.
    // FAT Size = (Clusters * 4 + 511) / 512
    let approx_clusters = (total_sectors - reserved_sectors) / sectors_per_cluster;
    let fat_size_bytes = approx_clusters * 4;
    let fat_sectors = (fat_size_bytes + sector_size - 1) / sector_size;
    
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
    LittleEndian::write_u16(&mut boot_sector[11..13], sector_size as u16);
    // Sectors Per Cluster
    boot_sector[13] = sectors_per_cluster as u8;
    // Reserved Sectors
    LittleEndian::write_u16(&mut boot_sector[14..16], reserved_sectors as u16);
    // Number of FATs
    boot_sector[16] = fat_count as u8;
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
    LittleEndian::write_u32(&mut boot_sector[32..36], total_sectors as u32);
    
    // FAT32 Extended Fields
    // Sectors Per FAT 32
    LittleEndian::write_u32(&mut boot_sector[36..40], fat_sectors as u32);
    // Ext Flags (0 - Mirror active)
    LittleEndian::write_u16(&mut boot_sector[40..42], 0);
    // FS Version (0.0)
    LittleEndian::write_u16(&mut boot_sector[42..44], 0);
    // Root Cluster (Usually 2)
    LittleEndian::write_u32(&mut boot_sector[44..48], 2);
    // FS Info Sector (1)
    LittleEndian::write_u16(&mut boot_sector[48..50], 1);
    // Backup Boot Sector (6)
    LittleEndian::write_u16(&mut boot_sector[50..52], 6);
    
    // Drive Number (0x80)
    boot_sector[64] = 0x80;
    // Boot Sig (0x29)
    boot_sector[66] = 0x29;
    // Volume ID (Randomish)
    LittleEndian::write_u32(&mut boot_sector[67..71], 0x12345678);
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
    writer.seek(SeekFrom::Start(6 * sector_size))?;
    writer.write_all(&boot_sector)?;
    
    // 5. Initialize FAT Tables
    // FAT1 starts at Reserved Sectors
    let fat1_offset = reserved_sectors * sector_size;
    writer.seek(SeekFrom::Start(fat1_offset))?;
    
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
    writer.seek(SeekFrom::Start(fat1_offset))?;
    writer.write_all(&fat_start)?;
    
    // Zero out the rest of FAT1
    let zeros = vec![0u8; 4096];
    let mut remaining = fat_size_bytes - 12;
    while remaining > 0 {
        let to_write = std::cmp::min(remaining, zeros.len() as u64);
        writer.write_all(&zeros[..to_write as usize])?;
        remaining -= to_write;
    }
    
    // Write FAT2
    let fat2_offset = fat1_offset + (fat_sectors * sector_size);
    writer.seek(SeekFrom::Start(fat2_offset))?;
    writer.write_all(&fat_start)?;
    
    // Zero out the rest of FAT2
    let mut remaining = fat_size_bytes - 12;
    while remaining > 0 {
        let to_write = std::cmp::min(remaining, zeros.len() as u64);
        writer.write_all(&zeros[..to_write as usize])?;
        remaining -= to_write;
    }
    
    // Initialize Root Directory (Cluster 2)
    // Cluster 2 starts at Data Start.
    // Data Start = Reserved + (FATs * FAT_Size).
    // Note: FAT_Size in sectors.
    
    let root_dir_offset = (reserved_sectors as u64 + (fat_count as u64 * fat_sectors as u64)) * sector_size;
    writer.seek(SeekFrom::Start(root_dir_offset))?;
    
    // Zero out one cluster for Root Directory
    let mut remaining = cluster_size;
    while remaining > 0 {
        let to_write = std::cmp::min(remaining, zeros.len() as u64);
        writer.write_all(&zeros[..to_write as usize])?;
        remaining -= to_write;
    }
    
    Ok(())
}
