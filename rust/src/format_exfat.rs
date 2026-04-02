use byteorder::{ByteOrder, LittleEndian};
use getrandom::fill as getrandom_fill;
use std::io::{self, Write, Seek, SeekFrom};

// Minimal ExFAT Formatter
const SECTOR_SIZE: u64 = 512;

struct ExFatGeometry {
    total_sectors: u64,
    fat_offset: u32,
    fat_length: u32,
    cluster_heap_offset: u32,
    cluster_count: u32,
    bitmap_cluster: u32,
    bitmap_clusters_count: u32,
    upcase_cluster: u32,
    upcase_clusters_count: u32,
    root_dir_cluster: u32,
    sectors_per_cluster: u32,
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn generate_volume_id() -> io::Result<u32> {
    let mut seed = [0u8; 4];
    getrandom_fill(&mut seed).map_err(io::Error::other)?;
    Ok(LittleEndian::read_u32(&seed))
}

fn calculate_geometry(volume_size: u64) -> io::Result<ExFatGeometry> {
    if volume_size < 1024 * 1024 { // minimum 1MB
        return Err(invalid_input("Volume too small for ExFAT"));
    }

    let total_sectors = volume_size / SECTOR_SIZE;
    
    // Boot sequence is 24 sectors
    let fat_offset = 24u32;
    
    // Dynamic cluster size
    let sectors_per_cluster = if volume_size <= 32 * 1024 * 1024 * 1024 {
        8u32 // <=32GB use 4KB
    } else {
        256u32 // >32GB use 128KB
    };
    let cluster_size = (SECTOR_SIZE * sectors_per_cluster as u64) as u32;

    // Calculate space for FAT and Cluster Heap
    let available_sectors = total_sectors.saturating_sub(fat_offset as u64);
    
    // 1 cluster = `sectors_per_cluster`. 1 FAT entry = 4 bytes = 1/128 sector.
    // C * sectors + C / 128 = available
    // C * (128 * sectors_per_cluster + 1) / 128 = available
    let approx_clusters = (available_sectors * 128) / (128 * sectors_per_cluster as u64 + 1);
    
    let fat_length_bytes = (approx_clusters + 2) * 4;
    let fat_length_sectors = (fat_length_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE;
    
    let cluster_heap_offset = fat_offset + fat_length_sectors as u32;
    
    // Ensure 128 sector alignment for cluster heap (optional but good for performance)
    let extra_align = (128 - (cluster_heap_offset % 128)) % 128;
    let cluster_heap_offset = cluster_heap_offset + extra_align;
    
    let usable_sectors_for_heap = total_sectors.saturating_sub(cluster_heap_offset as u64);
    let cluster_count = (usable_sectors_for_heap / sectors_per_cluster as u64) as u32;
    
    if cluster_count < 10 {
        return Err(invalid_input("Volume too small for ExFAT data"));
    }

    // 1 bit per cluster
    let bitmap_bytes = (cluster_count + 7) / 8;
    let bitmap_clusters_count = (bitmap_bytes + cluster_size - 1) / cluster_size;
    
    let upcase_bytes = 128 * 1024; // 128 KB
    let upcase_clusters_count = (upcase_bytes + cluster_size - 1) / cluster_size;

    Ok(ExFatGeometry {
        total_sectors,
        fat_offset,
        fat_length: fat_length_sectors as u32,
        cluster_heap_offset,
        cluster_count,
        bitmap_cluster: 2,
        bitmap_clusters_count,
        upcase_cluster: 2 + bitmap_clusters_count,
        upcase_clusters_count,
        root_dir_cluster: 2 + bitmap_clusters_count + upcase_clusters_count,
        sectors_per_cluster,
    })
}

fn boot_checksum(sectors: &[u8]) -> u32 {
    let mut checksum: u32 = 0;
    for (i, &b) in sectors.iter().enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        checksum = checksum.rotate_right(1).wrapping_add(b as u32);
    }
    checksum
}

fn checksum_upcase(data: &[u8]) -> u32 {
    let mut checksum: u32 = 0;
    for &b in data {
        checksum = checksum.rotate_right(1).wrapping_add(b as u32);
    }
    checksum
}

pub fn format_exfat<W: Write + Seek>(writer: &mut W, volume_size: u64) -> io::Result<()> {
    let geometry = calculate_geometry(volume_size)?;
    let volume_id = generate_volume_id()?;
    let cluster_size = (SECTOR_SIZE * geometry.sectors_per_cluster as u64) as u32;

    // 1. Build Up-Case Table
    let mut upcase_table = vec![0u8; 128 * 1024];
    for i in 0..65536u32 {
        let mut mapped = i as u16;
        if mapped >= b'a' as u16 && mapped <= b'z' as u16 {
            mapped -= 32;
        }
        LittleEndian::write_u16(&mut upcase_table[(i as usize) * 2..], mapped);
    }
    let upcase_checksum = checksum_upcase(&upcase_table);
    
    // 2. Build Boot Record layout (12 sectors)
    let mut boot_region = vec![0u8; 12 * 512];
    
    // Jump Instruction (EB + 76 + 90)
    boot_region[0] = 0xEB;
    boot_region[1] = 0x76;
    boot_region[2] = 0x90;
    // Name "EXFAT   "
    boot_region[3..11].copy_from_slice(b"EXFAT   ");
    
    // PartitionOffset
    LittleEndian::write_u64(&mut boot_region[64..72], 0);
    // VolumeLength
    LittleEndian::write_u64(&mut boot_region[72..80], geometry.total_sectors);
    // FatOffset
    LittleEndian::write_u32(&mut boot_region[80..84], geometry.fat_offset);
    // FatLength
    LittleEndian::write_u32(&mut boot_region[84..88], geometry.fat_length);
    // ClusterHeapOffset
    LittleEndian::write_u32(&mut boot_region[88..92], geometry.cluster_heap_offset);
    // ClusterCount
    LittleEndian::write_u32(&mut boot_region[92..96], geometry.cluster_count);
    // FirstClusterOfRootDirectory
    LittleEndian::write_u32(&mut boot_region[96..100], geometry.root_dir_cluster);
    // VolumeSerialNumber
    LittleEndian::write_u32(&mut boot_region[100..104], volume_id);
    // FileSystemRevision (1.00)
    LittleEndian::write_u16(&mut boot_region[104..106], 0x0100);
    // VolumeFlags
    LittleEndian::write_u16(&mut boot_region[106..108], 0x0000); // clear
    // BytesPerSectorShift
    boot_region[108] = 9; // 512 = 2^9
    // SectorsPerClusterShift
    boot_region[109] = geometry.sectors_per_cluster.trailing_zeros() as u8;
    // NumberOfFats
    boot_region[110] = 1;
    // DriveSelect
    boot_region[111] = 0x80;
    // PercentInUse
    boot_region[112] = 0;
    
    // Signature
    boot_region[510] = 0x55;
    boot_region[511] = 0xAA;
    
    // Extended Boot Sectors and OEM Parameter Record
    for s in 1..=10 {
        let offset = s * 512;
        boot_region[offset + 510] = 0x55;
        boot_region[offset + 511] = 0xAA;
    }
    
    // Compute checksum
    let boot_chs = boot_checksum(&boot_region[0..11*512]);
    let chs_bytes = boot_chs.to_le_bytes();
    // Fill sector 11 with checksums
    {
        let offset = 11 * 512;
        for i in (0..512).step_by(4) {
            boot_region[offset + i + 0] = chs_bytes[0];
            boot_region[offset + i + 1] = chs_bytes[1];
            boot_region[offset + i + 2] = chs_bytes[2];
            boot_region[offset + i + 3] = chs_bytes[3];
        }
    }
    
    // Write Main Boot Record
    writer.seek(SeekFrom::Start(0))?;
    writer.write_all(&boot_region)?;
    
    // Write Backup Boot Record (sectors 12-23)
    writer.seek(SeekFrom::Start(12 * 512))?;
    writer.write_all(&boot_region)?;
    
    // 3. Initialize FAT in chunks (to fix out-of-memory issue)
    writer.seek(SeekFrom::Start(geometry.fat_offset as u64 * 512))?;
    
    let mut fat_chunk = vec![0u8; 1024 * 1024]; // 1MB chunk
    let mut fat_written = 0;
    let fat_total_bytes = geometry.fat_length as u64 * 512;
    
    let last_allocated = geometry.root_dir_cluster;
    let mut current_cluster = 0u32;
    
    while fat_written < fat_total_bytes {
        let to_write = std::cmp::min(fat_chunk.len() as u64, fat_total_bytes - fat_written) as usize;
        // Zero out the chunk
        for b in &mut fat_chunk[..to_write] { *b = 0; }
        
        for i in 0..(to_write / 4) {
            let val = if current_cluster == 0 {
                0xFFFFFFF8 // Media
            } else if current_cluster == 1 {
                0xFFFFFFFF // Reserved
            } else if current_cluster >= 2 && current_cluster <= last_allocated {
                let mut next_val = current_cluster + 1;
                // End of chain
                if current_cluster == geometry.bitmap_cluster + geometry.bitmap_clusters_count - 1 
                   || current_cluster == geometry.upcase_cluster + geometry.upcase_clusters_count - 1 
                   || current_cluster == geometry.root_dir_cluster {
                    next_val = 0xFFFFFFFF;
                }
                next_val
            } else {
                0 // Unused
            };
            LittleEndian::write_u32(&mut fat_chunk[i * 4..(i + 1) * 4], val);
            current_cluster += 1;
        }
        
        writer.write_all(&fat_chunk[..to_write])?;
        fat_written += to_write as u64;
    }
    
    // Write zeros for alignment gap between FAT and Cluster Heap
    let fat_end = geometry.fat_offset as u64 * 512 + fat_total_bytes;
    let heap_start = geometry.cluster_heap_offset as u64 * 512;
    if heap_start > fat_end {
        let mut gap = heap_start - fat_end;
        let zero_chunk = vec![0u8; 65536]; // 64K buffer
        while gap > 0 {
            let to_write = std::cmp::min(gap, zero_chunk.len() as u64) as usize;
            writer.write_all(&zero_chunk[..to_write])?;
            gap -= to_write as u64;
        }
    }

    // 4. Write Bitmap
    let bitmap_pos = geometry.cluster_heap_offset as u64 * 512 + (geometry.bitmap_cluster - 2) as u64 * cluster_size as u64;
    writer.seek(SeekFrom::Start(bitmap_pos))?;
    let bitmap_size_bytes = (geometry.cluster_count + 7) / 8;
    let mut bitmap = vec![0u8; bitmap_size_bytes as usize];
    
    // Set bits for allocated clusters
    for c in 2..=last_allocated {
        let bit_index = (c - 2) as usize;
        bitmap[bit_index / 8] |= 1 << (bit_index % 8);
    }
    
    let bitmap_total_bytes = geometry.bitmap_clusters_count as u64 * cluster_size as u64;
    writer.write_all(&bitmap)?;
    // Pad to cluster size boundary
    if bitmap_total_bytes > bitmap.len() as u64 {
        let mut gap = bitmap_total_bytes - bitmap.len() as u64;
        let zero_chunk = vec![0u8; 65536];
        while gap > 0 {
            let to_write = std::cmp::min(gap, zero_chunk.len() as u64) as usize;
            writer.write_all(&zero_chunk[..to_write])?;
            gap -= to_write as u64;
        }
    }
    
    // 5. Write Up-case Table
    let upcase_pos = geometry.cluster_heap_offset as u64 * 512 + (geometry.upcase_cluster - 2) as u64 * cluster_size as u64;
    writer.seek(SeekFrom::Start(upcase_pos))?;
    writer.write_all(&upcase_table)?;
    let upcase_total_bytes = geometry.upcase_clusters_count as u64 * cluster_size as u64;
    if upcase_total_bytes > upcase_table.len() as u64 {
        let mut gap = upcase_total_bytes - upcase_table.len() as u64;
        let zero_chunk = vec![0u8; 65536];
        while gap > 0 {
            let to_write = std::cmp::min(gap, zero_chunk.len() as u64) as usize;
            writer.write_all(&zero_chunk[..to_write])?;
            gap -= to_write as u64;
        }
    }
    
    // 6. Write Root Directory
    let root_pos = geometry.cluster_heap_offset as u64 * 512 + (geometry.root_dir_cluster - 2) as u64 * cluster_size as u64;
    writer.seek(SeekFrom::Start(root_pos))?;
    
    let mut root_dir = vec![0u8; cluster_size as usize];
    
    // Entry 1: Volume Label (0x83)
    root_dir[0] = 0x83;
    root_dir[1] = 9; // Character count
    // "NOXCIPHER" in UTF-16
    let label = b"NOXCIPHER";
    for i in 0..9 {
        LittleEndian::write_u16(&mut root_dir[2 + i * 2..], label[i] as u16);
    }
    
    // Entry 2: Allocation Bitmap (0x81)
    let bitmap_entry = &mut root_dir[32..64];
    bitmap_entry[0] = 0x81;
    bitmap_entry[1] = 0; // Flags
    LittleEndian::write_u32(&mut bitmap_entry[20..24], geometry.bitmap_cluster);
    LittleEndian::write_u64(&mut bitmap_entry[24..32], bitmap_size_bytes as u64);
    
    // Entry 3: Up-case Table (0x82)
    let upcase_entry = &mut root_dir[64..96];
    upcase_entry[0] = 0x82;
    upcase_entry[1] = 0; // Reserved
    LittleEndian::write_u32(&mut upcase_entry[4..8], upcase_checksum);
    LittleEndian::write_u32(&mut upcase_entry[20..24], geometry.upcase_cluster);
    LittleEndian::write_u64(&mut upcase_entry[24..32], upcase_table.len() as u64);
    
    writer.write_all(&root_dir)?;
    
    Ok(())
}
