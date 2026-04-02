package com.noxcipher.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query

@Dao
interface VolumeDao {
    @Query("SELECT * FROM volumes")
    fun getAllMountedVolumes(): List<VolumeEntity>

    @Insert
    fun insertVolume(volume: VolumeEntity)
}
