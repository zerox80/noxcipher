package com.noxcipher.data.local

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "volumes")
data class VolumeEntity(
    @PrimaryKey val id: String,
    val name: String,
    val pathUri: String,
    val lastMounted: Long
)
