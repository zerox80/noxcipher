package com.noxcipher.domain.model

data class VolumeInfo(
    val id: String,
    val name: String,
    val isMounted: Boolean,
    val totalSpace: Long,
    val freeSpace: Long
)
