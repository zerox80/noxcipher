package com.noxcipher.domain.repository

import com.noxcipher.domain.model.VolumeInfo

interface VolumeRepository {
    suspend fun mountVolume(uri: String, password: ByteArray): Result<VolumeInfo>
    suspend fun unmountVolume(volumeId: String): Result<Unit>
}
