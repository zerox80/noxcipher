package com.noxcipher.data.repository

import com.noxcipher.domain.model.VolumeInfo
import com.noxcipher.domain.repository.VolumeRepository

class VolumeRepositoryImpl : VolumeRepository {
    override suspend fun mountVolume(uri: String, password: ByteArray): Result<VolumeInfo> {
        // TODO: Call Rust JNI here
        return Result.success(VolumeInfo("1", "USB_Drive", true, 1000L, 500L))
    }

    override suspend fun unmountVolume(volumeId: String): Result<Unit> {
        // TODO: Call Rust JNI here
        return Result.success(Unit)
    }
}
