package com.noxcipher.domain.usecase

import com.noxcipher.domain.repository.VolumeRepository
import com.noxcipher.domain.model.VolumeInfo

class MountVolumeUseCase(private val repository: VolumeRepository) {
    suspend operator fun invoke(uri: String, password: ByteArray): Result<VolumeInfo> {
        return repository.mountVolume(uri, password)
    }
}
