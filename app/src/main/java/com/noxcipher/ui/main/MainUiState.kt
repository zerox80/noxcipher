package com.noxcipher.ui.main

data class MainUiState(
    val isLoading: Boolean = false,
    val mountedVolumes: List<com.noxcipher.domain.model.VolumeInfo> = emptyList(),
    val error: String? = null
)
