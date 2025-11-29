package com.noxcipher
    
interface NativeReadCallback {
    fun read(offset: Long, length: Int): ByteArray
}
