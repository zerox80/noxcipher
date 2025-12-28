package com.noxcipher
    
interface NativeReadCallback {
    fun read(offset: Long, buffer: java.nio.ByteBuffer): Int
}
