package com.noxcipher

import android.app.Application
import android.os.Environment
import android.util.Log
import android.widget.Toast
import java.io.File
import java.io.FileWriter
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class NoxCipherApp : Application() {

    override fun onCreate() {
        super.onCreate()
        
        try {
            if (RustNative.isInitialized) {
                RustNative.initLogger()
            } else {
                Log.w("NoxCipherApp", "Rust library not initialized; skipping logger setup")
            }
        } catch (t: Throwable) {
            Log.e("NoxCipherApp", "Failed to init rust logger", t)
        }
        
        // Setup global exception handler
        val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            handleUncaughtException(thread, throwable)
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }

    private fun handleUncaughtException(thread: Thread, throwable: Throwable) {
        val stackTrace = StringWriter()
        throwable.printStackTrace(PrintWriter(stackTrace))
        val errorReport = StringBuilder()
            .append("************ CAUSE OF ERROR ************\n\n")
            .append(stackTrace.toString())
            .append("\n************ END OF ERROR ************\n")
            .toString()

        Log.e("NoxCipherApp", errorReport)

        try {
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val filename = "crash_$timestamp.txt"
            val dir = getExternalFilesDir(null)
            if (dir != null) {
                val file = File(dir, filename)
                FileWriter(file).use { it.write(errorReport) }
                Log.d("NoxCipherApp", "Crash log saved to ${file.absolutePath}")
            } else {
                Log.e("NoxCipherApp", "External files dir is null, cannot save crash log")
            }
        } catch (e: Exception) {
            Log.e("NoxCipherApp", "Failed to save crash log", e)
        }
    }
}
