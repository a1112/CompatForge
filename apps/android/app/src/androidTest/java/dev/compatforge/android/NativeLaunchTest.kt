package dev.compatforge.android

import android.os.Build
import android.os.Process
import android.system.Os
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NativeLaunchTest {
    private val launcherName = "libcompatforge_exec_probe.so"

    @Test
    fun rustCoreRunsUnderOrdinaryAppUid() {
        assertTrue("ARM64 ABI required", Build.SUPPORTED_ABIS.contains("arm64-v8a"))
        assertTrue("ordinary app UID required", Process.myUid() >= Process.FIRST_APPLICATION_UID)
        val pageSize = Os.sysconf(OsConstants._SC_PAGESIZE)
        assertTrue("unexpected page size $pageSize", pageSize == 4096L || pageSize == 16384L)
        val report = NativeProbe.readCapabilityReport()
        assertTrue("Rust probe did not report Android", report.contains("\"android\""))
    }

    @Test
    fun packagedLauncherRunsUnderAppUidButWritableCopyIsDenied() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val packaged = File(context.applicationInfo.nativeLibraryDir, launcherName)
        assertTrue("packaged launcher is missing: $packaged", packaged.isFile)
        val process = ProcessBuilder(packaged.absolutePath).redirectErrorStream(true).start()
        assertTrue("packaged launcher timed out", process.waitFor(10, TimeUnit.SECONDS))
        val output = process.inputStream.bufferedReader().readText().trim()
        assertEquals("packaged launcher failed: $output", 0, process.exitValue())
        assertEquals("compatforge-uid=${Process.myUid()}", output)

        val writableCopy = File(context.filesDir, launcherName)
        try {
            packaged.copyTo(writableCopy, overwrite = true)
            assertTrue(writableCopy.setExecutable(true, true))
            val failure = runCatching { ProcessBuilder(writableCopy.absolutePath).start() }.exceptionOrNull()
            assertTrue("writable app-private executable unexpectedly launched", failure is java.io.IOException)
        } finally {
            writableCopy.delete()
        }
    }
}
