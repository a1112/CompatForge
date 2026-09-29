package dev.compatforge.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.MessageDigest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SevenZipInspectionTest {
    @Test
    fun officialSevenZipInstallerIsInspectedByAndroidCore() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val assets = instrumentation.context.assets
        assertTrue("pass -PcompatforgeSevenZip to include the fixed asset", assets.list("")!!.contains("7z2601-x64.exe"))

        val file = File(instrumentation.targetContext.filesDir, "7z2601-x64.exe")
        try {
            assets.open("7z2601-x64.exe").use { input -> file.outputStream().use { input.copyTo(it) } }
            val digest = MessageDigest.getInstance("SHA-256").digest(file.readBytes())
                .joinToString("") { "%02x".format(it) }
            assertEquals("d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d", digest)
            val report = JSONObject(NativeProbe.inspectExecutable(file.absolutePath))
            assertEquals("x86_64", report.getString("architecture"))
            assertEquals("windowsGui", report.getString("subsystem"))
            assertEquals("sha256:$digest", report.getString("fileDigest"))
            assertTrue(report.getLong("fileSizeBytes") > 0)
        } finally {
            file.delete()
        }
    }
}
