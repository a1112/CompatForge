package dev.compatforge.android

internal object NativeProbe {
    init {
        System.loadLibrary("compatforge_ffi")
        System.loadLibrary("compatforge_jni")
    }

    private external fun readCapabilityReportBytes(): ByteArray
    private external fun inspectExecutableBytes(path: String): ByteArray

    fun readCapabilityReport(): String =
        String(readCapabilityReportBytes(), Charsets.UTF_8)

    fun inspectExecutable(path: String): String =
        String(inspectExecutableBytes(path), Charsets.UTF_8)
}
