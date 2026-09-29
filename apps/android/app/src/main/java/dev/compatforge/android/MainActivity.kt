package dev.compatforge.android

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.view.Gravity
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val status = TextView(this).apply {
            gravity = Gravity.CENTER_VERTICAL
            textSize = 17f
            setPadding(40, 40, 40, 40)
            text = "CompatForge Android\n正在检查本机 Core…"
        }
        setContentView(status)
        Thread {
            val result = runCatching {
                val report = NativeProbe.readCapabilityReport()
                val pageSize = Os.sysconf(OsConstants._SC_PAGESIZE)
                "CompatForge Android\n" +
                    "设备：${Build.MODEL}\n" +
                    "ABI：${Build.SUPPORTED_ABIS.joinToString()}\n" +
                    "应用 UID：${Process.myUid()}\n" +
                    "内存页：$pageSize 字节\n" +
                    "Rust Core：${if (report.contains("\"android\"")) "Android probe 成功" else "返回平台不匹配"}\n\n" +
                    "Windows 运行时尚未接入；7-Zip 运行验收尚未开始。"
            }.getOrElse { error -> "CompatForge Android\nCore 检查失败：${error.message}" }
            runOnUiThread { status.text = result }
        }.start()
    }
}
