package org.shadow6.android.gate

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.shadow6.android.BuildConfig
import java.io.File
import org.shadow6.android.security.checkedProcess
import org.shadow6.android.security.writePrivateConfig
import java.net.InetAddress
import java.util.concurrent.TimeUnit

data class GateProfile(
    val enabled: Boolean = false,
    val localPort: Int = 1086,
    val remoteHost: String = "",
    val upstream: String = "127.0.0.1:4433",
    val privateKey: String = "",
    val peerPublicKey: String = "",
    val openMode: String = "unconditional",
)

/** Runs the packaged Gate directly from the APK; no Termux, Tailscale, or shell is involved. */
class GateRuntime(private val context: Context) {
    @Volatile private var process: Process? = null
    private var outputThread: Thread? = null
    fun available() = BuildConfig.INCLUDE_GATE && File(context.applicationInfo.nativeLibraryDir, "libshadow6_gate.so").isFile
    fun running() = process?.isAlive == true

    @Synchronized fun start(profile: GateProfile) {
        require(profile.enabled) { "Gate remains disabled until explicitly enabled" }
        require(available()) { "Gate was excluded or is unavailable for this ABI" }
        require(profile.localPort in 1024..65535 && profile.remoteHost.matches(Regex("^[0-9a-fA-F:.]{2,45}$"))) { "Invalid Gate endpoint" }
        require(':' in profile.remoteHost || profile.remoteHost.matches(Regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))) { "Gate requires a numeric IP address" }
        InetAddress.getByName(profile.remoteHost)
        require(profile.upstream == "127.0.0.1:4433" && profile.openMode == "unconditional") { "Unsupported Android Gate profile" }
        require(profile.privateKey.matches(Regex("^[0-9a-fA-F]{64}([0-9a-fA-F]{64})?$")) && profile.peerPublicKey.matches(Regex("^[0-9a-fA-F]{64}$"))) { "Invalid Gate identity" }
        stop()
        val json=JSONObject().put("version",1).put("enabled",true).put("role","client").put("listen_host","127.0.0.1").put("listen_port",profile.localPort)
            .put("upstream",profile.upstream).put("remote_host",profile.remoteHost).put("private_key",profile.privateKey)
            .put("upstreams",JSONArray()).put("remote_hosts",JSONArray()).put("load_balance","round_robin")
            .put("peer_public_keys",JSONArray().put(profile.peerPublicKey)).put("protocol",JSONArray().put("tcp").put("udp"))
            .put("open_mode",profile.openMode).put("allowed_cidrs",JSONArray()).put("windows",JSONArray())
            .put("mtd",JSONObject().put("enabled",true).put("period_seconds",300).put("min_port",49152).put("max_port",65535).put("grace_seconds",15))
            .put("limits",JSONObject().put("max_connections",64).put("max_frame_bytes",65507).put("idle_seconds",120)).toString()+"\n"
        val config = writePrivateConfig(context.filesDir, "gate-config.json", json.toByteArray(Charsets.UTF_8))
        val binary=File(context.applicationInfo.nativeLibraryDir,"libshadow6_gate.so");require(binary.isFile)
        checkedProcess(listOf(binary.absolutePath,"--config",config.absolutePath,"--check-config"))
        val active = ProcessBuilder(binary.absolutePath,"--config",config.absolutePath).redirectErrorStream(true).start()
        process = active
        outputThread = Thread({ runCatching { active.inputStream.use { input ->
            val buffer=ByteArray(1024)
            while(input.read(buffer)>=0) { if (Thread.currentThread().isInterrupted) break }
        } } },"shadow6-gate-output").apply{isDaemon=true;start()}
        if (active.waitFor(350, TimeUnit.MILLISECONDS)) {
            stop()
            error("Gate exited during startup")
        }
    }
    @Synchronized fun stop() {
        val active = process
        process = null
        active?.destroy()
        active?.waitFor(2, TimeUnit.SECONDS)
        if (active?.isAlive == true) { active.destroyForcibly(); active.waitFor(1, TimeUnit.SECONDS) }
        runCatching { active?.inputStream?.close() }
        outputThread?.interrupt()
        outputThread?.join(1000)
        outputThread = null
    }
}
object GateController {
    @Volatile private var instance: GateRuntime? = null
    fun runtime(context: Context): GateRuntime = instance ?: synchronized(this) { instance ?: GateRuntime(context.applicationContext).also { instance = it } }
}
