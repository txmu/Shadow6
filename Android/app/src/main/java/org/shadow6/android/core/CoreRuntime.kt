package org.shadow6.android.core

import android.content.Context
import org.shadow6.android.BuildConfig
import java.io.File
import java.nio.file.Files
import org.shadow6.android.security.checkedProcess
import org.shadow6.android.security.writePrivateConfig
import java.util.concurrent.TimeUnit

enum class CoreEngine(val assetName: String, val transport: String) {
    GO("libshadow6_go.so", "kcp"), RUST("libshadow6_rust.so", "quic")
}
enum class AccessMode { NON_ROOT, ROOT }

data class CoreStatus(
    val running: Boolean = false,
    val engine: CoreEngine = CoreEngine.GO,
    val mode: AccessMode = AccessMode.NON_ROOT,
    val role: CoreRole = CoreRole.BROKER,
    val host: String = LOOPBACK_HOST,
    val port: Int = DEFAULT_PORT,
    val pid: Long? = null,
    val startedAtMillis: Long? = null,
    val detail: String = "",
) {
    val endpoint: String get() = if (port > 0) "$host:$port" else host

    companion object {
        const val LOOPBACK_HOST = "127.0.0.1"
        const val DEFAULT_PORT = 4433
    }
}

class CoreRuntime(private val context: Context) {
    @Volatile private var process: Process? = null
    private var outputThread: Thread? = null
    private val outputLock = Any()
    private var boundedOutput = ""
    @Volatile private var current = CoreStatus()

    fun available(engine: CoreEngine): Boolean = (when (engine) {
        CoreEngine.GO -> BuildConfig.INCLUDE_GO_CORE
        CoreEngine.RUST -> BuildConfig.INCLUDE_RUST_CORE
    }) && File(context.applicationInfo.nativeLibraryDir, engine.assetName).let { file ->
        file.isFile && !Files.isSymbolicLink(file.toPath())
    }

    @Synchronized
    fun status(): CoreStatus {
        val active = process
        if (active != null && !active.isAlive) {
            val exitCode = runCatching { active.exitValue() }.getOrDefault(-1)
            val output = synchronized(outputLock) { boundedOutput.trim() }
            process = null
            current = current.copy(
                running = false,
                port = 0,
                pid = null,
                detail = output.ifBlank { "Core exited with code $exitCode" },
            )
        }
        if (current.running && current.role == CoreRole.CLIENT) {
            val output = synchronized(outputLock) { boundedOutput }
            parseClientProxyPort(output)?.let { port ->
                if (current.port != port || current.host != CoreStatus.LOOPBACK_HOST) {
                    current = current.copy(
                        host = CoreStatus.LOOPBACK_HOST,
                        port = port,
                        detail = "Client Core is active • local proxy ${CoreStatus.LOOPBACK_HOST}:$port",
                    )
                }
            }
        }
        return current
    }

    /** Both Cores require config ownership to match their effective UID.
     * App-owned configuration cannot be passed to a UID-0 Core safely. */
    // A future owner-matched root lifecycle would probe with
    // ProcessBuilder("su", "0", "/system/bin/id", "-u"); root mode remains disabled.
    fun rootAvailable(): Boolean = false

    private fun writeConfig(profile: CoreProfile, engine: CoreEngine): File {
        // Keep credentials and runtime configuration in app-private storage.
        val directory = context.filesDir.canonicalFile
        val json = profile.toJson(engine).toString() + "\n"
        require(json.toByteArray(Charsets.UTF_8).size <= MAX_CONFIG_BYTES)
        return writePrivateConfig(directory, "core-config.json", json.toByteArray(Charsets.UTF_8))
    }

    private fun drainOutput(active: Process) {
        outputThread = Thread({
            runCatching {
                active.inputStream.use { input ->
                    val buffer = ByteArray(1024)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        val chunk = String(buffer, 0, count, Charsets.UTF_8)
                        synchronized(outputLock) {
                            if (process !== active) return@Thread
                            boundedOutput = (boundedOutput + chunk).takeLast(MAX_OUTPUT_CHARS)
                        }
                    }
                }
            }
        }, "shadow6-core-output").apply { isDaemon = true; start() }
    }

    @Synchronized
    fun start(engine: CoreEngine, mode: AccessMode, profile: CoreProfile): CoreStatus {
        require(available(engine)) { "Core was excluded by the selected build parameters" }
        require(mode == AccessMode.NON_ROOT) { "Root mode needs a separate owner-matched configuration lifecycle and is not supported" }
        profile.toJson(engine)
        if (profile.role == CoreRole.BROKER) require(profile.listenPort >= MIN_PORT) { "Non-root listening ports must be 1024–65535" }
        stop()
        val config = writeConfig(profile, engine)
        val binary = File(context.applicationInfo.nativeLibraryDir, engine.assetName)
        require(binary.isFile) { "Packaged ${engine.name} Core is unavailable for this ABI" }
        checkedProcess(listOf(binary.absolutePath, "--config", config.absolutePath, "--check-config"))
        val coreArgs = listOf(binary.absolutePath, "--config", config.absolutePath)
        synchronized(outputLock) { boundedOutput = "" }
        val active = ProcessBuilder(coreArgs).redirectErrorStream(true).start()
        process = active
        drainOutput(active)
        if (active.waitFor(STARTUP_PROBE_MILLIS, TimeUnit.MILLISECONDS)) {
            process = null
            outputThread?.join(100)
            val output = synchronized(outputLock) { boundedOutput.trim() }
            throw IllegalStateException(output.ifBlank { "Core exited with code ${active.exitValue()}" })
        }
        current = CoreStatus(
            running = true,
            engine = engine,
            mode = mode,
            role = profile.role,
            host = when (profile.role) {
                CoreRole.BROKER -> profile.listenHost
                CoreRole.CLIENT -> CoreStatus.LOOPBACK_HOST
                CoreRole.AGENT -> profile.endpoint().substringBeforeLast(':', profile.endpoint())
            },
            port = if (profile.role == CoreRole.BROKER) profile.listenPort else 0,
            // Android's java.lang.Process API does not expose the child PID
            // consistently across supported releases.
            pid = null,
            startedAtMillis = System.currentTimeMillis(),
            detail = "${profile.role.name.lowercase().replaceFirstChar(Char::uppercase)} Core is active • ${profile.endpoint()}",
        )
        return current
    }

    @Synchronized fun generateIdentity(engine: CoreEngine): CoreIdentity {
        require(available(engine)) { "Core was excluded by the selected build parameters" }
        val binary = File(context.applicationInfo.nativeLibraryDir, engine.assetName)
        require(binary.isFile) { "Packaged ${engine.name} Core is unavailable for this ABI" }
        val bytes = checkedProcess(listOf(binary.absolutePath, "--gen-key"))
        val output = String(bytes)
        val privateKey = Regex("Private Key \\(Hex\\):\\s*([0-9a-fA-F]{64,128})").find(output)?.groupValues?.get(1)
        val publicKey = Regex("Public Key \\(Hex\\):\\s*([0-9a-fA-F]{64})").find(output)?.groupValues?.get(1)
        require(privateKey != null && publicKey != null) { "Core returned an invalid key pair" }
        return CoreIdentity(privateKey.lowercase(), publicKey.lowercase())
    }

    @Synchronized
    fun stop(): CoreStatus {
        val active = process
        process = null
        active?.destroy()
        active?.waitFor(2, TimeUnit.SECONDS)
        if (active?.isAlive == true) { active.destroyForcibly(); active.waitFor(1, TimeUnit.SECONDS) }
        runCatching { active?.inputStream?.close() }
        outputThread?.interrupt()
        outputThread?.join(1000)
        outputThread = null
        current = current.copy(running = false, port = 0, pid = null, startedAtMillis = null, detail = "Core stopped")
        return current
    }

    companion object {
        const val MIN_PORT = 1024
        const val MAX_PORT = 65535
        private const val MAX_CONFIG_BYTES = 1_048_576
        private const val MAX_OUTPUT_CHARS = 4096
        private const val STARTUP_PROBE_MILLIS = 350L
        private val CLIENT_PROXY_PATTERN = Regex("\\[Client] Secure local proxy listening on 127\\.0\\.0\\.1:([0-9]{1,5})(?:\\s|$)")

        internal fun parseClientProxyPort(output: String): Int? =
            CLIENT_PROXY_PATTERN.findAll(output).lastOrNull()?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it in 1..MAX_PORT }
    }
}
