package org.shadow6.android.core

import android.content.Context
import org.shadow6.android.BuildConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import org.shadow6.android.security.checkedProcess
import org.shadow6.android.security.StrictJson
import org.shadow6.android.security.writePrivateConfig
import java.util.concurrent.TimeUnit

enum class CoreEngine(val assetName: String, val transport: String, val profileId: String) {
    GO("libshadow6_go.so", "kcp", "go-kcp"), RUST("libshadow6_rust.so", "quic", "rust-quic"),
    D("libshadow6_d.so", "secure-stream", "d-secure-stream"), NIM("libshadow6_nim.so", "webrtc", "nim-webrtc")
}
data class CoreStatus(
    val running: Boolean = false,
    val engine: CoreEngine = CoreEngine.GO,
    val role: CoreRole = CoreRole.BROKER,
    val host: String = LOOPBACK_HOST,
    val port: Int = DEFAULT_PORT,
    val pid: Long? = null,
    val startedAtMillis: Long? = null,
    val detail: String = "",
    val observation: RuntimeObservation? = null,
) {
    val endpoint: String get() = if (port > 0) "$host:$port" else host
    val access: String get() = if (isLoopbackHost(host)) "loopback" else "network"

    companion object {
        const val LOOPBACK_HOST = "127.0.0.1"
        const val DEFAULT_PORT = 4433

        private fun isLoopbackHost(value: String): Boolean {
            val trimmed = value.trim()
            val host = if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
                trimmed.substring(1, trimmed.length - 1)
            } else {
                trimmed
            }
            if (host.equals("::1", ignoreCase = true) || host.equals("localhost", ignoreCase = true)) return true
            val octets = host.split('.')
            return octets.size == 4 && octets[0] == "127" && octets.all { octet ->
                val number = octet.toIntOrNull()
                octet.isNotEmpty() && octet.all(Char::isDigit) && number != null && number in 0..255
            }
        }
    }
}

/** Android emits the canonical RuntimeObservation field set from Deployment/runtime_observation.py. */
data class ObservedProcessIdentity(val pid: Long, val processIdentity: String) {
    fun toJson() = JSONObject().put("pid", pid).put("processIdentity", processIdentity)
}

data class RuntimeObservation(
    val core: String,
    val profile: String,
    val nativeTransport: String,
    val applicationBoundary: String,
    val observedAt: Long,
    val pid: Long,
    val processIdentity: String,
    val processes: List<ObservedProcessIdentity>,
    val nativeEndpoints: List<Map<String, Any?>> = emptyList(),
    val endpoints: List<Map<String, Any?>> = emptyList(),
    val endpoint: Map<String, Any?>? = null,
    val readiness: String,
    val transportReadiness: String = "unknown",
    val applicationReadiness: String = "unknown",
) {
    fun toJson(): JSONObject = JSONObject()
        .put("observedAt", observedAt).put("pid", pid).put("processIdentity", processIdentity)
        .put("processes", JSONArray().also { array -> processes.forEach { array.put(it.toJson()) } })
        .put("nativeEndpoints", jsonArray(nativeEndpoints)).put("endpoints", jsonArray(endpoints))
        .put("endpoint", endpoint?.let { JSONObject(it) } ?: JSONObject.NULL).put("readiness", readiness)
        .put("transportReadiness", transportReadiness).put("applicationReadiness", applicationReadiness)

    companion object {
        private fun jsonArray(items: List<Map<String, Any?>>) = JSONArray().also { array ->
            items.forEach { array.put(JSONObject(it)) }
        }
    }
}

data class ApplicationSessionObservation(
    val schema: String = "shadow6.android-application-session.v1",
    val core: String,
    val profile: String,
    val nativeTransport: String,
    val applicationBoundary: String,
    val status: String,
    val connectMillis: Long? = null,
    val durationMillis: Long? = null,
    val bytesSent: Int = 0,
    val bytesReceived: Int = 0,
    val sentSha256: String? = null,
    val receivedSha256: String? = null,
    val readiness: String = "unavailable",
    val reason: String? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("schema", schema).put("core", core).put("profile", profile)
        .put("nativeTransport", nativeTransport).put("applicationBoundary", applicationBoundary)
        .put("status", status).put("connectMillis", connectMillis).put("durationMillis", durationMillis)
        .put("bytesSent", bytesSent).put("bytesReceived", bytesReceived)
        .put("sentSha256", sentSha256).put("receivedSha256", receivedSha256)
        .put("readiness", readiness).put("reason", reason)
}

data class CoreSetupObservation(
    val core: String,
    val profile: String,
    val nativeTransport: String,
    val applicationBoundary: String,
    val profileContractDigest: String,
    val role: String,
    val endpoint: String,
    val configurationBytes: Int,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("core", core).put("profile", profile).put("nativeTransport", nativeTransport)
        .put("applicationBoundary", applicationBoundary).put("profileContractDigest", profileContractDigest)
        .put("role", role).put("endpoint", endpoint).put("configurationBytes", configurationBytes)
        .put("secretsIncluded", false)
}

class CoreRuntime(private val context: Context) {
    @Volatile private var process: Process? = null
    private var outputThread: Thread? = null
    private var ownedChild: ObservedProcessIdentity? = null
    private val outputLock = Any()
    private var boundedOutput = ""
    @Volatile private var current = CoreStatus()
    @Volatile private var setupReceipt: CoreSetupObservation? = null

    fun nativeProfiles(): List<NativeProfileDescriptor> =
        NativeProfileCatalog.load(context.assets.open(NATIVE_PROFILE_ASSET))

    fun profileAvailability(): List<NativeProfileAvailability> {
        val catalog = nativeProfiles()
        return NativeProfileCatalog.availability(catalog,
            artifactPresent = { profile -> nativeArtifact(profile).let { it.isFile && !Files.isSymbolicLink(it.toPath()) } },
            runtimeBound = { profile -> CoreEngine.entries.any { it.profileId == profile.id } },
        )
    }

    private fun nativeArtifact(profile: NativeProfileDescriptor): File {
        val artifact = profile.artifact.substringAfterLast('/')
        val libraryName = "lib" + artifact.replaceFirst("shadow6-", "shadow6_") + ".so"
        return File(context.applicationInfo.nativeLibraryDir, libraryName)
    }

    fun available(engine: CoreEngine): Boolean = (when (engine) {
        CoreEngine.GO -> BuildConfig.INCLUDE_GO_CORE
        CoreEngine.RUST -> BuildConfig.INCLUDE_RUST_CORE
        CoreEngine.D -> BuildConfig.INCLUDE_D_CORE && File(context.applicationInfo.nativeLibraryDir, engine.assetName).isFile
        CoreEngine.NIM -> BuildConfig.INCLUDE_NIM_CORE
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
            ownedChild = null
            current = current.copy(
                running = false,
                port = 0,
                pid = null,
                detail = output.ifBlank { "Core exited with code $exitCode" },
                observation = null,
            )
        }
        if (current.running && ownedChild?.let { linuxProcessIdentity(it.pid) != it.processIdentity } != false) {
            current = current.copy(pid = null, observation = null,
                detail = "Core process identity is unavailable; application readiness cannot be verified")
        }
        if (current.running && current.role == CoreRole.CLIENT) {
            val output = synchronized(outputLock) { boundedOutput }
            val selected = runCatching { profileFor(current.engine) }.getOrNull()
            parseClientReadyEndpoint(output, current.engine, selected)?.let { port ->
                if (ownsTcpListener(port) && (current.port != port || current.host != CoreStatus.LOOPBACK_HOST)) {
                    current = current.copy(
                        host = CoreStatus.LOOPBACK_HOST,
                        port = port,
                        detail = "Client Core reported its Profile-owned application listener • ${CoreStatus.LOOPBACK_HOST}:$port",
                        observation = current.observation?.takeIf { it.readiness == "application-ready" }
                            ?: observation(current.engine, selected!!, "listener-ready"),
                    )
                }
            }
        }
        return current
    }

    private fun profileFor(engine: CoreEngine): NativeProfileDescriptor =
        nativeProfiles().singleOrNull { it.id == engine.profileId && it.core == engine.name.lowercase() }
            ?: error("Packaged Core has no matching registered Native Profile")

    /** Resolve a Profile-bound setup receipt without exposing credential values. */
    fun setup(engine: CoreEngine, profile: CoreProfile): CoreSetupObservation {
        require(available(engine)) { "Core was excluded by the selected build parameters" }
        val selected = profileFor(engine)
        require(selected.nativeTransport == engine.transport) { "Android Core transport differs from the Native Profile Registry" }
        if (profile.role == CoreRole.BROKER) require(profile.listenPort in MIN_PORT..MAX_PORT) { "Non-root listening ports must be 1024–65535" }
        val encoded = profile.toJson(engine).toString().toByteArray(Charsets.UTF_8)
        require(encoded.size <= MAX_CONFIG_BYTES) { "Core configuration exceeds the Android byte limit" }
        return CoreSetupObservation(core = selected.core, profile = selected.id,
            nativeTransport = selected.nativeTransport, applicationBoundary = boundaryLabel(selected),
            profileContractDigest = selected.contractDigest, role = profile.role.name.lowercase(),
            endpoint = profile.endpoint(), configurationBytes = encoded.size).also { setupReceipt = it }
    }

    private fun boundaryLabel(profile: NativeProfileDescriptor) =
        "${profile.applicationBoundary["kind"]}/${profile.applicationBoundary["mode"]}"

    private fun observation(engine: CoreEngine, profile: NativeProfileDescriptor, readiness: String,
                            endpoint: Map<String, Any?>? = null): RuntimeObservation? {
        val parentPid = android.os.Process.myPid().toLong()
        val parentIdentity = linuxProcessIdentity(parentPid) ?: return null
        if (process?.isAlive != true) return null
        val child = ownedChild ?: return null
        val childPid = child.pid
        val childIdentity = linuxProcessIdentity(childPid) ?: return null
        if (childIdentity != child.processIdentity ||
            runCatching { procDetails(readProcFile("/proc/$childPid/stat", 4096))?.first }.getOrNull() != parentPid) return null
        val applicationReady = readiness == "application-ready"
        return RuntimeObservation(core = profile.core, profile = profile.id,
            nativeTransport = profile.nativeTransport, applicationBoundary = boundaryLabel(profile),
            observedAt = System.currentTimeMillis() / 1000, pid = parentPid,
            processIdentity = parentIdentity,
            processes = listOf(ObservedProcessIdentity(childPid, childIdentity)), endpoint = endpoint,
            readiness = readiness, applicationReadiness = if (applicationReady) "ready" else "unknown")
    }

    private fun linuxProcessIdentity(pid: Long): String? = runCatching {
        val bootId = readProcFile("/proc/sys/kernel/random/boot_id", 256).trim()
        require(bootId.matches(Regex("[0-9a-fA-F-]{36}")))
        val startTicks = procDetails(readProcFile("/proc/$pid/stat", 4096))?.second
            ?: error("process start identity is unavailable")
        "$bootId:$startTicks"
    }.getOrNull()

    private fun readProcFile(path: String, limit: Int): String = File(path).inputStream().use { input ->
        val buffer = ByteArray(limit + 1)
        var count = 0
        while (count < buffer.size) {
            val n = input.read(buffer, count, buffer.size - count)
            if (n < 0) break
            count += n
        }
        require(count <= limit) { "Process observation exceeds its byte bound" }
        String(buffer, 0, count, Charsets.US_ASCII)
    }

    /** Enumerate only this application's own task children, never global PIDs. */
    private fun taskChildren(): Set<Long> = runCatching {
        val tasks = File("/proc/self/task").listFiles() ?: error("Task observation unavailable")
        require(tasks.size <= 512)
        val children = tasks.flatMap { task ->
            readProcFile("${task.path}/children", 8192).trim().split(Regex("\\s+"))
                .filter { it.isNotEmpty() }.map { it.toLong().also { pid -> require(pid > 0) } }
        }.toSet()
        require(children.size <= 128)
        children
    }.getOrDefault(emptySet())

    private fun identifyChild(binary: File, previous: Set<Long>): ObservedProcessIdentity? {
        val parentPid = android.os.Process.myPid().toLong()
        val candidates = (taskChildren() - previous).mapNotNull { pid -> runCatching {
            val identity = linuxProcessIdentity(pid) ?: return@runCatching null
            val details = procDetails(readProcFile("/proc/$pid/stat", 4096)) ?: return@runCatching null
            if (details.first != parentPid || android.system.Os.readlink("/proc/$pid/exe") != binary.canonicalPath ||
                linuxProcessIdentity(pid) != identity) return@runCatching null
            ObservedProcessIdentity(pid, identity)
        }.getOrNull() }
        return candidates.singleOrNull()
    }

    private fun ownsTcpListener(port: Int): Boolean = runCatching {
        val child = ownedChild ?: return@runCatching false
        if (process?.isAlive != true || linuxProcessIdentity(child.pid) != child.processIdentity) return@runCatching false
        val descriptors = File("/proc/${child.pid}/fd").listFiles() ?: return@runCatching false
        require(descriptors.size <= 512)
        val inodes = descriptors.mapNotNull { descriptor ->
            runCatching { android.system.Os.readlink(descriptor.path) }.getOrNull()
                ?.takeIf { it.startsWith("socket:[") && it.endsWith("]") }
                ?.substringAfter("socket:[")?.removeSuffix("]")
        }.toSet()
        val owned = readProcFile("/proc/${child.pid}/net/tcp", 65536).lineSequence().drop(1).any { row ->
            val fields = row.trim().split(Regex("\\s+"))
            fields.size >= 10 && fields[3] == "0A" && fields[9] in inodes &&
                fields[1].substringBefore(':') == "0100007F" &&
                fields[1].substringAfter(':').toIntOrNull(16) == port
        }
        owned && linuxProcessIdentity(child.pid) == child.processIdentity
    }.getOrDefault(false)

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
    fun start(engine: CoreEngine, profile: CoreProfile): CoreStatus {
        setup(engine, profile)
        val nativeProfile = profileFor(engine)
        stop()
        val config = writeConfig(profile, engine)
        val binary = File(context.applicationInfo.nativeLibraryDir, engine.assetName)
        require(binary.isFile) { "Packaged ${engine.name} Core is unavailable for this ABI" }
        checkedProcess(listOf(binary.absolutePath, "--config", config.absolutePath, "--check-config"))
        val coreArgs = listOf(binary.absolutePath, "--config", config.absolutePath)
        synchronized(outputLock) { boundedOutput = "" }
        val previousChildren = taskChildren()
        val active = ProcessBuilder(coreArgs).redirectErrorStream(true).start()
        process = active
        ownedChild = null
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
            role = profile.role,
            host = when (profile.role) {
                CoreRole.BROKER -> profile.listenHost
                CoreRole.CLIENT -> CoreStatus.LOOPBACK_HOST
                CoreRole.AGENT -> profile.endpoint().substringBeforeLast(':', profile.endpoint())
            },
            port = if (profile.role == CoreRole.BROKER) profile.listenPort else 0,
            pid = null,
            startedAtMillis = System.currentTimeMillis(),
            detail = "${profile.role.name.lowercase().replaceFirstChar(Char::uppercase)} Core process started • readiness is being observed",
            observation = observation(engine, nativeProfile, "process-alive"),
        )
        val readyDeadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(STARTUP_READY_WAIT_MILLIS)
        while (active.isAlive && System.nanoTime() < readyDeadline) {
            if (ownedChild == null) {
                ownedChild = identifyChild(binary, previousChildren)
                current = current.copy(pid = ownedChild?.pid)
            }
            if (observeReadiness(engine, nativeProfile, profile)) return current
            Thread.sleep(100)
        }
        if (active.isAlive) {
            current = current.copy(observation = observation(engine, nativeProfile, "process-alive"),
                detail = "Core process remains active; Profile application readiness was not observed")
        }
        return current
    }

    fun connect(engine: CoreEngine, profile: CoreProfile): CoreStatus {
        require(profile.role == CoreRole.CLIENT) { "connect is available only for a Client Profile" }
        setup(engine, profile)
        return start(engine, profile)
    }

    private fun observeReadiness(engine: CoreEngine, nativeProfile: NativeProfileDescriptor,
                                 profile: CoreProfile): Boolean {
        val output = synchronized(outputLock) { boundedOutput }
        val clientPort = if (profile.role == CoreRole.CLIENT)
            parseClientReadyEndpoint(output, engine, nativeProfile) else null
        if (clientPort != null && ownsTcpListener(clientPort)) {
            current = current.copy(host = CoreStatus.LOOPBACK_HOST, port = clientPort,
                observation = observation(engine, nativeProfile, "listener-ready"),
                detail = "Client Core reported its Profile-owned endpoint; application session is not yet verified")
            return true
        }
        if (profile.role == CoreRole.BROKER && brokerListenerReported(output)) {
            current = current.copy(observation = observation(engine, nativeProfile, "listener-ready"),
                detail = "Broker Core reported its bound listener; remote application readiness is not inferred")
            return true
        }
        return false
    }

    /** Bounded end-to-end stream echo through the running Client ApplicationBoundary. */
    fun applicationSessionProbe(payloadBytes: Int = DEFAULT_SESSION_BYTES): ApplicationSessionObservation {
        require(payloadBytes in 1..MAX_SESSION_BYTES) { "ApplicationSession payload must be 1..65536 bytes" }
        val active = status()
        val selected = runCatching { profileFor(active.engine) }.getOrNull()
            ?: return ApplicationSessionObservation(core = "unknown", profile = "unknown", nativeTransport = "unknown",
                applicationBoundary = "unavailable", status = "BLOCKED", reason = "No registered Android Native Profile")
        val boundary = boundaryLabel(selected)
        fun blocked(reason: String) = ApplicationSessionObservation(core = selected.core,
            profile = selected.id, nativeTransport = selected.nativeTransport,
            applicationBoundary = boundary, status = "BLOCKED", reason = reason)
        if (!active.running || active.role != CoreRole.CLIENT || active.port !in 1..MAX_PORT) {
            return blocked("A running Client with a reported ApplicationBoundary listener is required")
        }
        if (active.pid == null || active.observation == null || !ownsTcpListener(active.port)) {
            return blocked("A current process identity and its owned ApplicationBoundary listener are required")
        }
        if (selected.applicationBoundary["kind"] != "stream" || selected.applicationBoundary["mode"] != "localhost-tcp-proxy") {
            return blocked("Android correctness probe currently supports only the registered localhost TCP stream boundary")
        }
        val sent = ByteArray(payloadBytes) { ((it * 31 + 7) and 0xff).toByte() }
        val sentDigest = sha256(sent)
        val startNanos = System.nanoTime()
        return try {
            Socket().use { socket ->
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(CoreStatus.LOOPBACK_HOST, active.port), SESSION_TIMEOUT_MILLIS.toInt())
                val connectMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos)
                socket.soTimeout = SESSION_TIMEOUT_MILLIS.toInt()
                socket.getOutputStream().write(sent)
                socket.getOutputStream().flush()
                val received = ByteArray(payloadBytes)
                var offset = 0
                while (offset < received.size) {
                    val count = socket.getInputStream().read(received, offset, received.size - offset)
                    if (count < 0) throw java.io.EOFException("Application Session ended after $offset of $payloadBytes bytes")
                    offset += count
                }
                val receivedDigest = sha256(received)
                val match = sent.contentEquals(received)
                if (current.pid != active.pid || !ownsTcpListener(active.port)) {
                    throw IllegalStateException("Core identity or listener changed during the Application Session")
                }
                val sessionStatus = if (match) "PASS" else "FAIL"
                val endpoint = mapOf<String, Any?>("host" to CoreStatus.LOOPBACK_HOST,
                    "port" to active.port, "boundary" to selected.applicationBoundary["kind"],
                    "mode" to selected.applicationBoundary["mode"],
                    "observation" to "structured-ready-event",
                    "owner" to mapOf("pid" to active.pid, "processIdentity" to linuxProcessIdentity(active.pid!!)))
                val observed = if (match) observation(active.engine, selected,
                    "application-ready", endpoint) else observation(active.engine, selected, "process-alive")
                if (match && observed == null) throw IllegalStateException("Current Core identity cannot be observed")
                current = current.copy(observation = observed)
                ApplicationSessionObservation(core = selected.core, profile = selected.id,
                    nativeTransport = selected.nativeTransport, applicationBoundary = boundary,
                    status = sessionStatus, connectMillis = connectMillis,
                    durationMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos),
                    bytesSent = sent.size, bytesReceived = received.size,
                    sentSha256 = sentDigest, receivedSha256 = receivedDigest,
                    readiness = if (match && observed != null) "application-ready" else "unavailable",
                    reason = if (match) null else "Echo payload integrity check failed")
            }
        } catch (error: Exception) {
            ApplicationSessionObservation(core = selected.core, profile = selected.id,
                nativeTransport = selected.nativeTransport, applicationBoundary = boundary,
                status = "FAIL", durationMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos),
                bytesSent = sent.size, sentSha256 = sentDigest, readiness = "process-alive",
                reason = "${error.javaClass.simpleName}: ${error.message ?: "application endpoint failed"}".take(512))
        }
    }

    fun diagnosticJson(session: ApplicationSessionObservation? = null): JSONObject {
        val snapshot = status()
        val root = JSONObject().put("schema", "shadow6.android-test-lab-observation.v1")
            .put("createdAtMillis", System.currentTimeMillis())
            .put("lifecycle", if (snapshot.running) "running" else "stopped")
            .put("role", snapshot.role.name.lowercase())
            .put("setup", setupReceipt?.toJson())
            .put("runtimeObservation", snapshot.observation?.toJson())
            .put("nativeProfileBinding", snapshot.observation?.let { JSONObject()
                .put("core", it.core).put("profile", it.profile)
                .put("nativeTransport", it.nativeTransport).put("applicationBoundary", it.applicationBoundary) })
            .put("profileAvailability", org.json.JSONArray().also { array ->
                profileAvailability().forEach { item -> array.put(JSONObject()
                    .put("core", item.core).put("profile", item.profile)
                    .put("nativeTransport", item.nativeTransport).put("applicationBoundary", item.applicationBoundary)
                    .put("artifact", item.artifact).put("state", item.state).put("reason", item.reason)) }
            })
            .put("capabilities", JSONObject().put("supervisor", "unavailable: Android process supervision is app-scoped")
                .put("s6epe", "unavailable").put("s6sg1", "unavailable")
                .put("llmLifecycle", "unavailable: desktop lifecycle is not ported")
                .put("pcap", "unavailable: use a controlled remote capture endpoint"))
            .put("runtimeObservationUnavailableReason", if (snapshot.observation == null)
                "Process identity or live Native Core child identity is unavailable" else JSONObject.NULL)
        if (session != null) root.put("applicationSession", session.toJson())
        return root
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
        ownedChild = null
        active?.destroy()
        active?.waitFor(2, TimeUnit.SECONDS)
        if (active?.isAlive == true) { active.destroyForcibly(); active.waitFor(1, TimeUnit.SECONDS) }
        runCatching { active?.inputStream?.close() }
        outputThread?.interrupt()
        outputThread?.join(1000)
        outputThread = null
        current = current.copy(running = false, port = 0, pid = null, startedAtMillis = null, detail = "Core stopped",
            observation = null)
        return current
    }

    companion object {
        const val MIN_PORT = 1024
        const val MAX_PORT = 65535
        private const val MAX_CONFIG_BYTES = 1_048_576
        private const val MAX_OUTPUT_CHARS = 4096
        private const val STARTUP_PROBE_MILLIS = 350L
        private const val STARTUP_READY_WAIT_MILLIS = 8_000L
        private const val SESSION_TIMEOUT_MILLIS = 8_000L
        private const val DEFAULT_SESSION_BYTES = 4096
        private const val MAX_SESSION_BYTES = 65_536
        private const val NATIVE_PROFILE_ASSET = "native-profiles.json"
        private val CLIENT_PROXY_PATTERN = Regex("(?:\\[Client]\\s+)?(?:Secure\\s+)?[Ll]ocal proxy listening on 127\\.0\\.0\\.1:([0-9]{1,5})(?:\\s|$)")

        internal fun procDetails(stat: String): Pair<Long, Long>? {
            if (stat.length > 4096 || ')' !in stat) return null
            val fields = stat.substringAfterLast(')').trim().split(Regex("\\s+"))
            val parent = fields.getOrNull(1)?.toLongOrNull() ?: return null
            val ticks = fields.getOrNull(19)?.toLongOrNull() ?: return null
            return if (parent > 0 && ticks > 0) parent to ticks else null
        }

        internal fun parseClientProxyPort(output: String): Int? =
            CLIENT_PROXY_PATTERN.findAll(output).lastOrNull()?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it in 1..MAX_PORT }

        internal fun parseClientReadyEndpoint(output: String, engine: CoreEngine,
                                              profile: NativeProfileDescriptor?): Int? {
            if (profile == null) return null
            output.lines().takeLast(128).forEach { line ->
                val event = runCatching { StrictJson.objectValue(StrictJson.parse(line)) }.getOrNull() ?: return@forEach
                if (event.keys != setOf("event", "schema", "core", "role", "application_boundary") ||
                    event["event"] != "shadow6.ready" || event["schema"] != 1L ||
                    event["core"] != "shadow6-${engine.name.lowercase()}" || event["role"] != "client") return@forEach
                val boundary = runCatching { StrictJson.objectValue(event["application_boundary"]) }.getOrNull() ?: return@forEach
                if (boundary.keys != setOf("kind", "mode", "endpoint") ||
                    boundary["kind"] != profile.applicationBoundary["kind"] ||
                    boundary["mode"] != profile.applicationBoundary["mode"]) return@forEach
                val endpoint = runCatching { StrictJson.objectValue(boundary["endpoint"]) }.getOrNull() ?: return@forEach
                if (endpoint.keys != setOf("host", "port") || endpoint["host"] != CoreStatus.LOOPBACK_HOST) return@forEach
                val port = endpoint["port"] as? Long ?: return@forEach
                if (port in 1L..MAX_PORT.toLong()) return port.toInt()
            }
            return null
        }

        internal fun brokerListenerReported(output: String): Boolean =
            output.lines().takeLast(128).any { line ->
                line.contains("[Broker] Listening on ") ||
                    line.contains("[Broker] Core-D authenticated control listening on ") ||
                    line.trim() == "Broker ready"
            }

        private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
