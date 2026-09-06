package org.shadow6.android.security

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URI
import java.util.concurrent.TimeUnit
import java.util.concurrent.ScheduledThreadPoolExecutor
import javax.net.ssl.HttpsURLConnection

private val deadlines = ScheduledThreadPoolExecutor(1) { job ->
    Thread(job, "shadow6-http-deadline").apply { isDaemon = true }
}.apply { removeOnCancelPolicy = true }

fun <T> withHttpsConnection(url: String, seconds: Long, block: (HttpsURLConnection) -> T): T {
    require(seconds in 1..90)
    val connection = httpsUrl(url).toURL().openConnection() as HttpsURLConnection
    connection.instanceFollowRedirects = false
    connection.connectTimeout = 10_000
    connection.readTimeout = 15_000
    connection.useCaches = false
    val deadline = deadlines.schedule({ connection.disconnect() }, seconds, TimeUnit.SECONDS)
    val started = System.nanoTime()
    try {
        return block(connection).also {
            check(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(seconds)) { "HTTPS request timed out" }
        }
    } finally {
        deadline.cancel(false)
        connection.disconnect()
    }
}

/** Uses APIs available on API 28; readNBytes is only available on API 33+. */
fun InputStream.readBounded(limit: Int): ByteArray {
    require(limit in 1..1_048_576)
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(4096)
    while (true) {
        val count = read(buffer, 0, minOf(buffer.size, limit + 1 - output.size()))
        if (count < 0) return output.toByteArray()
        if (count == 0) continue
        output.write(buffer, 0, count)
        require(output.size() <= limit) { "Input exceeds the size limit" }
    }
}

fun httpsUrl(value: String, base: Boolean = false): URI {
    require(value.length in 1..2048 && value.none { it <= ' ' || it == '\u007f' }) { "Invalid HTTPS URL" }
    val uri = URI(value)
    require(uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null && uri.rawFragment == null
        && (uri.port == -1 || uri.port in 1..65535) && (!base || uri.rawQuery == null)) {
        "Endpoint must be credential-free HTTPS; base URLs cannot contain queries"
    }
    return uri
}

/** Drain concurrently: waiting for exit before reading can deadlock a full pipe. */
fun checkedProcess(command: List<String>, timeoutSeconds: Long = 10, limit: Int = 4096): ByteArray {
    val child = ProcessBuilder(command).redirectErrorStream(true).start()
    var bytes: ByteArray? = null
    var failure: Throwable? = null
    val reader = Thread({
        try {
            bytes = child.inputStream.use { it.readBounded(limit) }
        } catch (error: Exception) {
            failure = error
            child.destroyForcibly()
        }
    }, "shadow6-command-output").apply { isDaemon = true; start() }
    try {
        check(child.waitFor(timeoutSeconds, TimeUnit.SECONDS)) { "Core command timed out" }
        reader.join(1000)
        check(!reader.isAlive && failure == null) { "Core command output is invalid or oversized" }
        // Native diagnostics can contain configuration values. Do not expose
        // them to the remote AI tools or echo key-generation failures.
        check(child.exitValue() == 0) { "Core command rejected the configuration or operation" }
        return checkNotNull(bytes)
    } finally {
        if (child.isAlive) child.destroyForcibly()
        child.waitFor(1, TimeUnit.SECONDS)
        runCatching { child.inputStream.close() }
        runCatching { child.outputStream.close() }
        reader.interrupt()
        reader.join(1000)
    }
}
