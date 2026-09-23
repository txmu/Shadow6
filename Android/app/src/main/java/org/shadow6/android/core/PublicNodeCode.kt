package org.shadow6.android.core

import org.shadow6.android.security.StrictJson
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import java.security.MessageDigest
import java.util.Base64
import javax.net.ssl.HttpsURLConnection

data class PublicNodeCodeInfo(val mode: String, val lookupId: String, val httpsHost: String? = null, val httpsPort: Int? = null)

/** The wire layout matches Public6/join_code.py; codes are credentials and stay in SecretStore. */
object PublicNodeCode {
    private val alphabet = Regex("^[A-Za-z0-9_-]{40}$")
    private val tenant = Regex("^[A-Za-z0-9._-]{1,64}$")
    private val hexKey = Regex("^[0-9a-f]{64}$")
    private val cores = setOf("go", "rust", "gleam", "ada", "nim", "pony", "zig", "d", "cpp", "idris", "hare", "carp")

    fun decode(code: String): PublicNodeCodeInfo {
        require(alphabet.matches(code)) { "Join code must have exactly 40 characters" }
        val raw = Base64.getUrlDecoder().decode(code)
        require(raw.size == 30 && Base64.getUrlEncoder().withoutPadding().encodeToString(raw) == code) { "Invalid join-code encoding" }
        val mode = when (raw[0].toInt() and 255) { 1 -> "directory"; 2 -> "manual"; 3 -> "ipv4-https"; else -> error("Unknown join-code version") }
        val id = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it.toInt() and 255) }
        if (mode != "ipv4-https") return PublicNodeCodeInfo(mode, id)
        val host = (1..4).joinToString(".") { (raw[it].toInt() and 255).toString() }
        val port = ((raw[5].toInt() and 255) shl 8) or (raw[6].toInt() and 255)
        require(port in 1..65535) { "Invalid HTTPS port" }
        return PublicNodeCodeInfo(mode, id, host, port)
    }

    fun seed(code: String, purpose: String): ByteArray {
        require(purpose in setOf("gate", "admission") || Regex("^core:(go|rust|gleam|ada|nim|pony|zig|d|cpp|idris|hare|carp):(client|agent)$").matches(purpose))
        decode(code)
        val raw = Base64.getUrlDecoder().decode(code)
        return MessageDigest.getInstance("SHA-256").digest(
            "shadow6.public-node.v1\u0000$purpose\u0000".toByteArray(Charsets.US_ASCII) + raw)
    }

    fun profile(code: String, directory: String = "", manualJson: String = "", manualPin: String = ""): Map<String, Any?> {
        val info = decode(code)
        val bytes = when (info.mode) {
            "manual" -> {
                require(manualJson.isNotBlank() && manualJson.toByteArray(Charsets.UTF_8).size <= 65_536) { "Paste a bounded manual profile" }
                manualJson.toByteArray(Charsets.UTF_8)
            }
            else -> {
                val origin = if (info.mode == "ipv4-https") "https://${info.httpsHost}:${info.httpsPort}" else {
                    val parsed = URL(directory)
                    require(parsed.protocol == "https" && parsed.host.isNotBlank() && parsed.userInfo == null && parsed.query == null && parsed.ref == null) { "Use a trusted HTTPS directory" }
                    directory.trimEnd('/')
                }
                val connection = URL("$origin/.well-known/shadow6/${info.lookupId}.json").openConnection() as HttpsURLConnection
                try {
                    connection.connectTimeout = 10_000
                    connection.readTimeout = 10_000
                    connection.instanceFollowRedirects = false
                    connection.setRequestProperty("Accept", "application/json")
                    require(connection.responseCode == HttpURLConnection.HTTP_OK) { "Profile lookup failed" }
                    connection.inputStream.use { stream ->
                        val output = ByteArrayOutputStream()
                        val chunk = ByteArray(4096)
                        while (true) {
                            val count = stream.read(chunk)
                            if (count < 0) break
                            require(output.size() + count <= 65_536) { "Profile is oversized" }
                            output.write(chunk, 0, count)
                        }
                        output.toByteArray()
                    }
                } finally { connection.disconnect() }
            }
        }
        val value = StrictJson.objectValue(StrictJson.decode(bytes))
        require(value.keys == setOf("schema", "lookup_id", "tenant", "admission_public_key", "routes") &&
                value["schema"] == "shadow6.public-node-profile.v1" && value["lookup_id"] == info.lookupId &&
                value["tenant"] is String && tenant.matches(value["tenant"] as String)) { "Profile does not match join code" }
        val admissionPublic = value["admission_public_key"] as? String ?: error("Missing admission identity")
        require(hexKey.matches(admissionPublic)) { "Invalid admission identity" }
        val routes = value["routes"] as? List<*> ?: error("Invalid Core route catalog")
        require(routes.size in 1..12)
        val seen = mutableSetOf<String>()
        routes.forEach { item ->
            val route = StrictJson.objectValue(item)
            require(route.keys == setOf("core", "transport", "gate_host", "gate_port", "gate_public_key", "native_broker_public_key", "native_client_public_key", "native_agent_public_key", "default_agent_id", "default_agent_public_key")) { "Unknown Core route field" }
            val core = route["core"] as? String ?: error("Invalid Core family")
            require(core in cores && seen.add(core)) { "Invalid or duplicate Core family" }
            require(route["transport"] in setOf("tcp", "udp")) { "Invalid Core carrier" }
            val host = route["gate_host"] as? String ?: error("Invalid Gate host")
            require(host.length in 2..45 && host.matches(Regex("^[0-9a-fA-F:.]+$")) &&
                    (':' in host || host.matches(Regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$"))) &&
                    !InetAddress.getByName(host).isAnyLocalAddress && !InetAddress.getByName(host).isMulticastAddress) { "Gate host must be a numeric IP address" }
            require(route["gate_port"] is Long && (route["gate_port"] as Long) in 1024L..65534L) { "Invalid Gate port" }
            val key = route["gate_public_key"] as? String ?: error("Invalid Gate identity")
            require(hexKey.matches(key)) { "Invalid Gate identity" }
            require(hexKey.matches(route["native_broker_public_key"] as? String ?: "")) { "Invalid native Broker identity" }
            require(hexKey.matches(route["native_client_public_key"] as? String ?: "") &&
                    hexKey.matches(route["native_agent_public_key"] as? String ?: "")) { "Invalid native Core identities" }
            val agentId = route["default_agent_id"] as? String ?: error("Invalid default Agent")
            val agentKey = route["default_agent_public_key"] as? String ?: error("Invalid default Agent")
            require((agentId.isEmpty() && agentKey.isEmpty()) || (tenant.matches(agentId) && hexKey.matches(agentKey))) { "Invalid default Agent" }
            if (info.mode == "manual") require(routes.size == 1 && manualPin == key) { "Manual profile needs the separately verified full Gate public key" }
        }
        return value
    }
}
