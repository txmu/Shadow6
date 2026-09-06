package org.shadow6.android.core

import org.json.JSONArray
import org.json.JSONObject
import org.shadow6.android.security.StrictJson
import org.shadow6.android.security.httpsUrl

enum class CoreRole { BROKER, AGENT, CLIENT }

data class CoreIdentity(val privateKey: String, val publicKey: String)

data class CoreProfile(
    val role: CoreRole = CoreRole.BROKER,
    val listenHost: String = "127.0.0.1",
    val listenPort: Int = 4433,
    val identityId: String = "android-1",
    val privateKey: String = "",
    val publicKey: String = "",
    val brokerAddresses: String = "",
    val brokerPublicKey: String = "",
    val targetPort: Int = 22,
    val autoCloseSeconds: Int = 7200,
    val allowLocalDiscovery: Boolean = false,
    val targetAgent: String = "agent-1",
    val agentPublicKey: String = "",
    val webhookUrl: String = "",
    val stealthMode: Boolean = false,
    val brokerAgentsJson: String = "[]",
    val brokerClientsJson: String = "[]",
    val clientPublicKeysJson: String = "{}",
    val sni: String = "",
    val alpn: String = "",
) {
    fun endpoint(): String = when (role) {
        CoreRole.BROKER -> listenEndpoint()
        else -> brokerAddresses.lineSequence().map(String::trim).firstOrNull(String::isNotEmpty) ?: "not configured"
    }

    private fun listenEndpoint(): String =
        if (':' in listenHost && !listenHost.startsWith('[')) "[$listenHost]:$listenPort" else "$listenHost:$listenPort"

    fun toJson(engine: CoreEngine): JSONObject {
        require(privateKey.matches(Regex("^[0-9a-fA-F]{64}([0-9a-fA-F]{64})?$"))) { "Generate or enter a valid Ed25519 private key" }
        val root = JSONObject().put("role", role.name.lowercase())
        when (role) {
            CoreRole.BROKER -> {
                require(listenHost.isNotBlank() && listenHost.length <= 253 && !listenHost.contains(Regex("[\\r\\n\\u0000]"))) { "Invalid listen host" }
                require(listenPort in 1..65535) { "Listen port must be between 1 and 65535" }
                val agents = strictAgents(strictArray(brokerAgentsJson.ifBlank { "[]" }))
                val clients = strictClients(strictArray(brokerClientsJson.ifBlank { "[]" }))
                if (webhookUrl.isNotBlank()) httpsUrl(webhookUrl.trim())
                root.put("broker", JSONObject()
                    .put("listen_addr", listenEndpoint())
                    .put("private_key", privateKey)
                    .put("agents", agents)
                    .put("clients", clients)
                    .put("webhook_url", webhookUrl.trim())
                    .put("stealth_mode", stealthMode))
            }
            CoreRole.AGENT -> {
                validateIdentity(identityId)
                require(targetPort in 1..65535) { "Target port must be between 1 and 65535" }
                require(autoCloseSeconds in 1..86_400) { "Auto-close must be between 1 and 86400 seconds" }
                val section = JSONObject()
                    .put("id", identityId)
                    .put("broker_addrs", brokerArray())
                    .put("broker_pubkey", publicKey(brokerPublicKey, "broker"))
                    .put("private_key", privateKey)
                    .put("target_port", targetPort)
                    .put("auto_close_after", autoCloseSeconds)
                    .put("allow_local_discovery", allowLocalDiscovery)
                    .put("client_pubkeys", strictKeyMap(JSONObject(StrictJson.objectValue(StrictJson.parse(clientPublicKeysJson.ifBlank { "{}" })))))
                    .put("transport", if (engine == CoreEngine.GO) "kcp" else "quic")
                rustTls(engine, section)
                root.put("agent", section)
            }
            CoreRole.CLIENT -> {
                validateIdentity(identityId)
                validateIdentity(targetAgent)
                val section = JSONObject()
                    .put("id", identityId)
                    .put("broker_addrs", brokerArray())
                    .put("broker_pubkey", publicKey(brokerPublicKey, "broker"))
                    .put("private_key", privateKey)
                    .put("target_agent", targetAgent)
                    .put("agent_pubkey", publicKey(agentPublicKey, "agent"))
                    .put("on_success", "")
                    .put("allow_local_discovery", allowLocalDiscovery)
                    .put("transport", if (engine == CoreEngine.GO) "kcp" else "quic")
                rustTls(engine, section)
                root.put("client", section)
            }
        }
        return root
    }

    private fun brokerArray(): JSONArray {
        val values = brokerAddresses.lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
        require(values.isNotEmpty() && values.size <= 16 && values.all { it.length <= 2048 && !it.contains(Regex("[\\r\\n\\u0000]")) }) { "Enter 1–16 valid broker addresses, one per line" }
        return JSONArray(values)
    }

    private fun rustTls(engine: CoreEngine, section: JSONObject) {
        if (engine != CoreEngine.RUST) return
        if (sni.isNotBlank()) section.put("sni", boundedText(sni, 253, "SNI"))
        if (alpn.isNotBlank()) section.put("alpn", boundedText(alpn, 255, "ALPN"))
    }

    companion object {
        private val identityPattern = Regex("^[A-Za-z0-9._-]{1,64}$")
        private val publicKeyPattern = Regex("^[0-9a-fA-F]{64}$")

        private fun strictArray(source: String): JSONArray {
            val value = StrictJson.parse(source)
            require(value is List<*>) { "Expected ACL array" }
            return JSONArray(value)
        }

        private fun validateIdentity(value: String): String {
            require(identityPattern.matches(value)) { "Identity must contain 1–64 letters, digits, dot, dash, or underscore" }
            return value
        }

        private fun publicKey(value: String, label: String): String {
            require(publicKeyPattern.matches(value)) { "Enter a valid $label Ed25519 public key" }
            return value
        }

        private fun boundedText(value: String, limit: Int, label: String): String {
            require(value.length <= limit && !value.contains(Regex("[\\r\\n\\u0000]"))) { "Invalid $label" }
            return value
        }

        private fun strictAgents(input: JSONArray): JSONArray {
            require(input.length() <= 256) { "Too many broker agents" }
            return JSONArray().also { output ->
                for (index in 0 until input.length()) {
                    val item = input.getJSONObject(index)
                    require(keys(item) == setOf("id", "pubkey")) { "Agent ACL has unknown or missing fields" }
                    output.put(JSONObject().put("id", validateIdentity(StrictJson.text(item.get("id")))).put("pubkey", publicKey(StrictJson.text(item.get("pubkey")), "agent")))
                }
            }
        }

        private fun strictClients(input: JSONArray): JSONArray {
            require(input.length() <= 256) { "Too many broker clients" }
            return JSONArray().also { output ->
                for (index in 0 until input.length()) {
                    val item = input.getJSONObject(index)
                    require(keys(item) == setOf("id", "pubkey", "allowed_agents")) { "Client ACL has unknown or missing fields" }
                    val allowed = item.getJSONArray("allowed_agents")
                    require(allowed.length() <= 256) { "Too many allowed agents" }
                    val normalized = JSONArray()
                    for (position in 0 until allowed.length()) normalized.put(validateIdentity(StrictJson.text(allowed.get(position))))
                    output.put(JSONObject().put("id", validateIdentity(StrictJson.text(item.get("id")))).put("pubkey", publicKey(StrictJson.text(item.get("pubkey")), "client")).put("allowed_agents", normalized))
                }
            }
        }

        private fun strictKeyMap(input: JSONObject): JSONObject {
            require(input.length() in 1..256) { "Agent requires 1–256 authorized client public keys" }
            return JSONObject().also { output ->
                keys(input).sorted().forEach { id: String -> output.put(validateIdentity(id), publicKey(StrictJson.text(input.get(id)), "client")) }
            }
        }

        private fun keys(input: JSONObject): Set<String> = buildSet {
            val iterator = input.keys()
            while (iterator.hasNext()) add(iterator.next())
        }
    }
}
