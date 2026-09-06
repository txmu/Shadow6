package org.shadow6.android.ai

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import org.shadow6.android.security.SecretStore
import org.shadow6.android.security.StrictJson
import org.shadow6.android.security.httpsUrl
import org.shadow6.android.security.readBounded
import org.shadow6.android.security.withHttpsConnection

data class AiTurn(val text: String, val responseId: String, val toolEvents: List<String>)

class OpenAiCompatibleClient(private val context: Context) {
    private val secrets = SecretStore(context, "ai", "shadow6-openai-key")
    private val preferences = context.getSharedPreferences("ai", Context.MODE_PRIVATE)

    fun saveApiKey(value: String, endpoint: String) {
        val bound = httpsUrl(endpoint, base = true).toString().trimEnd('/')
        secrets.put("key", value)
        check(preferences.edit().putString("key_endpoint", bound).commit()) { "Unable to bind API key to endpoint" }
    }

    fun hasApiKey(): Boolean = secrets.has("key")
    fun clearApiKey() { secrets.remove("key"); preferences.edit().remove("key_endpoint").apply() }

    fun requireKeyEndpoint(endpoint: String) {
        val bound = preferences.getString("key_endpoint", null)
        require(bound != null && bound == httpsUrl(endpoint, base = true).toString().trimEnd('/')) {
            "Save/re-enter the API key for this endpoint before sending"
        }
    }

    private fun apiKey(endpoint: String): String {
        requireKeyEndpoint(endpoint)
        return secrets.get("key").also { require(it.isNotBlank() && it.all { char -> char in '!'..'~' }) { "Invalid API key" } }
    }

    @Synchronized fun respond(endpoint: String, model: String, prompt: String, previousResponseId: String?, mcpUrl: String,
                localTool: (String, JSONObject) -> JSONObject): AiTurn {
        httpsUrl(endpoint, base = true)
        require(model.matches(Regex("^[A-Za-z0-9._:-]{1,128}$"))) { "Invalid model name" }
        require(prompt.isNotBlank() && prompt.length <= 65_536) { "Message is empty or too large" }
        if (mcpUrl.isNotBlank()) httpsUrl(mcpUrl)
        require(previousResponseId == null || previousResponseId.matches(Regex("^[A-Za-z0-9_-]{1,256}$"))) { "Invalid response ID" }
        var response = post(endpoint, model, prompt, previousResponseId, tools(mcpUrl))
        val events = mutableListOf<String>()
        repeat(MAX_TOOL_ROUNDS + 1) { round ->
            val calls = functionCalls(response)
            val responseId = StrictJson.text(response.get("id"), 256)
            require(responseId.matches(Regex("^[A-Za-z0-9_-]{1,256}$"))) { "Invalid response ID" }
            if (calls.isEmpty()) return AiTurn(extractText(response), responseId, events)
            require(round < MAX_TOOL_ROUNDS) { "AI exceeded the bounded tool-call loop" }
            require(calls.size <= MAX_TOOL_CALLS) { "AI requested too many tools" }
            val outputs = JSONArray()
            calls.forEach { call ->
                check(!Thread.currentThread().isInterrupted) { "AI request cancelled" }
                val name = StrictJson.text(call.get("name"), 128)
                require(name in LOCAL_TOOLS) { "Unknown or mutating tool" }
                val arguments = JSONObject(StrictJson.objectValue(StrictJson.parse(StrictJson.text(call.get("arguments"), 4096))))
                require(arguments.length() == 0) { "Read-only tools accept no arguments" }
                val result = localTool(name, arguments)
                events += name
                outputs.put(JSONObject().put("type", "function_call_output")
                    .put("call_id", call.getString("call_id")).put("output", result.toString()))
            }
            response = post(endpoint, model, outputs, responseId, tools(mcpUrl))
        }
        throw IllegalStateException("AI exceeded the bounded tool-call loop")
    }

    private fun tools(mcpUrl: String): JSONArray = JSONArray().apply {
        put(function("shadow6_core_status", "Read the current Android Core process status."))
        put(function("shadow6_config_summary", "Read the active Android Core configuration summary without secrets."))
        put(function("shadow6_modules", "List Android modules and availability."))
        if (mcpUrl.isNotBlank()) put(JSONObject().put("type", "mcp")
            .put("server_label", "shadow6_remote")
            .put("server_description", "Operator-configured Shadow6 Control Center. Every remote call requires approval.")
            .put("server_url", mcpUrl).put("require_approval", "always"))
    }

    private fun function(name: String, description: String) = JSONObject().put("type", "function")
        .put("name", name).put("description", description).put("strict", true)
        .put("parameters", JSONObject().put("type", "object").put("properties", JSONObject())
            .put("required", JSONArray()).put("additionalProperties", false))

    private fun post(endpoint: String, model: String, input: Any, previousId: String?, tools: JSONArray): JSONObject {
        val base = endpoint.trimEnd('/')
        val url = base + if (base.endsWith("/v1")) "/responses" else "/v1/responses"
        return withHttpsConnection(url, 90) { connection ->
        connection.readTimeout = 60_000
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Authorization", "Bearer ${apiKey(endpoint)}")
        connection.setRequestProperty("Content-Type", "application/json")
        val request = JSONObject().put("model", model).put("input", input)
            .put("instructions", SYSTEM_INSTRUCTIONS).put("tools", tools).put("store", true)
        if (!previousId.isNullOrBlank()) request.put("previous_response_id", previousId)
        val payload = request.toString().toByteArray(Charsets.UTF_8)
        require(payload.size <= MAX_REQUEST_BYTES) { "AI request is too large" }
        connection.setFixedLengthStreamingMode(payload.size)
        connection.outputStream.use { it.write(payload) }
        val code = connection.responseCode
        val stream = if (code in 200..299) connection.inputStream else connection.errorStream
        val bytes = stream?.use { it.readBounded(MAX_RESPONSE_BYTES) } ?: ByteArray(0)
        require(bytes.size <= MAX_RESPONSE_BYTES) { "AI response is too large" }
        require(code in 200..299) { "AI endpoint returned HTTP $code" }
        JSONObject(StrictJson.objectValue(StrictJson.decode(bytes, portable = false)))
        }
    }

    private fun functionCalls(response: JSONObject): List<JSONObject> {
        val output = response.optJSONArray("output") ?: JSONArray()
        return buildList {
            for (index in 0 until output.length()) output.optJSONObject(index)?.let {
                if (it.optString("type") == "function_call") add(it)
            }
        }
    }

    private fun extractText(response: JSONObject): String {
        val output = response.optJSONArray("output") ?: JSONArray()
        val text = buildList {
            for (index in 0 until output.length()) {
                val content = output.optJSONObject(index)?.optJSONArray("content") ?: continue
                for (part in 0 until content.length()) content.optJSONObject(part)?.let {
                    if (it.optString("type") == "output_text") add(it.optString("text"))
                }
            }
        }.filter(String::isNotBlank).joinToString("\n")
        if (text.isNotBlank()) return text.take(MAX_MESSAGE_CHARS)
        for (index in 0 until output.length()) {
            val item = output.optJSONObject(index) ?: continue
            if (item.optString("type") == "mcp_approval_request")
                return "Remote MCP requested approval. This Android client cannot submit approval responses; no remote action was approved."
        }
        return "The model returned no displayable text."
    }

    companion object {
        private val LOCAL_TOOLS = setOf("shadow6_core_status", "shadow6_config_summary", "shadow6_modules")
        private const val MAX_REQUEST_BYTES = 262_144
        private const val MAX_RESPONSE_BYTES = 1_048_576
        private const val MAX_MESSAGE_CHARS = 65_536
        private const val MAX_TOOL_ROUNDS = 4
        private const val MAX_TOOL_CALLS = 8
        private const val SYSTEM_INSTRUCTIONS = "You are the Shadow6 Android operations assistant. Explain clearly, use only supplied read-only tools, never claim to execute shell commands, and never reveal or request private keys or API keys."
    }
}
