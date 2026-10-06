package org.shadow6.android.core

import org.shadow6.android.security.StrictJson
import java.io.InputStream
import java.io.ByteArrayOutputStream

data class NativeProfileDescriptor(
    val id: String,
    val core: String,
    val primary: Boolean,
    val nativeTransport: String,
    val applicationBoundary: Map<String, Any?>,
    val requirements: Map<String, Any?>,
    val artifact: String,
    val contractDigest: String,
)

data class NativeProfileAvailability(
    val core: String,
    val profile: String,
    val nativeTransport: String,
    val applicationBoundary: String,
    val artifact: String,
    val state: String,
    val reason: String?,
)

object NativeProfileCatalog {
    private const val MAX_CATALOG_BYTES = 256 * 1024
    private val digestPattern = Regex("sha256:[0-9a-f]{64}")

    fun load(input: InputStream): List<NativeProfileDescriptor> {
        val bytes = input.use { stream ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                require(output.size() + count <= MAX_CATALOG_BYTES) { "Native Profile catalog is oversized" }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        require(bytes.isNotEmpty()) { "Native Profile catalog is empty" }
        val root = StrictJson.objectValue(StrictJson.decode(bytes))
        require(root.keys == setOf("schema", "sourceSchema", "profiles")) { "Native Profile catalog has unknown fields" }
        require(root["schema"] == "shadow6.android-native-profile-catalog.v1") { "Unsupported Android Profile catalog" }
        require(root["sourceSchema"] == "shadow6.native-profile.v1") { "Unexpected Native Profile source schema" }
        val entries = root["profiles"] as? List<*> ?: error("Native Profile list is missing")
        require(entries.size in 12..32) { "Native Profile catalog count is outside bounds" }
        val profiles = entries.map { raw ->
            val item = StrictJson.objectValue(raw)
            require(item.keys == setOf("id", "core", "primary", "nativeTransport", "applicationBoundary", "requirements", "artifact", "contractDigest")) {
                "Native Profile descriptor has unknown fields"
            }
            val id = StrictJson.text(item["id"], 128)
            val core = StrictJson.text(item["core"], 32)
            val transport = StrictJson.text(item["nativeTransport"], 64)
            val artifact = StrictJson.text(item["artifact"], 256)
            val digest = StrictJson.text(item["contractDigest"], 71)
            require(id.startsWith("$core-") && digestPattern.matches(digest)) { "Invalid Native Profile identity or digest" }
            val boundary = StrictJson.objectValue(item["applicationBoundary"])
            require(boundary.keys.containsAll(setOf("kind", "mode"))) { "ApplicationBoundary is incomplete" }
            val kind = StrictJson.text(boundary["kind"], 32)
            require(kind == "stream" || kind == "message") { "Unknown ApplicationBoundary kind" }
            NativeProfileDescriptor(id, core, item["primary"] as? Boolean ?: error("Invalid primary flag"),
                transport, boundary, StrictJson.objectValue(item["requirements"]), artifact, digest)
        }
        require(profiles.map { it.id }.toSet().size == profiles.size) { "Duplicate Native Profile" }
        val primary = profiles.filter { it.primary }
        require(primary.size == 12 && primary.map { it.core }.toSet().size == 12) { "Catalog must contain twelve primary Cores" }
        return profiles
    }

    fun availability(
        profiles: List<NativeProfileDescriptor>,
        artifactPresent: (NativeProfileDescriptor) -> Boolean,
        runtimeBound: (NativeProfileDescriptor) -> Boolean,
    ): List<NativeProfileAvailability> = profiles.map { profile ->
        val present = artifactPresent(profile)
        val bound = present && runtimeBound(profile)
        NativeProfileAvailability(profile.core, profile.id, profile.nativeTransport,
            "${profile.applicationBoundary["kind"]}/${profile.applicationBoundary["mode"]}",
            profile.artifact,
            when { bound -> "RUNNABLE"; present -> "ARTIFACT-UNBOUND"; else -> "NOT-PACKAGED" },
            when { bound -> null; present -> "Android runtime has no Core/Profile controller binding"; else -> "No executable for this Core was packaged for the selected ABI" })
    }
}
