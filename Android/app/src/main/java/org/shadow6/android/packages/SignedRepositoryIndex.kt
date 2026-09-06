package org.shadow6.android.packages

import org.shadow6.android.security.StrictJson
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/** Pure data/signature contract; no package download or code activation. */
object SignedRepositoryIndex {
    const val MAX_PACKAGE_BYTES = 268_435_456L
    fun supported(): Boolean = runCatching {
        KeyFactory.getInstance("Ed25519")
        Signature.getInstance("Ed25519")
    }.isSuccess

    fun shape(bytes: ByteArray): Map<String, Any?> {
        val root = StrictJson.objectValue(StrictJson.decode(bytes))
        require(root.keys == setOf("schema", "signer", "packages", "signature")) { "Unknown repository schema fields" }
        require(root["schema"] == "shadow6-repository-v1") { "Unsupported repository schema" }
        require(StrictJson.text(root["signer"], 128).isNotBlank()) { "Missing repository signer" }
        hex(StrictJson.text(root["signature"], 128), 64)
        val packages = root["packages"]
        require(packages is List<*> && packages.size <= 2048) { "Invalid package collection" }
        val names = mutableSetOf<String>()
        packages.forEach { raw ->
            val item = StrictJson.objectValue(raw)
            require(item.keys == setOf("name", "size", "sha256")) { "Unknown package fields" }
            val name = StrictJson.text(item["name"], 255)
            require(name.isNotBlank() && name !in setOf(".", "..") && name.none { it < ' ' || it in "/\\:\u007f" }
                && !name.endsWith('.') && !name.endsWith(' ') && names.add(name)) { "Unsafe or duplicate package name" }
            val size = item["size"]
            require(size is Long && size in 1..MAX_PACKAGE_BYTES) { "Invalid package size" }
            hex(StrictJson.text(item["sha256"], 64), 32)
        }
        return root
    }

    fun verify(bytes: ByteArray, publicKeyHex: String): Map<String, Any?> {
        val rawKey = hex(publicKeyHex, 32)
        val root = shape(bytes)
        val unsigned = root.filterKeys { it != "signature" }
        val key = KeyFactory.getInstance("Ed25519").generatePublic(
            X509EncodedKeySpec(hex("302a300506032b6570032100", 12) + rawKey))
        val verifier = Signature.getInstance("Ed25519").apply { initVerify(key) }
        val canonical = StrictJson.canonical(unsigned).toByteArray(Charsets.UTF_8)
        require(canonical.size <= StrictJson.MAX_BYTES) { "Canonical index is too large" }
        verifier.update(canonical)
        require(verifier.verify(hex(root["signature"] as String, 64))) { "Repository signature verification failed" }
        return unsigned
    }

    fun hex(value: String, size: Int): ByteArray {
        require(value.length == size * 2 && value.all { it in "0123456789abcdefABCDEF" }) { "Invalid key, digest or signature" }
        return ByteArray(size) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
