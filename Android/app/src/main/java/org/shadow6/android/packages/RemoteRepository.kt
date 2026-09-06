package org.shadow6.android.packages
import org.json.JSONObject
import org.shadow6.android.security.httpsUrl
import org.shadow6.android.security.readBounded
import org.shadow6.android.security.withHttpsConnection
/** HTTPS-only bounded repository client with Ed25519 index verification. */
object RemoteRepository {
    const val MAX_INDEX_BYTES=1_048_576
    const val MAX_PACKAGE_BYTES=268_435_456
    fun supported() = SignedRepositoryIndex.supported()
    fun validateUrl(value: String) = httpsUrl(value, base = true)
    fun validateIndexShape(bytes: ByteArray) = JSONObject(SignedRepositoryIndex.shape(bytes))
    @Synchronized fun fetchAndVerify(value: String, publicKeyHex: String): JSONObject {
        require(supported()) { "Signed repositories require an Ed25519 provider (standard on Android 13+)" }
        SignedRepositoryIndex.hex(publicKeyHex, 32)
        val uri = validateUrl(value)
        return withHttpsConnection(uri.toString().trimEnd('/') + "/index.json", 30) { connection ->
            require(connection.responseCode == 200) { "Repository returned HTTP ${connection.responseCode}" }
            val bytes = connection.inputStream.use { it.readBounded(MAX_INDEX_BYTES) }
            JSONObject(SignedRepositoryIndex.verify(bytes, publicKeyHex))
        }
    }
}
