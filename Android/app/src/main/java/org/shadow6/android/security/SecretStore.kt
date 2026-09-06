package org.shadow6.android.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Ciphertext is app-private; the wrapping key never leaves Android Keystore. */
class SecretStore(context: Context, namespace: String, private val alias: String = "shadow6-$namespace-key") {
    private val preferences = context.getSharedPreferences(namespace, Context.MODE_PRIVATE)
    private fun key(create: Boolean): SecretKey = synchronized(keyLock) {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey) ?: run {
            check(create) { "Stored credential cannot be decrypted; re-enter it" }
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
                generateKey()
            }
        }
    }
    fun put(name: String, value: String) {
        require(value.length in 1..4096 && value.all { it in '!'..'~' }) { "Invalid credential" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key(true)) }
        val encrypted = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        check(preferences.edit().putString(name, Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP)).commit()) {
            "Unable to save encrypted credential"
        }
    }
    fun get(name: String): String {
        val encoded = preferences.getString(name, "") ?: ""
        if (encoded.isEmpty()) return ""
        require(encoded.length <= 8192) { "Stored credential is oversized" }
        val packed = Base64.decode(encoded, Base64.NO_WRAP)
        require(packed.size in 29..4124) { "Invalid stored credential" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, packed.copyOfRange(0, 12)))
        }
        return String(cipher.doFinal(packed.copyOfRange(12, packed.size)), Charsets.UTF_8)
    }
    fun has(name: String) = !preferences.getString(name, "").isNullOrEmpty()
    fun remove(name: String) { check(preferences.edit().remove(name).commit()) { "Unable to clear credential" } }
    fun migrate(legacy: SharedPreferences, name: String): String {
        val plain = legacy.getString(name, "") ?: ""
        if (plain.isNotEmpty()) {
            if (!has(name)) put(name, plain)
            val restored = get(name)
            check(legacy.edit().remove(name).commit()) { "Unable to remove legacy credential" }
            return restored
        }
        return get(name)
    }
    companion object { private val keyLock = Any() }
}
