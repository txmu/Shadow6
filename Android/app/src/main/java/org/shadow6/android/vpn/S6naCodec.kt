package org.shadow6.android.vpn

import java.nio.ByteBuffer
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Wire-compatible S6NA data-frame codec. Configuration is immutable per VPN session. */
class S6naCodec(master: ByteArray, private val payloadLimit: Int, side: Int) {
    init { require(master.size == 32 && payloadLimit in 64..65536 && side in 0..1) }
    private val tx = derive(master, side)
    private val rx = derive(master, 1 - side)
    private var sequence = 0L
    private var highestReceived = -1L
    private val received = LongArray(1024) { -1L }

    private fun derive(key: ByteArray, direction: Int): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256")); doFinal("shadow6-network-v1:".toByteArray() + direction.toByte())
    }
    private fun nonce(header: ByteArray) = MessageDigest.getInstance("SHA-256")
        .digest("shadow6-network-nonce-v1".toByteArray() + header).copyOf(12)
    fun encode(packet: ByteArray): ByteArray {
        require(packet.isNotEmpty() && packet.size <= payloadLimit)
        check(sequence < Long.MAX_VALUE) { "VPN sequence exhausted; establish a fresh session" }
        val header = ByteBuffer.allocate(32).put("S6NA".toByteArray()).put(1.toByte()).put(1.toByte()).putShort(0.toShort())
            .putLong(0L).putLong(sequence++).putShort(0.toShort()).putShort(1.toShort()).putInt(packet.size).array()
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(tx, "ChaCha20"), IvParameterSpec(nonce(header)))
        cipher.updateAAD(header)
        return header + cipher.doFinal(packet)
    }
    fun decode(frame: ByteArray): ByteArray {
        require(frame.size in 48..(48 + payloadLimit))
        val header = frame.copyOfRange(0, 32); val input = ByteBuffer.wrap(header)
        val magic = ByteArray(4); input.get(magic)
        require(magic.contentEquals("S6NA".toByteArray()) && input.get().toInt() == 1 && input.get().toInt() == 1)
        require(input.short.toInt() == 0 && input.long == 0L)
        val message = input.long
        require(message >= 0 && message > highestReceived - received.size)
        val slot = (message % received.size).toInt()
        require(received[slot] != message) { "replayed VPN frame" }
        require(input.short.toInt() == 0 && input.short.toInt() == 1)
        val length = input.int; require(length > 0 && length == frame.size - 48)
        // A failed authentication can leave provider state unusable for another init.
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(rx, "ChaCha20"), IvParameterSpec(nonce(header)))
        cipher.updateAAD(header)
        val packet = cipher.doFinal(frame.copyOfRange(32, frame.size))
        // Authentication precedes replay-state updates, including high values.
        received[slot] = message
        highestReceived = maxOf(highestReceived, message)
        return packet
    }
}
