package org.shadow6.android.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class S6naCodecTest {
    @Test fun authenticatesAndRejectsReplayAndTampering() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val sender = S6naCodec(key, 1400, 0)
        val receiver = S6naCodec(key, 1400, 1)
        val first = sender.encode(byteArrayOf(1, 2, 3))
        val second = sender.encode(byteArrayOf(4, 5, 6))
        val forged = second.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { receiver.decode(forged) }
        assertArrayEquals(byteArrayOf(4, 5, 6), receiver.decode(second))
        assertArrayEquals(byteArrayOf(1, 2, 3), receiver.decode(first))
        assertThrows(IllegalArgumentException::class.java) { receiver.decode(first) }
    }

    @Test fun boundedWindowRejectsOldFramesAndWrongDirection() {
        val key = ByteArray(32) { 7 }
        val sender = S6naCodec(key, 1400, 0)
        val receiver = S6naCodec(key, 1400, 1)
        val old = sender.encode(byteArrayOf(1))
        repeat(1024) { receiver.decode(sender.encode(byteArrayOf(2))) }
        assertThrows(IllegalArgumentException::class.java) { receiver.decode(old) }
        val wrong = S6naCodec(key, 1400, 0)
        assertThrows(Exception::class.java) { wrong.decode(sender.encode(byteArrayOf(3))) }
    }
}
