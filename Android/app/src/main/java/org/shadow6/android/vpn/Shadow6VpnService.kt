package org.shadow6.android.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

/** Optional app-private VPN carrier. It never starts unless the user grants VpnService consent. */
class Shadow6VpnService : VpnService() {
    private val running = AtomicBoolean(false)
    private var descriptor: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stop(); return START_NOT_STICKY }
        if (!running.compareAndSet(false, true)) return START_NOT_STICKY
        val host = intent?.getStringExtra(EXTRA_HOST) ?: return fail()
        val port = intent.getIntExtra(EXTRA_PORT, 0)
        val key = runCatching { Base64.getDecoder().decode(intent.getStringExtra(EXTRA_KEY)) }.getOrNull()
        val side = intent.getIntExtra(EXTRA_SIDE, -1)
        if (key?.size != 32 || port !in 1..65535 || side !in 0..1) return fail()
        descriptor = Builder().setSession("Shadow6 S6NA VPN").setMtu(1400)
            .addAddress("10.66.0.${side + 1}", 30).addRoute("0.0.0.0", 0).establish() ?: return fail()
        worker = Thread({ loop(host, port, key, side) }, "shadow6-vpn").also { it.start() }
        return START_NOT_STICKY
    }
    private fun loop(host: String, port: Int, key: ByteArray, side: Int) {
        val vpn = descriptor ?: return
        val input = FileInputStream(vpn.fileDescriptor); val output = FileOutputStream(vpn.fileDescriptor)
        val channel = DatagramChannel.open(); protect(channel.socket()); channel.connect(InetSocketAddress(host, port)); channel.configureBlocking(false)
        val codec = S6naCodec(key, 1400, side); val packet = ByteArray(1400); val wire = ByteBuffer.allocate(1500)
        try { while (running.get()) {
            if (input.available() > 0) { val n = input.read(packet); if (n > 0) channel.write(ByteBuffer.wrap(codec.encode(packet.copyOf(n)))) }
            wire.clear(); if (channel.read(wire) > 0) { wire.flip(); val bytes=ByteArray(wire.remaining()); wire.get(bytes); output.write(codec.decode(bytes)) }
            Thread.sleep(2)
        }} finally { channel.close(); input.close(); output.close() }
    }
    private fun fail(): Int { stop(); return START_NOT_STICKY }
    private fun stop() { running.set(false); worker?.interrupt(); descriptor?.close(); descriptor=null; stopSelf() }
    override fun onDestroy() { stop(); super.onDestroy() }
    companion object {
        const val ACTION_STOP="org.shadow6.android.vpn.STOP"
        const val EXTRA_HOST="host"; const val EXTRA_PORT="port"; const val EXTRA_KEY="key"; const val EXTRA_SIDE="side"
    }
}
