package org.shadow6.android.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.shadow6.android.MainActivity
import org.shadow6.android.R
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean

/** Optional standalone S6NA IP carrier, started only after Android VPN consent. */
class Shadow6VpnService : VpnService() {
    private class Session(val key: ByteArray) {
        val active = AtomicBoolean(true)
        @Volatile var descriptor: ParcelFileDescriptor? = null
        @Volatile var channel: DatagramChannel? = null
        @Volatile var sender: Thread? = null
        fun close() {
            active.set(false)
            runCatching { channel?.close() }
            runCatching { descriptor?.close() }
            sender?.interrupt()
            key.fill(0)
        }
    }
    @Volatile private var session: Session? = null

    override fun onCreate() {
        super.onCreate()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("shadow6-vpn", getString(R.string.vpn_title), NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, Shadow6VpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        val notification = Notification.Builder(this, "shadow6-vpn")
            .setContentTitle(getString(R.string.vpn_title)).setContentText(getString(R.string.vpn_notification))
            .setSmallIcon(android.R.drawable.stat_sys_download_done).setOngoing(true).setContentIntent(open)
            .addAction(Notification.Action.Builder(null, getString(R.string.stop), stop).build()).build()
        startForeground(7, notification)
    }

    @Synchronized override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { finish(session); return START_NOT_STICKY }
        if (session != null) return START_NOT_STICKY
        try {
            require(intent?.action == ACTION_START) { "VPN requires explicit startup configuration" }
            val host = intent.getStringExtra(EXTRA_HOST) ?: error("VPN peer IP is required")
            // Numeric addresses avoid unbounded DNS lookup and recursive VPN DNS.
            require(host.length in 1..45 && (host.matches(Regex("[0-9.]+")) ||
                (host.contains(':') && host.matches(Regex("[0-9a-fA-F:]+"))))) { "VPN peer must be a numeric IP address" }
            val address = InetAddress.getByName(host)
            require(!address.isAnyLocalAddress && !address.isMulticastAddress) { "Invalid VPN peer address" }
            val port = intent.getIntExtra(EXTRA_PORT, 0)
            val side = intent.getIntExtra(EXTRA_SIDE, -1)
            val encoded = intent.getStringExtra(EXTRA_KEY) ?: error("VPN key is required")
            require(encoded.length == 44) { "VPN key must be 32 bytes in Base64" }
            val key = Base64.getDecoder().decode(encoded)
            require(key.size == 32 && port in 1..65535 && side in 0..1) { "Invalid VPN key, port or side" }
            val created = Session(key)
            session = created
            mutableStatus.value = VpnStatus(starting = true)
            Thread({ runSession(created, address, port, side) }, "shadow6-vpn-receive").start()
        } catch (error: Exception) { finish(session, error.message ?: "VPN setup failed") }
        return START_NOT_STICKY
    }

    private fun reserveFreshKey(key: ByteArray) {
        // S6NA/1 counters restart at zero. Persist consumption before sending
        // anything, so crashes/restarts cannot reuse a key/nonce pair. Store
        // only fingerprints, never session keys. No automatic ledger pruning.
        val fingerprint = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(key))
        val preferences = getSharedPreferences("vpn-used-session-keys", MODE_PRIVATE)
        val used = preferences.getStringSet("fingerprints", emptySet())!!.toMutableSet()
        require(fingerprint !in used) { "This VPN session key was already used; configure a fresh key on both peers" }
        require(used.size < 4096) { "VPN key history is full; retire all previous session keys before reprovisioning" }
        used.add(fingerprint)
        check(preferences.edit().putStringSet("fingerprints", used).commit()) { "Cannot persist VPN nonce safety state" }
    }

    private fun runSession(current: Session, address: InetAddress, port: Int, side: Int) {
        try {
            reserveFreshKey(current.key)
            val codec = S6naCodec(current.key, 1400, side)
            current.key.fill(0)
            DatagramChannel.open().use { channel ->
                current.channel = channel
                if (!current.active.get()) return
                check(protect(channel.socket())) { "Could not protect the VPN carrier socket" }
                channel.connect(InetSocketAddress(address, port))
                channel.configureBlocking(true)
                val tun = Builder().setSession("Shadow6 S6NA VPN").setMtu(1400).setBlocking(false)
                    .addAddress("10.66.0.${side + 1}", 30).addRoute("0.0.0.0", 0)
                    .addAddress("fd66::${side + 1}", 126).addRoute("::", 0)
                    .addDnsServer("1.1.1.1").establish() ?: error("VPN authorization was revoked")
                current.descriptor = tun
                if (!current.active.get()) { tun.close(); return }
                synchronized(this) {
                    if (session === current && current.active.get()) mutableStatus.value = VpnStatus(running = true)
                }
                FileInputStream(tun.fileDescriptor).use { input ->
                    FileOutputStream(tun.fileDescriptor).use { output ->
                        current.sender = Thread({
                            try {
                                val packet = ByteArray(1400)
                                val ready = StructPollfd().apply { fd = tun.fileDescriptor; events = OsConstants.POLLIN.toShort() }
                                while (current.active.get()) {
                                    if (Os.poll(arrayOf(ready), 500) == 0) continue
                                    if (!current.active.get()) break
                                    check(ready.revents.toInt() and OsConstants.POLLIN != 0) { "VPN interface closed" }
                                    val size = input.read(packet)
                                    if (size < 0) { finish(current); break }
                                    if (size > 0) {
                                        val frame = codec.encode(packet.copyOf(size))
                                        check(channel.write(ByteBuffer.wrap(frame)) == frame.size) { "Incomplete VPN datagram" }
                                    }
                                }
                            } catch (error: Exception) {
                                if (current.active.get()) finish(current, error.message ?: "VPN send failed")
                            }
                        }, "shadow6-vpn-send").also { it.start() }
                        // One extra byte detects oversized/truncated datagrams.
                        val wire = ByteBuffer.allocate(1449)
                        while (current.active.get()) {
                            wire.clear()
                            val size = channel.read(wire)
                            if (size <= 0) continue
                            wire.flip()
                            val bytes = ByteArray(size)
                            wire.get(bytes)
                            val packet = try { codec.decode(bytes) } catch (_: Exception) { continue }
                            output.write(packet)
                        }
                    }
                }
            }
        } catch (error: Exception) {
            if (current.active.get()) finish(current, error.message ?: "VPN receive failed")
        } finally { current.close() }
    }

    @Synchronized private fun finish(current: Session?, error: String? = null) {
        if (current != null && session !== current) return
        current?.close()
        session = null
        mutableStatus.value = VpnStatus(error = error?.take(256))
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }
    override fun onRevoke() { finish(session); super.onRevoke() }
    override fun onDestroy() {
        session?.let { finish(it) }
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "org.shadow6.android.vpn.START"
        const val ACTION_STOP = "org.shadow6.android.vpn.STOP"
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_KEY = "key"
        const val EXTRA_SIDE = "side"
        private val mutableStatus = MutableStateFlow(VpnStatus())
        val status = mutableStatus.asStateFlow()
    }
}

data class VpnStatus(val starting: Boolean = false, val running: Boolean = false, val error: String? = null)
