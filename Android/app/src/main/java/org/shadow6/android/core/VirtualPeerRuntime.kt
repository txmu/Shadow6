package org.shadow6.android.core

import android.util.Base64
import org.shadow6.android.security.StrictJson
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Collections
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Bounded loopback bridge from an Android native Core to the packaged Gate. */
class VirtualPeerRuntime {
    private val active = AtomicInteger()
    private val sockets = Collections.synchronizedSet(mutableSetOf<AutoCloseable>())
    private var listener: AutoCloseable? = null
    private var acceptThread: Thread? = null
    private var workers: ThreadPoolExecutor? = null

    @Synchronized fun running(): Boolean = acceptThread?.isAlive == true

    @Synchronized fun stop() {
        listener?.close()
        listener = null
        synchronized(sockets) { sockets.toList().forEach { runCatching { it.close() } }; sockets.clear() }
        workers?.shutdownNow()
        workers?.awaitTermination(2, TimeUnit.SECONDS)
        workers = null
        acceptThread?.interrupt()
        acceptThread?.join(1000)
        acceptThread = null
        active.set(0)
    }

    @Synchronized fun start(code: String, profile: Map<String, Any?>, core: String, role: CoreRole,
                            localPort: Int = 1087, gatePort: Int = 1086) {
        require(role == CoreRole.CLIENT || role == CoreRole.AGENT)
        require(localPort in 1024..65535 && gatePort in 1024..65535 && localPort != gatePort)
        require(KeyFactory.getInstance("Ed25519") != null && Signature.getInstance("Ed25519") != null) {
            "This Android release needs an Ed25519 provider for Virtual Peer"
        }
        val routes = profile["routes"] as? List<*> ?: error("Missing Core routes")
        val route = routes.map(StrictJson::objectValue).singleOrNull { it["core"] == core } ?: error("Core is absent from public node")
        val transport = route["transport"] as? String ?: error("Invalid Core carrier")
        require(transport == "tcp" || transport == "udp")
        val admissionPublic = profile["admission_public_key"] as? String ?: error("Missing admission identity")
        require(admissionPublic.matches(Regex("[0-9a-f]{64}")))
        fun verifiedKey(purpose: String, publicHex: String): java.security.PrivateKey {
            require(publicHex.matches(Regex("[0-9a-f]{64}"))) { "Invalid public-node identity" }
            val seed = PublicNodeCode.seed(code, purpose)
            val privateKey = KeyFactory.getInstance("Ed25519").generatePrivate(
                PKCS8EncodedKeySpec(byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20) + seed))
            val publicBytes = publicHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val verifiedPublic = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(
                byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00) + publicBytes))
            val challenge = "shadow6.public-node.identity.v1".toByteArray(Charsets.US_ASCII)
            val proof = Signature.getInstance("Ed25519").apply { initSign(privateKey); update(challenge) }.sign()
            require(Signature.getInstance("Ed25519").apply { initVerify(verifiedPublic); update(challenge) }.verify(proof)) {
                "Profile identity does not match the join code"
            }
            return privateKey
        }
        val key = verifiedKey("admission", admissionPublic)
        val roleName = role.name.lowercase()
        verifiedKey("core:$core:$roleName", route["native_${roleName}_public_key"] as? String ?: "")
        val publicBytes = admissionPublic.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val tenant = profile["tenant"] as? String ?: error("Missing tenant")
        val identity = "invite-${PublicNodeCode.decode(code).lookupId.take(16)}-${role.name.lowercase()}"
        fun admission(): ByteArray {
            val now = System.currentTimeMillis() / 1000
            val nonce = ByteArray(32).also(SecureRandom()::nextBytes)
            val unsigned = mapOf("schema" to "shadow6.virtual-broker-admission.v1", "tenant" to tenant,
                "client" to identity, "core" to core, "issued" to now, "expires" to now + 60,
                "nonce" to Base64.encodeToString(nonce, Base64.NO_WRAP),
                "public_key" to Base64.encodeToString(publicBytes, Base64.NO_WRAP))
            val signature = Signature.getInstance("Ed25519").apply { initSign(key); update(StrictJson.canonical(unsigned).toByteArray(Charsets.UTF_8)) }.sign()
            return StrictJson.canonical(unsigned + ("signature" to Base64.encodeToString(signature, Base64.NO_WRAP))).toByteArray(Charsets.UTF_8)
        }

        stop()
        val pool = ThreadPoolExecutor(32, 32, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(32))
        workers = pool
        if (transport == "tcp") {
            val server = ServerSocket(localPort, 32, InetAddress.getByName("127.0.0.1"))
            listener = server
            acceptThread = Thread({
                while (!server.isClosed) {
                    val incoming = try { server.accept() } catch (_: Exception) { break }
                    if (active.incrementAndGet() > 32) { active.decrementAndGet(); incoming.close(); continue }
                    try { pool.execute { tcp(incoming, gatePort, ::admission) } }
                    catch (_: RuntimeException) { active.decrementAndGet(); incoming.close() }
                }
            }, "shadow6-virtual-peer-tcp").apply { isDaemon = true; start() }
        } else {
            val server = DatagramSocket(localPort, InetAddress.getByName("127.0.0.1"))
            listener = server
            acceptThread = Thread({
                val buffer = ByteArray(65_508)
                while (!server.isClosed) {
                    val packet = DatagramPacket(buffer, buffer.size)
                    try { server.receive(packet) } catch (_: Exception) { break }
                    if (packet.length !in 1..65_507 || active.incrementAndGet() > 32) {
                        active.decrementAndGet(); continue
                    }
                    val payload = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    val source = packet.socketAddress
                    try { pool.execute { udp(server, source, payload, gatePort, ::admission) } }
                    catch (_: RuntimeException) { active.decrementAndGet() }
                }
            }, "shadow6-virtual-peer-udp").apply { isDaemon = true; start() }
        }
    }

    private fun tcp(incoming: Socket, gatePort: Int, admission: () -> ByteArray) {
        sockets.add(incoming)
        var remote: Socket? = null
        try {
            incoming.soTimeout = 120_000
            remote = Socket("127.0.0.1", gatePort).also { it.soTimeout = 120_000; sockets.add(it) }
            val request = admission()
            require(request.size in 1..16_384)
            remote.getOutputStream().write(byteArrayOf((request.size ushr 24).toByte(),
                (request.size ushr 16).toByte(), (request.size ushr 8).toByte(), request.size.toByte()) + request)
            val upstream = remote ?: error("Gate socket unavailable")
            val reverse = Thread({ copy(upstream, incoming) }, "shadow6-virtual-peer-reverse").apply { isDaemon = true; start() }
            copy(incoming, upstream)
            reverse.join(1000)
        } catch (_: Exception) {
            // An invalid or refused admission closes only this local connection.
        } finally {
            incoming.close()
            remote?.close()
            sockets.remove(incoming)
            if (remote != null) sockets.remove(remote)
            active.updateAndGet { count -> maxOf(0, count - 1) }
        }
    }

    private fun copy(source: Socket, target: Socket) {
        try {
            val input = source.getInputStream()
            val output = target.getOutputStream()
            val buffer = ByteArray(65_536)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                output.write(buffer, 0, count)
            }
            target.shutdownOutput()
        } catch (_: Exception) { /* The peer or deadline closed this stream. */ }
    }

    private fun udp(listener: DatagramSocket, source: java.net.SocketAddress, payload: ByteArray,
                    gatePort: Int, admission: () -> ByteArray) {
        DatagramSocket().use { remote ->
            sockets.add(remote)
            try {
                remote.soTimeout = 120_000
                remote.connect(InetAddress.getByName("127.0.0.1"), gatePort)
                val request = admission()
                val frame = byteArrayOf((request.size ushr 8).toByte(), request.size.toByte()) + request + payload
                if (frame.size > 65_507) return
                remote.send(DatagramPacket(frame, frame.size))
                val reply = DatagramPacket(ByteArray(65_508), 65_508)
                remote.receive(reply)
                if (reply.length in 1..65_507 && !listener.isClosed)
                    listener.send(DatagramPacket(reply.data, reply.length, source))
            } catch (_: Exception) { /* One datagram cannot take down the listener. */ }
            finally { sockets.remove(remote); active.updateAndGet { count -> maxOf(0, count - 1) } }
        }
    }
}

object VirtualPeerController {
    private val instance = VirtualPeerRuntime()
    fun runtime(): VirtualPeerRuntime = instance
}
