package org.shadow6.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CoreRuntimeTest {
    @Test
    fun packagedEnginesExposeTheirSharedNativeProfileIds() {
        assertEquals("go-kcp", CoreEngine.GO.profileId)
        assertEquals("rust-quic", CoreEngine.RUST.profileId)
        assertEquals("d-secure-stream", CoreEngine.D.profileId)
        assertEquals("nim-webrtc", CoreEngine.NIM.profileId)
    }

    @Test
    fun parsesLatestBoundedClientProxyEndpoint() {
        val output = """
            2026/09/02 [Client] Secure local proxy listening on 127.0.0.1:34129
            2026/09/02 [Client] Secure local proxy listening on 127.0.0.1:41399
        """.trimIndent()
        assertEquals(41399, CoreRuntime.parseClientProxyPort(output))
    }

    @Test
    fun parsesNimClientProxyEndpointWithoutClientPrefix() {
        assertEquals(24835, CoreRuntime.parseClientProxyPort("Local proxy listening on 127.0.0.1:24835\n"))
    }

    @Test
    fun rejectsMalformedOrOutOfRangeProxyEndpoints() {
        assertNull(CoreRuntime.parseClientProxyPort("listening on 0.0.0.0:4433"))
        assertNull(CoreRuntime.parseClientProxyPort("[Client] Secure local proxy listening on 127.0.0.1:70000"))
    }

    @Test
    fun onlyAcceptsStructuredReadyEndpointThatMatchesTheNativeProfile() {
        val profile = NativeProfileDescriptor("go-kcp", "go", true, "kcp",
            mapOf("kind" to "stream", "mode" to "localhost-tcp-proxy"), emptyMap(),
            "Core-Go/shadow6-go", "sha256:" + "0".repeat(64))
        val event = """{"event":"shadow6.ready","schema":1,"core":"shadow6-go","role":"client","application_boundary":{"kind":"stream","mode":"localhost-tcp-proxy","endpoint":{"host":"127.0.0.1","port":34129}}}"""
        assertEquals(34129, CoreRuntime.parseClientReadyEndpoint(event, CoreEngine.GO, profile))
        assertNull(CoreRuntime.parseClientReadyEndpoint(event.replace("localhost-tcp-proxy", "other"), CoreEngine.GO, profile))
        assertNull(CoreRuntime.parseClientReadyEndpoint(event.replace("shadow6-go", "shadow6-rust"), CoreEngine.GO, profile))
        assertNull(CoreRuntime.parseClientReadyEndpoint(event.replace("34129", "4295001425"), CoreEngine.GO, profile))
        assertNull(CoreRuntime.parseClientReadyEndpoint(event.replace("\"schema\":1", "\"schema\":1,\"extra\":true"), CoreEngine.GO, profile))
    }

    @Test
    fun processStatUsesParentAndStartTicksWithParenthesesInTheCommand() {
        val fields = MutableList(20) { "0" }
        fields[0] = "S"
        fields[1] = "123"
        fields[19] = "4567"
        assertEquals(123L to 4567L, CoreRuntime.procDetails("999 (core (worker)) " + fields.joinToString(" ")))
        fields[19] = "-1"
        assertNull(CoreRuntime.procDetails("999 (core) " + fields.joinToString(" ")))
        assertNull(CoreRuntime.procDetails("999 (core) S 123"))
    }

    @Test
    fun processOutputMustContainAnActualCoreListenerEventForListenerReadiness() {
        assertEquals(false, CoreRuntime.brokerListenerReported("PID 42 alive\n"))
        assertEquals(true, CoreRuntime.brokerListenerReported("[Broker] Listening on 127.0.0.1:4433\n"))
    }

    @Test
    fun classifiesIpv4AndIpv6LoopbackAccess() {
        for (host in listOf("127.0.0.1", "127.255.0.7", "::1", "[::1]", "localhost")) {
            assertEquals("loopback", CoreStatus(host = host).access)
        }
        for (host in listOf("0.0.0.0", "::", "192.0.2.1", "2001:db8::1", "example.test")) {
            assertEquals("network", CoreStatus(host = host).access)
        }
    }

    @Test
    fun runtimeObservationUsesTheCanonicalDeploymentFieldSet() {
        val observation = RuntimeObservation(
            core = "go", profile = "go-kcp", nativeTransport = "kcp",
            applicationBoundary = "stream/localhost-tcp-proxy", observedAt = 1000,
            pid = 123, processIdentity = "01234567-89ab-cdef-0123-456789abcdef:10",
            processes = listOf(ObservedProcessIdentity(124,
                "01234567-89ab-cdef-0123-456789abcdef:11")),
            endpoint = mapOf("host" to "127.0.0.1", "port" to 4242,
                "boundary" to "stream", "mode" to "localhost-tcp-proxy",
                "observation" to "structured-ready-event",
                "owner" to mapOf("pid" to 124L,
                    "processIdentity" to "01234567-89ab-cdef-0123-456789abcdef:11")),
            readiness = "application-ready", applicationReadiness = "ready",
        ).toJson()
        assertEquals(setOf("observedAt", "pid", "processIdentity", "processes", "nativeEndpoints",
            "endpoints", "endpoint", "readiness", "transportReadiness", "applicationReadiness"),
            observation.keySet())
        assertEquals("application-ready", observation.getString("readiness"))
        assertEquals("structured-ready-event", observation.getJSONObject("endpoint").getString("observation"))
        assertEquals(124L, observation.getJSONObject("endpoint").getJSONObject("owner").getLong("pid"))
    }
}
