package org.shadow6.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CoreRuntimeTest {
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
    fun classifiesIpv4AndIpv6LoopbackAccess() {
        for (host in listOf("127.0.0.1", "127.255.0.7", "::1", "[::1]", "localhost")) {
            assertEquals("loopback", CoreStatus(host = host).access)
        }
        for (host in listOf("0.0.0.0", "::", "192.0.2.1", "2001:db8::1", "example.test")) {
            assertEquals("network", CoreStatus(host = host).access)
        }
    }
}
