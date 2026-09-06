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
    fun rejectsMalformedOrOutOfRangeProxyEndpoints() {
        assertNull(CoreRuntime.parseClientProxyPort("listening on 0.0.0.0:4433"))
        assertNull(CoreRuntime.parseClientProxyPort("[Client] Secure local proxy listening on 127.0.0.1:70000"))
    }
}
