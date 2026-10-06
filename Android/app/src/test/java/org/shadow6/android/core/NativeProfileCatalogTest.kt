package org.shadow6.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class NativeProfileCatalogTest {
    @Test
    fun strictCatalogKeepsTwelveCoreDenominatorAndRegisteredProfileSemantics() {
        val entries = (0 until 12).map { index ->
            """{"id":"core$index-kcp","core":"core$index","primary":true,"nativeTransport":"kcp","applicationBoundary":{"kind":"stream","mode":"localhost-tcp-proxy"},"requirements":{},"artifact":"Core-Test/shadow6-core$index","contractDigest":"sha256:${"0".repeat(64)}"}"""
        } + listOf("""{"id":"core0-alt","core":"core0","primary":false,"nativeTransport":"alt","applicationBoundary":{"kind":"message","mode":"seqpacket-fd"},"requirements":{},"artifact":"Core-Test/shadow6-core0","contractDigest":"sha256:${"1".repeat(64)}"}""")
        val source = """{"schema":"shadow6.android-native-profile-catalog.v1","sourceSchema":"shadow6.native-profile.v1","profiles":[${entries.joinToString(",")}] }"""
        val parsed = NativeProfileCatalog.load(ByteArrayInputStream(source.toByteArray()))
        assertEquals(13, parsed.size)
        assertEquals(12, parsed.count { it.primary })
        assertEquals("message", parsed.last().applicationBoundary["kind"])
        val availability = NativeProfileCatalog.availability(parsed,
            artifactPresent = { it.core == "core0" },
            runtimeBound = { it.id == "core0-kcp" })
        assertEquals("RUNNABLE", availability.first().state)
        assertEquals("ARTIFACT-UNBOUND", availability.last().state)
        assertTrue(availability.drop(1).take(11).all { it.state == "NOT-PACKAGED" })
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsDuplicateNativeProfileIds() {
        val one = """{"id":"core-kcp","core":"core","primary":true,"nativeTransport":"kcp","applicationBoundary":{"kind":"stream","mode":"localhost-tcp-proxy"},"requirements":{},"artifact":"Core-Test/shadow6-core","contractDigest":"sha256:${"0".repeat(64)}"}"""
        val source = """{"schema":"shadow6.android-native-profile-catalog.v1","sourceSchema":"shadow6.native-profile.v1","profiles":[${List(12) { one }.joinToString(",")}] }"""
        NativeProfileCatalog.load(ByteArrayInputStream(source.toByteArray()))
    }
}
