package org.shadow6.android.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PublicNodeCodeTest {
    private val code = "A8YzZAoBuwABAgMEBQYHCAkKCwwNDg8QERITFBUW"

    @Test fun pythonWireVector() {
        val info = PublicNodeCode.decode(code)
        assertEquals("ipv4-https", info.mode)
        assertEquals("198.51.100.10", info.httpsHost)
        assertEquals(443, info.httpsPort)
        assertEquals("29ba43311f908fa99653084749d2078ded0d30252704a1c7f5cd3f082a03b082", info.lookupId)
        assertEquals("947f4e6ac07bd4c002398dddbd985317363a8b80473fd39760ae819ba9c16cb7",
            PublicNodeCode.seed(code, "gate").joinToString("") { "%02x".format(it.toInt() and 255) })
    }

    @Test fun manualProfileRequiresIndependentPin() {
        val manualCode = "AsYzZAoBuwABAgMEBQYHCAkKCwwNDg8QERITFBUW"
        val profile = """{"schema":"shadow6.public-node-profile.v1","lookup_id":"96c17975f8bd4891096e8e5d8b5ee1829da15f2c3eef008701debdff5655b69e","tenant":"demo","admission_public_key":"1786a03233fb73476af5cbea49c7cafa68403bd6d00844431a8e15f32d85782c","routes":[{"core":"go","transport":"tcp","gate_host":"198.51.100.10","gate_port":5443,"gate_public_key":"${"a".repeat(64)}","native_broker_public_key":"${"b".repeat(64)}","native_client_public_key":"b4c28b0604f4ce539c8a35fcf73dafb1f262e1e4d3497e33cb3faf149a046838","native_agent_public_key":"fa2433cb778b70845565877354badc0be24b4f2bb0dedba71a9a8f4198eed1b6","default_agent_id":"","default_agent_public_key":""}]}"""
        assertEquals("manual", PublicNodeCode.decode(manualCode).mode)
        assertEquals("demo", PublicNodeCode.profile(manualCode, manualJson = profile, manualPin = "a".repeat(64))["tenant"])
        assertTrue(runCatching { PublicNodeCode.profile(manualCode, manualJson = profile, manualPin = "b".repeat(64)) }.isFailure)
    }
}
