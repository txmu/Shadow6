package main

// The high-throughput contract is shared by the Go data-plane setup and its
// tests.  It is a capacity target, not a claim that every CPU, kernel, NIC, or
// path can sustain this rate.
const (
	targetThroughputBitsPerSecond int64 = 10_000_000_000
	designRoundTripMilliseconds   int64 = 50
	kcpMTU                              = 1350
	kcpSendWindow                       = 65_535
	kcpReceiveWindow                    = 65_535
	dataSocketBufferBytes               = 32 * 1024 * 1024
	proxyCopyBufferBytes                = 256 * 1024
	maxAEADPlaintext                    = 1024 * 1024
	maxActiveTunnels                    = 512
	maxControlConnections               = 4096
	maxSessionsPerGrant                 = 256
)

func requiredBandwidthDelayBytes(bitsPerSecond, roundTripMilliseconds int64) int64 {
	return (bitsPerSecond*roundTripMilliseconds + 7999) / 8000
}

func configuredKCPWindowBytes() int64 {
	return int64(kcpMTU * kcpSendWindow)
}
