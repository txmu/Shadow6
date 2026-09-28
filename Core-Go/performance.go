package main

import "runtime"

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
	// Copy batches and authenticated records serve different purposes. A
	// record must arrive in full before any plaintext is released over KCP.
	aeadRecordPlaintext   = 32 * 1024
	maxActiveTunnels      = 512
	maxControlConnections = 4096
	maxSessionsPerGrant   = 256
)

type transportBudget struct {
	window, socketBytes, copyBytes int
	congestionControl              bool
}

// Socket buffers are kernel memory; the KCP window bounds user-space queued
// segments. Mobile builds need smaller budgets for both, independently.
// The window is a capacity ceiling, not permission to burst that much data:
// kernels may clamp socket buffers far below our requested size. Keep KCP's
// congestion control on so losses reduce in-flight traffic on every platform.
func budgetForPlatform(platform string) transportBudget {
	if platform == "android" || platform == "ios" {
		return transportBudget{256, 256 * 1024, 32 * 1024, true}
	}
	return transportBudget{kcpSendWindow, dataSocketBufferBytes, proxyCopyBufferBytes, true}
}

var dataBudget = budgetForPlatform(runtime.GOOS)

func requiredBandwidthDelayBytes(bitsPerSecond, roundTripMilliseconds int64) int64 {
	return (bitsPerSecond*roundTripMilliseconds + 7999) / 8000
}

func configuredKCPWindowBytes() int64 {
	return int64(kcpMTU * kcpSendWindow)
}
