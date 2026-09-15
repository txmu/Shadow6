package main

import "testing"

func TestMobileTransportBudget(t *testing.T) {
	for _, platform := range []string{"android", "ios"} {
		budget := budgetForPlatform(platform)
		if budget.window*kcpMTU > 512*1024 || budget.socketBytes > 512*1024 || budget.copyBytes > 64*1024 || !budget.congestionControl {
			t.Fatalf("unbounded mobile profile for %s: %+v", platform, budget)
		}
	}
	desktop := budgetForPlatform("linux")
	if int64(desktop.window*kcpMTU) < requiredBandwidthDelayBytes(targetThroughputBitsPerSecond, designRoundTripMilliseconds) {
		t.Fatal("desktop capacity contract regressed")
	}
}
