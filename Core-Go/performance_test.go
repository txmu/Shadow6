package main

import (
	"bytes"
	"io"
	"testing"
)

// Exercise the same optional interfaces as TCPConn without opening sockets.
type copyBudgetReader struct {
	*bytes.Reader
	maxRead int
}

func (reader *copyBudgetReader) Read(destination []byte) (int, error) {
	if len(destination) > reader.maxRead {
		reader.maxRead = len(destination)
	}
	return reader.Reader.Read(destination)
}

func (*copyBudgetReader) WriteTo(io.Writer) (int64, error) {
	panic("WriterTo bypassed the copy budget")
}

type copyBudgetWriter struct {
	bytes.Buffer
	maxWrite int
}

func (writer *copyBudgetWriter) Write(source []byte) (int, error) {
	if len(source) > writer.maxWrite {
		writer.maxWrite = len(source)
	}
	return writer.Buffer.Write(source)
}

func (*copyBudgetWriter) ReadFrom(io.Reader) (int64, error) {
	panic("ReaderFrom bypassed the copy budget")
}

func TestPooledCopyUsesPlatformBudget(t *testing.T) {
	payload := bytes.Repeat([]byte("bounded encrypted copy"), dataBudget.copyBytes/7)
	source := &copyBudgetReader{Reader: bytes.NewReader(payload)}
	destination := &copyBudgetWriter{}
	n, err := copyWithPooledBuffer(destination, source)
	if err != nil || n != int64(len(payload)) || !bytes.Equal(destination.Bytes(), payload) {
		t.Fatalf("pooled copy corrupted data: bytes=%d err=%v", n, err)
	}
	if source.maxRead != dataBudget.copyBytes || destination.maxWrite != dataBudget.copyBytes {
		t.Fatalf("copy budget bypassed: read=%d write=%d budget=%d", source.maxRead, destination.maxWrite, dataBudget.copyBytes)
	}
}

func TestMobileTransportBudget(t *testing.T) {
	for _, platform := range []string{"android", "ios"} {
		budget := budgetForPlatform(platform)
		if budget.window*kcpMTU > 512*1024 || budget.socketBytes > 512*1024 || budget.copyBytes > 64*1024 || !budget.congestionControl {
			t.Fatalf("unbounded mobile profile for %s: %+v", platform, budget)
		}
	}
	desktop := budgetForPlatform("linux")
	for _, platform := range []string{"linux", "windows", "darwin", "freebsd", "openbsd", "netbsd"} {
		if !budgetForPlatform(platform).congestionControl {
			t.Fatalf("%s can burst the full capacity window without congestion control", platform)
		}
	}
	if int64(desktop.window*kcpMTU) < requiredBandwidthDelayBytes(targetThroughputBitsPerSecond, designRoundTripMilliseconds) {
		t.Fatal("desktop capacity contract regressed")
	}
}
