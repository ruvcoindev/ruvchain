package core

import (
	"bytes"
	"crypto/rand"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/gologme/log"
	"github.com/ruvcoindev/ruvchain/src/config"
)

// GetLoggerWithPrefix creates a new logger instance with prefix.
// If verbose is set to true, three log levels are enabled: "info", "warn", "error".
func GetLoggerWithPrefix(prefix string, verbose bool) *log.Logger {
	l := log.New(os.Stderr, prefix, log.Flags())
	if !verbose {
		return l
	}
	l.EnableLevel("info")
	l.EnableLevel("warn")
	l.EnableLevel("error")
	return l
}

func require_NoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func require_Equal[T comparable](t *testing.T, a, b T) {
	t.Helper()
	if a != b {
		t.Fatalf("%v != %v", a, b)
	}
}

func require_True(t *testing.T, a bool) {
	t.Helper()
	if !a {
		t.Fatal("expected true")
	}
}

// CreateAndConnectTwo creates two nodes. nodeB connects to nodeA.
// Verbosity flag is passed to logger.
func CreateAndConnectTwo(t testing.TB, verbose bool) (nodeA *Core, nodeB *Core) {
	var err error

	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	if err = cfgA.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	if err = cfgB.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}

	logger := GetLoggerWithPrefix("", false)
	logger.EnableLevel("debug")

	if nodeA, err = New(cfgA.Certificate, logger); err != nil {
		t.Fatal(err)
	}
	if nodeB, err = New(cfgB.Certificate, logger); err != nil {
		t.Fatal(err)
	}

	nodeAListenURL, err := url.Parse("tcp://localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	nodeAListener, err := nodeA.Listen(nodeAListenURL, "")
	if err != nil {
		t.Fatal(err)
	}
	nodeAURL, err := url.Parse("tcp://" + nodeAListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err = nodeB.CallPeer(nodeAURL, ""); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)

	if l := len(nodeA.GetPeers()); l != 1 {
		t.Fatal("unexpected number of peers", l)
	}
	if l := len(nodeB.GetPeers()); l != 1 {
		t.Fatal("unexpected number of peers", l)
	}

	return nodeA, nodeB
}

// WaitConnected blocks until either nodes negotiated DHT or 5 seconds passed.
func WaitConnected(nodeA, nodeB *Core) bool {
	// It may take up to 3 seconds, but let's wait 5.
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		/*
			if len(nodeA.GetPeers()) > 0 && len(nodeB.GetPeers()) > 0 {
				return true
			}
		*/
		if len(nodeA.GetTree()) > 1 && len(nodeB.GetTree()) > 1 {
			time.Sleep(3 * time.Second) // FIXME hack, there's still stuff happening internally
			return true
		}
	}
	return false
}

// CreateEchoListener creates a routine listening on nodeA. It expects repeats messages of length bufLen.
// It returns a channel used to synchronize the routine with caller.
func CreateEchoListener(t testing.TB, nodeA *Core, bufLen int, repeats int) chan struct{} {
	// Start routine
	done := make(chan struct{})
	go func() {
		buf := make([]byte, bufLen)
		res := make([]byte, bufLen)
		for i := 0; i < repeats; i++ {
			n, from, err := nodeA.ReadFrom(buf)
			if err != nil {
				t.Error(err)
				return
			}
			if n != bufLen {
				t.Error("missing data")
				return
			}
			copy(res, buf)
			copy(res[8:24], buf[24:40])
			copy(res[24:40], buf[8:24])
			_, err = nodeA.WriteTo(res, from)
			if err != nil {
				t.Error(err)
			}
		}
		done <- struct{}{}
	}()

	return done
}

// TestCore_Start_Connect checks if two nodes can connect together.
func TestCore_Start_Connect(t *testing.T) {
	CreateAndConnectTwo(t, true)
}

// TestCore_Start_Transfer checks that messages can be passed between nodes (in both directions).
func TestCore_Start_Transfer(t *testing.T) {
	nodeA, nodeB := CreateAndConnectTwo(t, true)
	defer nodeA.Stop()
	defer nodeB.Stop()

	msgLen := 1500
	done := CreateEchoListener(t, nodeA, msgLen, 1)

	if !WaitConnected(nodeA, nodeB) {
		t.Fatal("nodes did not connect")
	}

	// Send
	msg := make([]byte, msgLen)
	_, _ = rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], nodeB.Address())
	copy(msg[24:40], nodeA.Address())
	_, err := nodeB.WriteTo(msg, nodeA.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, msgLen)
	_, _, err = nodeB.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg[40:], buf[40:]) {
		t.Fatal("expected echo")
	}
	<-done
}

// BenchmarkCore_Start_Transfer estimates the possible transfer between nodes (in MB/s).
func BenchmarkCore_Start_Transfer(b *testing.B) {
	nodeA, nodeB := CreateAndConnectTwo(b, false)

	msgLen := 1500 // typical MTU
	done := CreateEchoListener(b, nodeA, msgLen, b.N)

	if !WaitConnected(nodeA, nodeB) {
		b.Fatal("nodes did not connect")
	}

	// Send
	msg := make([]byte, msgLen)
	_, _ = rand.Read(msg[40:])
	msg[0] = 0x60
	copy(msg[8:24], nodeB.Address())
	copy(msg[24:40], nodeA.Address())

	buf := make([]byte, msgLen)

	b.SetBytes(int64(msgLen))
	b.ResetTimer()

	addr := nodeA.LocalAddr()
	for i := 0; i < b.N; i++ {
		_, err := nodeB.WriteTo(msg, addr)
		if err != nil {
			b.Fatal(err)
		}
		_, _, err = nodeB.ReadFrom(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
	<-done
}

func TestAllowedPublicKeys(t *testing.T) {
	logger := GetLoggerWithPrefix("", false)
	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	require_NoError(t, cfgA.GenerateSelfSignedCertificate())
	require_NoError(t, cfgB.GenerateSelfSignedCertificate())

	nodeA, err := New(cfgA.Certificate, logger, AllowedPublicKey("abcdef"))
	require_NoError(t, err)
	defer nodeA.Stop()

	nodeB, err := New(cfgB.Certificate, logger)
	require_NoError(t, err)
	defer nodeB.Stop()

	u, err := url.Parse("tcp://localhost:0")
	require_NoError(t, err)

	l, err := nodeA.Listen(u, "")
	require_NoError(t, err)

	u, err = url.Parse("tcp://" + l.Addr().String())
	require_NoError(t, err)

	require_NoError(t, nodeB.AddPeer(u, ""))

	time.Sleep(time.Second)

	peers := nodeB.GetPeers()
	require_Equal(t, len(peers), 1)
	require_True(t, !peers[0].Up)
	require_True(t, peers[0].LastError != nil)
}

func TestAllowedPublicKeysLocal(t *testing.T) {
	logger := GetLoggerWithPrefix("", false)
	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	require_NoError(t, cfgA.GenerateSelfSignedCertificate())
	require_NoError(t, cfgB.GenerateSelfSignedCertificate())

	nodeA, err := New(cfgA.Certificate, logger, AllowedPublicKey("abcdef"))
	require_NoError(t, err)
	defer nodeA.Stop()

	nodeB, err := New(cfgB.Certificate, logger)
	require_NoError(t, err)
	defer nodeB.Stop()

	u, err := url.Parse("tcp://localhost:0")
	require_NoError(t, err)

	l, err := nodeA.ListenLocal(u, "")
	require_NoError(t, err)

	u, err = url.Parse("tcp://" + l.Addr().String())
	require_NoError(t, err)

	require_NoError(t, nodeB.AddPeer(u, ""))

	time.Sleep(time.Second)

	peers := nodeB.GetPeers()
	require_Equal(t, len(peers), 1)
	require_True(t, peers[0].Up)
	require_True(t, peers[0].LastError == nil)
}
