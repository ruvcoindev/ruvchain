package multicast

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/gologme/log"
	"github.com/ruvcoindev/ruvchain/src/core"
	"github.com/stretchr/testify/require"
)

func TestFullMulticastWorkflow(t *testing.T) {
	// Используем правильный конструктор конфига
	cfg := core.NewConfig()
	require.NoError(t, cfg.GenerateSelfSignedCertificate())

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	node := createTestNode(t, cfg, key)
	defer node.Core.Stop()
	defer node.Multicast.Stop()

	t.Run("Basic functionality", func(t *testing.T) {
		require.True(t, node.Multicast.IsStarted())
	})
}


func createTestNode(t *testing.T, cfg *core.Config, key []byte) struct {
	Core     *core.Core
	Multicast *Multicast
} {
	node, err := core.New(cfg.Certificate, log.New(os.Stderr, "", 0))
	require.NoError(t, err)

	mcast, err := New(
		node,
		log.New(os.Stderr, "", 0),
		WithMulticastInterface(MulticastInterface{
			Regex:    regexp.MustCompile(".*"),
			Beacon:   true,
			Listen:   true,
			Port:     5001,
			Password: hex.EncodeToString(key),
		}),
	)
	require.NoError(t, err)

	return struct {
		Core     *core.Core
		Multicast *Multicast
	}{
		Core:      node,
		Multicast: mcast,
	}
}

type Option func(*Multicast) error

func WithMulticastInterface(intf MulticastInterface) Option {
	return func(m *Multicast) error {
		m.config._interfaces[intf] = struct{}{}
		return nil
	}
}
