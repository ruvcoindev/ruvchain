// internal/core/core.go
package core

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gologme/log"
	"github.com/ruvcoindev/ruvchain/internal/config"
	"github.com/ruvcoindev/ruvchain/internal/crypto"
	"github.com/ruvcoindev/ruvchain/internal/network"
	"github.com/ruvcoindev/ruvchain/internal/protocol"
)

var (
	ErrPeerAlreadyConnected = errors.New("peer already connected")
	ErrInvalidHandshake     = errors.New("invalid handshake")
)

type Core struct {
	mu          sync.RWMutex
	config      *config.Config
	logger      *log.Logger
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	nodeID      [32]byte
	peers       map[[32]byte]*network.Peer
	transport   network.Transport
	running     bool
	shutdownCh  chan struct{}
	peerHandler PeerHandler
}

type PeerHandler interface {
	HandleMessage(msg *protocol.Message) error
	HandleNewPeer(p *network.Peer)
	HandleDisconnect(p *network.Peer)
}

func New(cfg *config.Config, logger *log.Logger) (*Core, error) {
	if len(cfg.PrivateKey) != ed25519.PrivateKeySize*2 {
		return nil, fmt.Errorf("invalid private key length")
	}

	privateKeyBytes, err := hex.DecodeString(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	if len(privateKeyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	privateKey := ed25519.PrivateKey(privateKeyBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &Core{
		config:      cfg,
		logger:      logger,
		privateKey: privateKey,
		publicKey:   publicKey,
		nodeID:      crypto.DeriveNodeID(privateKey),
		peers:       make(map[[32]byte]*network.Peer),
		transport:   network.NewTCPTransport(cfg.ListenAddr),
		shutdownCh:  make(chan struct{}),
	}, nil
}

func (c *Core) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return errors.New("core already running")
	}

	if err := c.transport.Listen(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}

	c.running = true
	go c.listenLoop()
	go c.connectionCleanupLoop()

	c.logger.Info("Core started successfully")
	return nil
}

func (c *Core) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return
	}

	close(c.shutdownCh)
	c.transport.Close()

	for _, peer := range c.peers {
		peer.Close()
	}

	c.running = false
	c.logger.Info("Core stopped")
}

func (c *Core) listenLoop() {
	for {
		select {
		case <-c.shutdownCh:
			return
		default:
			conn, err := c.transport.Accept()
			if err != nil {
				if network.IsClosedError(err) {
					return
				}
				c.logger.Warnf("Accept error: %v", err)
				continue
			}

			go c.handleNewConnection(conn)
		}
	}
}

func (c *Core) handleNewConnection(conn net.Conn) {
	c.logger.Infof("New connection from %s", conn.RemoteAddr())

	peer := network.NewPeer(conn)
	defer peer.Close()

	if err := c.performHandshake(peer); err != nil {
		c.logger.Warnf("Handshake failed with %s: %v", conn.RemoteAddr(), err)
		return
	}

	c.addPeer(peer)
	defer c.removePeer(peer)

	c.peerHandler.HandleNewPeer(peer)

	if err := c.readLoop(peer); err != nil {
		c.logger.Warnf("Read loop error for %s: %v", peer.ID(), err)
	}
}

func (c *Core) performHandshake(p *network.Peer) error {
	// Отправка нашего handshake
	hs := &protocol.Handshake{
		Version:    protocol.ProtocolVersion,
		NodeID:     c.nodeID,
		ListenPort: uint16(c.transport.Port()),
		Timestamp:  time.Now().Unix(),
	}

	sig := ed25519.Sign(c.privateKey, hs.Bytes())
	hs.Signature = sig

	if err := p.SendHandshake(hs); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// Получение ответного handshake
	remoteHS, err := p.ReceiveHandshake()
	if err != nil {
		return fmt.Errorf("failed to receive handshake: %w", err)
	}

	// Валидация полученного handshake
	if remoteHS.Version != protocol.ProtocolVersion {
		return fmt.Errorf("protocol version mismatch: %d != %d",
			remoteHS.Version, protocol.ProtocolVersion)
	}

	if !ed25519.Verify(remoteHS.PublicKey, remoteHS.Bytes(), remoteHS.Signature) {
		return ErrInvalidHandshake
	}

	p.SetID(remoteHS.NodeID)
	p.SetPublicKey(remoteHS.PublicKey)

	return nil
}

func (c *Core) addPeer(p *network.Peer) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.peers[p.ID()]; exists {
		p.Close()
		return
	}

	c.peers[p.ID()] = p
	c.logger.Infof("Added new peer %x", p.ID())
}

func (c *Core) removePeer(p *network.Peer) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.peers[p.ID()]; exists {
		delete(c.peers, p.ID())
		c.logger.Infof("Removed peer %x", p.ID())
		c.peerHandler.HandleDisconnect(p)
	}
}

func (c *Core) readLoop(p *network.Peer) error {
	for {
		select {
		case <-c.shutdownCh:
			return nil
		default:
			msg, err := p.ReadMessage()
			if err != nil {
				return fmt.Errorf("read error: %w", err)
			}

			if err := c.validateMessage(msg); err != nil {
				return fmt.Errorf("invalid message: %w", err)
			}

			if err := c.peerHandler.HandleMessage(msg); err != nil {
				return fmt.Errorf("message handling failed: %w", err)
			}
		}
	}
}

func (c *Core) validateMessage(msg *protocol.Message) error {
	if msg == nil {
		return errors.New("nil message")
	}

	if time.Since(time.Unix(msg.Timestamp, 0)) > 5*time.Minute {
		return errors.New("message too old")
	}

	if !ed25519.Verify(msg.SenderPublicKey, msg.Bytes(), msg.Signature) {
		return errors.New("invalid message signature")
	}

	return nil
}

func (c *Core) connectionCleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.shutdownCh:
			return
		case <-ticker.C:
			c.cleanupStaleConnections()
		}
	}
}

func (c *Core) cleanupStaleConnections() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for id, peer := range c.peers {
		if now.Sub(peer.LastActive()) > 5*time.Minute {
			peer.Close()
			delete(c.peers, id)
			c.logger.Infof("Cleaned up stale connection to %x", id)
		}
	}
}

func (c *Core) GetPeerCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.peers)
}

func (c *Core) SetPeerHandler(handler PeerHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerHandler = handler
}
