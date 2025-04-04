//go:build (linux && cgo) || (darwin && cgo) || (ios && cgo) || windows
// +build linux,cgo darwin,cgo ios,cgo, windows
package multicast

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Arceliar/phony"
	"github.com/gologme/log"
	"github.com/ruvcoindev/ruvchain/src/admin"
	"github.com/ruvcoindev/ruvchain/src/core"
	"github.com/zeebo/blake3"
	"golang.org/x/exp/slices"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.org/x/sys/windows"
)

type GroupAddress string

type MulticastInterface struct {
	Regex    *regexp.Regexp
	Beacon   bool
	Listen   bool
	Port     uint16
	Priority uint8
	Password string
}

type multicastAdvertisement struct {
	MajorVersion uint16
	MinorVersion uint16
	PublicKey    ed25519.PublicKey
	Port         uint16
	Hash         []byte
}

type Multicast struct {
	phony.Inbox
	core        *core.Core
	log         *log.Logger
	sock        *ipv6.PacketConn
	running     atomic.Bool
	listeners   map[string]*listenerInfo
	interfaces  map[string]*interfaceInfo
	timer       *time.Timer
	groupAddr   GroupAddress
	ifaceConfig map[MulticastInterface]struct{}
}

type interfaceInfo struct {
	iface     net.Interface
	addrs     []net.Addr
	beacon    bool
	listen    bool
	port      uint16
	priority  uint8
	password  [32]byte
	hash      []byte
	lastSeen  time.Time
}

type listenerInfo struct {
	listener *core.Listener
	time     time.Time
	interval time.Duration
	port     uint16
}

const (
	defaultPort        = 5001
	protocolVersion    = 0x02
	announceInterval   = 5 * time.Minute
	maxAdvertisementSize = 128
)

var (
	ErrInvalidAdvertisement = errors.New("invalid multicast advertisement")
	ErrInterfaceNotFound    = errors.New("network interface not found")
	ErrUnsupportedPlatform  = errors.New("unsupported platform")
)

func New(c *core.Core, logger *log.Logger, opts ...Option) (*Multicast, error) {
	m := &Multicast{
		core:       c,
		log:        logger,
		listeners:  make(map[string]*listenerInfo),
		interfaces: make(map[string]*interfaceInfo),
		groupAddr:  "[ff02::114]:5001",
		ifaceConfig: make(map[MulticastInterface]struct{}),
	}

	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, fmt.Errorf("option error: %w", err)
		}
	}

	if err := m.start(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Multicast) start() error {
	if !m.running.CompareAndSwap(false, true) {
		return errors.New("already running")
	}

	lc := net.ListenConfig{Control: m.multicastReuse}
	conn, err := lc.ListenPacket(context.Background(), "udp6", string(m.groupAddr))
	if err != nil {
		return fmt.Errorf("listen error: %w", err)
	}

	m.sock = ipv6.NewPacketConn(conn)
	if err := m.sock.SetControlMessage(ipv6.FlagDst, true); err != nil {
		m.log.Warnf("Failed to set control message: %v", err)
	}

	go m.receiveLoop()
	m.scheduleAnnouncement()
	return nil
}

func (m *Multicast) Stop() error {
	if !m.running.CompareAndSwap(true, false) {
		return nil
	}

	if m.sock != nil {
		m.sock.Close()
	}
	if m.timer != nil {
		m.timer.Stop()
	}
	return nil
}

func (m *Multicast) IsStarted() bool {
	return m.running.Load()
}

func (m *Multicast) multicastReuse(network, address string, c syscall.RawConn) error {
	var operr error
	if err := c.Control(func(fd uintptr) {
		switch runtime.GOOS {
		case "windows":
			// Windows-specific socket options
			operr = windows.SetsockoptInt(
				windows.Handle(fd),
				windows.SOL_SOCKET,
				windows.SO_REUSEADDR,
				1,
			)
		default:
			// UNIX-like systems
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if operr == nil && runtime.GOOS != "linux" {
				operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
		}
	}); err != nil {
		return err
	}
	return operr
}

func (m *Multicast) receiveLoop() {
	buf := make([]byte, 1500)
	for m.running.Load() {
		n, cm, src, err := m.sock.ReadFrom(buf)
		if err != nil {
			if m.running.Load() {
				m.log.Errorf("ReadFrom error: %v", err)
			}
			continue
		}

		if cm.Dst.IsMulticast() {
			if err := m.handlePacket(buf[:n], src); err != nil {
				m.log.Warnf("Error handling packet: %v", err)
			}
		}
	}
}

func (m *Multicast) handlePacket(data []byte, src net.Addr) error {
	var adv multicastAdvertisement
	if err := adv.UnmarshalBinary(data); err != nil {
		return ErrInvalidAdvertisement
	}

	if !m.validateAdvertisement(&adv) {
		return ErrInvalidAdvertisement
	}

	m.core.Peers().AddPeer(
		hex.EncodeToString(adv.PublicKey),
		fmt.Sprintf("udp://%s:%d", src.(*net.UDPAddr).IP, adv.Port),
	)
	return nil
}

func (m *Multicast) validateAdvertisement(adv *multicastAdvertisement) bool {
	// Validate protocol version
	if adv.MajorVersion != protocolVersion {
		return false
	}

	// Validate hash
	digest := blake3.Sum256(adv.PublicKey)
	return bytes.Equal(adv.Hash, digest[:])
}

func (m *Multicast) scheduleAnnouncement() {
	m.timer = time.AfterFunc(announceInterval, func() {
		m.Act(nil, m.sendAnnouncement)
		m.scheduleAnnouncement()
	})
}

func (m *Multicast) sendAnnouncement() {
	if !m.running.Load() {
		return
	}

	addr, err := net.ResolveUDPAddr("udp6", string(m.groupAddr))
	if err != nil {
		m.log.Errorf("Failed to resolve group address: %v", err)
		return
	}

	adv := multicastAdvertisement{
		MajorVersion: protocolVersion,
		PublicKey:    m.core.PublicKey(),
		Port:         m.core.Port(),
	}
	adv.Hash = blake3.Sum256(adv.PublicKey)[:]

	data, err := adv.MarshalBinary()
	if err != nil {
		m.log.Errorf("Failed to marshal advertisement: %v", err)
		return
	}

	for _, intf := range m.interfaces {
		if intf.beacon {
			if err := m.sock.SetMulticastInterface(&intf.iface); err != nil {
				m.log.Warnf("SetMulticastInterface error: %v", err)
				continue
			}
			m.sock.WriteTo(data, nil, addr)
		}
	}
}

// Admin API Handlers
type MulticastInterfaceState struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Beacon   bool   `json:"beacon"`
	Listen   bool   `json:"listen"`
	Password bool   `json:"password"`
}

func (m *Multicast) SetupAdminHandlers(a *admin.AdminSocket) {
	a.AddHandler("getMulticastInterfaces", "List multicast interfaces", []string{},
		func(req json.RawMessage) (interface{}, error) {
			var states []MulticastInterfaceState
			phony.Block(m, func() {
				for name, intf := range m.interfaces {
					state := MulticastInterfaceState{
						Name:     name,
						Beacon:   intf.beacon,
						Listen:   intf.listen,
						Password: len(intf.password) > 0,
					}
					if li := m.listeners[name]; li != nil {
						state.Address = li.listener.Addr().String()
					}
					states = append(states, state)
				}
			})
			slices.SortFunc(states, func(a, b MulticastInterfaceState) int {
				return strings.Compare(a.Name, b.Name)
			})
			return states, nil
		})
}

// Option pattern configuration
type Option func(*Multicast) error

func WithGroupAddress(addr GroupAddress) Option {
	return func(m *Multicast) error {
		m.groupAddr = addr
		return nil
	}
}

func WithInterface(cfg MulticastInterface) Option {
	return func(m *Multicast) error {
		m.ifaceConfig[cfg] = struct{}{}
		return m.updateInterfaces()
	}
}

func (m *Multicast) updateInterfaces() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		for cfg := range m.ifaceConfig {
			if cfg.Regex.MatchString(iface.Name) {
				addrs, _ := iface.Addrs()
				m.interfaces[iface.Name] = &interfaceInfo{
					iface:    iface,
					addrs:    addrs,
					beacon:   cfg.Beacon,
					listen:   cfg.Listen,
					port:     cfg.Port,
					priority: cfg.Priority,
					password: normalizeKey([]byte(cfg.Password)),
				}
			}
		}
	}
	return nil
}

func normalizeKey(password []byte) [32]byte {
	if len(password) == 32 {
		var key [32]byte
		copy(key[:], password)
		return key
	}
	return blake3.Sum256(password)
}

func (a *multicastAdvertisement) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, a.MajorVersion); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, a.MinorVersion); err != nil {
		return nil, err
	}
	if _, err := buf.Write(a.PublicKey); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, a.Port); err != nil {
		return nil, err
	}
	if _, err := buf.Write(a.Hash); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (a *multicastAdvertisement) UnmarshalBinary(data []byte) error {
	if len(data) < 4+ed25519.PublicKeySize+2+blake3.Size {
		return ErrInvalidAdvertisement
	}
	a.MajorVersion = binary.BigEndian.Uint16(data[0:2])
	a.MinorVersion = binary.BigEndian.Uint16(data[2:4])
	a.PublicKey = make([]byte, ed25519.PublicKeySize)
	copy(a.PublicKey, data[4:4+ed25519.PublicKeySize])
	a.Port = binary.BigEndian.Uint16(data[4+ed25519.PublicKeySize : 6+ed25519.PublicKeySize])
	a.Hash = make([]byte, blake3.Size)
	copy(a.Hash, data[6+ed25519.PublicKeySize:6+ed25519.PublicKeySize+blake3.Size])
	return nil
}
