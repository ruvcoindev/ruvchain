package multicast

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"sync/atomic"
	"time"
	
	

	"github.com/Arceliar/phony"
	"github.com/gologme/log"
	"github.com/wlynxg/anet"
	"golang.org/x/net/ipv6"
	

	"github.com/ruvcoindev/ruvchain/src/core"
	"github.com/zeebo/blake3"
)






type Multicast struct {
	phony.Inbox
	core        *core.Core
	log         *log.Logger
	running     atomic.Bool
	sock        *ipv6.PacketConn
	_listeners  map[string]*listenerInfo
	_interfaces map[string]*interfaceInfo
	_timer      *time.Timer
	config      struct {
		_groupAddr  GroupAddress
		_interfaces map[MulticastInterface]struct{}
	}
}

type interfaceInfo struct {
	iface    net.Interface
	addrs    []net.Addr
	beacon   bool
	listen   bool
	port     uint16
	priority uint8
	password []byte
	hash     []byte
}

type listenerInfo struct {
	listener *core.Listener
	time     time.Time
	interval time.Duration
	port     uint16
}

func New(core *core.Core, log *log.Logger, opts ...SetupOption) (*Multicast, error) {
	m := &Multicast{
		core:        core,
		log:         log,
		_listeners:  make(map[string]*listenerInfo),
		_interfaces: make(map[string]*interfaceInfo),
	}
	m.config._interfaces = map[MulticastInterface]struct{}{}
	m.config._groupAddr = GroupAddress("[ff02::114]:5001")
	for _, opt := range opts {
		m._applyOption(opt)
	}
	var err error
	phony.Block(m, func() {
		err = m._start()
	})
	return m, err
}

func (m *Multicast) _start() error {
	if !m.running.CompareAndSwap(false, true) {
		return fmt.Errorf("multicast module is already started")
	}
	var anyEnabled bool
	for intf := range m.config._interfaces {
		anyEnabled = anyEnabled || intf.Beacon || intf.Listen
	}
	if !anyEnabled {
		m.running.Store(false)
		return nil
	}
	m.log.Debugln("Starting multicast module")
	defer m.log.Debugln("Started multicast module")
	addr, err := net.ResolveUDPAddr("udp", string(m.config._groupAddr))
	if err != nil {
		m.running.Store(false)
		return err
	}
	listenString := fmt.Sprintf("[::]:%v", addr.Port)
	lc := net.ListenConfig{
		Control: m.multicastReuse,
	}
	conn, err := lc.ListenPacket(context.Background(), "udp6", listenString)
	if err != nil {
		m.running.Store(false)
		return err
	}
	m.sock = ipv6.NewPacketConn(conn)
	if err = m.sock.SetControlMessage(ipv6.FlagDst, true); err != nil { // nolint:staticcheck
	}

	go m.listen()
	m.Act(nil, m._multicastStarted)
	m.Act(nil, m._announce)

	return nil
}

func (m *Multicast) IsStarted() bool {
	return m.running.Load()
}

func (m *Multicast) Stop() error {
	var err error
	phony.Block(m, func() {
		err = m._stop()
	})
	m.log.Debugln("Stopped multicast module")
	return err
}

func (m *Multicast) _stop() error {
	if !m.running.CompareAndSwap(true, false) {
		return nil
	}
	m.log.Infoln("Stopping multicast module")
	if m.sock != nil {
		m.sock.Close()
	}
	return nil
}

func (m *Multicast) _updateInterfaces() {
	interfaces := m._getAllowedInterfaces()
	for name, info := range interfaces {
		addrs, err := anet.InterfaceAddrsByInterface(&info.iface)
		if err != nil {
			m.log.Warnf("Failed up get addresses for interface %s: %s", name, err)
			delete(interfaces, name)
			continue
		}
		for _, addr := range addrs {
			addrIP, _, err := net.ParseCIDR(addr.String())
			if err != nil || addrIP.To4() != nil || !addrIP.IsLinkLocalUnicast() {
				continue
			}
			info.addrs = append(info.addrs, addr)
		}
		interfaces[name] = info
		m.log.Debugf("Discovered addresses for interface %s: %s", name, addrs)
	}
	m._interfaces = interfaces
}

func (m *Multicast) Interfaces() map[string]net.Interface {
	interfaces := make(map[string]net.Interface)
	phony.Block(m, func() {
		for _, info := range m._interfaces {
			interfaces[info.iface.Name] = info.iface
		}
	})
	return interfaces
}

func (m *Multicast) _getAllowedInterfaces() map[string]*interfaceInfo {
	interfaces := make(map[string]*interfaceInfo)
	allifaces, err := anet.Interfaces()
	if err != nil {
		m.log.Debugf("Failed to get interfaces: %s", err)
		return nil
	}

	pk := m.core.PublicKey()
	for _, iface := range allifaces {
		switch {
		case iface.Flags&net.FlagUp == 0,
			iface.Flags&net.FlagRunning == 0,
			iface.Flags&net.FlagMulticast == 0,
			iface.Flags&net.FlagPointToPoint != 0:
			continue
		}
		for ifcfg := range m.config._interfaces {
			if !ifcfg.Beacon && !ifcfg.Listen {
				continue
			}
			if !ifcfg.Regex.MatchString(iface.Name) {
				continue
			}

			hasher := blake3.New()
			hasher.Write([]byte(ifcfg.Password))
			if _, err := hasher.Write(pk); err != nil {
				continue
			}
			if len(pk) != ed25519.PublicKeySize {
				continue
			}
			
			interfaces[iface.Name] = &interfaceInfo{
				iface:    iface,
				beacon:   ifcfg.Beacon,
				listen:   ifcfg.Listen,
				port:     ifcfg.Port,
				priority: ifcfg.Priority,
				password: []byte(ifcfg.Password),
				hash:     hasher.Sum(nil),
			}
			break
		}
	}
	return interfaces
}

func (m *Multicast) AnnounceNow() {
	phony.Block(m, func() {
		if m._timer != nil && !m._timer.Stop() {
			<-m._timer.C
		}
		m.Act(nil, m._announce)
	})
}

func (m *Multicast) _announce() {
	if !m.running.Load() {
		return
	}
	m._updateInterfaces()
	groupAddr, err := net.ResolveUDPAddr("udp6", string(m.config._groupAddr))
	if err != nil {
		panic(err)
	}
	destAddr, err := net.ResolveUDPAddr("udp6", string(m.config._groupAddr))
	if err != nil {
		panic(err)
	}

	for name, info := range m._listeners {
		stop := func() {
			info.listener.Cancel()
			delete(m._listeners, name)
			m.log.Debugln("No longer multicasting on", name)
		}
		if _, ok := m._interfaces[name]; !ok {
			stop()
			continue
		}
		listenaddr, err := net.ResolveTCPAddr("tcp6", info.listener.Addr().String())
		if err != nil {
			stop()
			continue
		}
		if info, ok := m._interfaces[name]; ok {
			found := false
			for _, addr := range info.addrs {
				if ip, _, err := net.ParseCIDR(addr.String()); err == nil {
					if ip.Equal(listenaddr.IP) {
						found = true
						break
					}
				}
			}
			if !found {
				stop()
			}
		}
	}

	for _, info := range m._interfaces {
		iface := info.iface
		for _, addr := range info.addrs {
			addrIP, _, err := net.ParseCIDR(addr.String())
			if err != nil || addrIP.To4() != nil || !addrIP.IsLinkLocalUnicast() {
				continue
			}
			if info.listen {
				_ = m.sock.JoinGroup(&iface, groupAddr)
			}
			if !info.beacon {
				break
			}
			var linfo *listenerInfo
			if _, ok := m._listeners[iface.Name]; !ok {
				v := &url.Values{}
				v.Add("priority", fmt.Sprintf("%d", info.priority))
				v.Add("password", string(info.password))
				u := &url.URL{
					Scheme:   "tls",
					Host:     net.JoinHostPort(addrIP.String(), fmt.Sprintf("%d", info.port)),
					RawQuery: v.Encode(),
				}
				if li, err := m.core.ListenLocal(u, iface.Name); err == nil {
					m.log.Debugln("Started multicasting on", iface.Name)
					linfo = &listenerInfo{listener: li, time: time.Now(), port: info.port}
					m._listeners[iface.Name] = linfo
				} else {
					m.log.Warnln("Not multicasting on", iface.Name, "due to error:", err)
				}
			} else {
				linfo = m._listeners[iface.Name]
			}
			if linfo == nil {
				continue
			}
			if time.Since(linfo.time) < linfo.interval {
				continue
			}
			addr := linfo.listener.Addr().(*net.TCPAddr)
			adv := multicastAdvertisement{
				MajorVersion: core.ProtocolVersionMajor,
				MinorVersion: core.ProtocolVersionMinor,
				PublicKey:    m.core.PublicKey(),
				Port:         uint16(addr.Port),
				Hash:         info.hash,
			}
			msg, err := adv.MarshalBinary()
			if err != nil {
				continue
			}
			destAddr.Zone = iface.Name
			if _, err = m.sock.WriteTo(msg, nil, destAddr); err != nil {
				m.log.Warn("Failed to send multicast beacon:", err)
			}
			if linfo.interval.Seconds() < 15 {
				linfo.interval += time.Second
			}
			linfo.time = time.Now()
			break
		}
	}
	annInterval := time.Second + time.Microsecond*(time.Duration(rand.Intn(1048576)))
	m._timer = time.AfterFunc(annInterval, func() {
		m.Act(nil, m._announce)
	})
}

func (m *Multicast) listen() {
	groupAddr, err := net.ResolveUDPAddr("udp6", string(m.config._groupAddr))
	if err != nil {
		panic(err)
	}
	bs := make([]byte, 2048)

	for {
		if !m.running.Load() {
			return
		}
		n, rcm, fromAddr, err := m.sock.ReadFrom(bs)
		if err != nil {
			if !m.IsStarted() {
				return
			}
			panic(err)
		}
		if rcm != nil {
			if !rcm.Dst.IsLinkLocalMulticast() || !rcm.Dst.Equal(groupAddr.IP) {
				continue
			}
		}
		var adv multicastAdvertisement
		if err := adv.UnmarshalBinary(bs[:n]); err != nil {
			continue
		}
		switch {
		case adv.MajorVersion != core.ProtocolVersionMajor,
			adv.MinorVersion != core.ProtocolVersionMinor,
			adv.PublicKey.Equal(m.core.PublicKey()):
			continue
		}
		from := fromAddr.(*net.UDPAddr)
		from.Port = int(adv.Port)
		var interfaces map[string]*interfaceInfo
		phony.Block(m, func() {
			interfaces = m._interfaces
		})
		if info, ok := interfaces[from.Zone]; ok && info.listen {
			hasher := blake3.New()
			hasher.Write(info.password)
			if _, err := hasher.Write(adv.PublicKey); err != nil {
				continue
			}
			if !bytes.Equal(hasher.Sum(nil), adv.Hash) {
				continue
			}
			v := &url.Values{}
			v.Add("key", hex.EncodeToString(adv.PublicKey))
			v.Add("priority", fmt.Sprintf("%d", info.priority))
			v.Add("password", string(info.password))
			u := &url.URL{
				Scheme:   "tls",
				Host:     from.String(),
				RawQuery: v.Encode(),
			}
			if err := m.core.CallPeer(u, from.Zone); err != nil {
				m.log.Debugln("Call from multicast failed:", err)
			}
		}
	}
}



