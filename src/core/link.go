package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Arceliar/phony"
	"github.com/ruvcoindev/ruvchain/src/address"
	
)

type linkType int

const (
	linkTypePersistent linkType = iota
	linkTypeEphemeral
	linkTypeIncoming
)

const defaultBackoffLimit = time.Second << 12
const minimumBackoffLimit = time.Second * 30

type links struct {
	phony.Inbox
	core  *Core
	tcp   *linkTCP
	tls   *linkTLS
	unix  *linkUNIX
	socks *linkSOCKS
	quic  *linkQUIC
	ws    *linkWS
	wss   *linkWSS
	_links     map[linkInfo]*link
	_listeners map[*Listener]context.CancelFunc
}

type linkProtocol interface {
	dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error)
	listen(ctx context.Context, url *url.URL, sintf string) (net.Listener, error)
}

type linkInfo struct {
	uri   string
	sintf string
}

type link struct {
	ctx       context.Context
	cancel    context.CancelFunc
	kick      chan struct{}
	linkType  linkType
	linkProto string
	_conn    *linkConn
	_err     error
	_errtime time.Time
}

type linkOptions struct {
	pinnedEd25519Keys map[keyArray]struct{}
	priority          uint8
	tlsSNI            string
	password          []byte
	maxBackoff        time.Duration
}

type Listener struct {
	listener net.Listener
	ctx      context.Context
	Cancel   context.CancelFunc
}

func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func (l *links) init(c *Core) error {
	l.core = c
	l.tcp = l.newLinkTCP()
	l.tls = l.newLinkTLS(l.tcp)
	l.unix = l.newLinkUNIX()
	l.socks = l.newLinkSOCKS()
	l.quic = l.newLinkQUIC()
	l.ws = l.newLinkWS()
	l.wss = l.newLinkWSS()
	l._links = make(map[linkInfo]*link)
	l._listeners = make(map[*Listener]context.CancelFunc)

	l.Act(nil, l._updateAverages)
	return nil
}

func (l *links) _updateAverages() {
	select {
	case <-l.core.ctx.Done():
		return
	default:
	}

	for _, l := range l._links {
		if l._conn == nil {
			continue
		}
		rx := atomic.LoadUint64(&l._conn.rx)
		tx := atomic.LoadUint64(&l._conn.tx)
		lastrx := atomic.LoadUint64(&l._conn.lastrx)
		lasttx := atomic.LoadUint64(&l._conn.lasttx)
		atomic.StoreUint64(&l._conn.rxrate, rx-lastrx)
		atomic.StoreUint64(&l._conn.txrate, tx-lasttx)
		atomic.StoreUint64(&l._conn.lastrx, rx)
		atomic.StoreUint64(&l._conn.lasttx, tx)
	}

	time.AfterFunc(time.Second, func() {
		l.Act(nil, l._updateAverages)
	})
}

func (l *links) shutdown() {
	phony.Block(l, func() {
		for _, cancel := range l._listeners {
			cancel()
		}
		for _, link := range l._links {
			if link._conn != nil {
				_ = link._conn.Close()
			}
		}
	})
}

type linkError string

func (e linkError) Error() string { return string(e) }

const ErrLinkAlreadyConfigured = linkError("peer is already configured")
const ErrLinkNotConfigured = linkError("peer is not configured")
const ErrLinkPriorityInvalid = linkError("priority value is invalid")
const ErrLinkPinnedKeyInvalid = linkError("pinned public key is invalid")
// ИЗМЕНЕНО: Обновлено сообщение об ошибке
const ErrLinkPasswordInvalid = linkError("invalid password: must be 12-64 characters") 
const ErrLinkUnrecognisedSchema = linkError("link schema unknown")
const ErrLinkMaxBackoffInvalid = linkError("max backoff duration invalid")
const ErrLinkSNINotSupported = linkError("SNI not supported on this link type")
const ErrLinkNoSuitableIPs = linkError("peer has no suitable addresses")

func (l *links) add(u *url.URL, sintf string, linkType linkType) error {
	var retErr error
	phony.Block(l, func() {
		lu := urlForLinkInfo(*u)
		info := linkInfo{
			uri:   lu.String(),
			sintf: sintf,
		}
		options := linkOptions{
			maxBackoff: defaultBackoffLimit,
		}
		for _, pubkey := range u.Query()["key"] {
			sigPub, err := hex.DecodeString(pubkey)
			if err != nil {
				retErr = ErrLinkPinnedKeyInvalid
				return
			}
			var sigPubKey keyArray
			copy(sigPubKey[:], sigPub)
			if options.pinnedEd25519Keys == nil {
				options.pinnedEd25519Keys = map[keyArray]struct{}{}
			}
			options.pinnedEd25519Keys[sigPubKey] = struct{}{}
		}
		if p := u.Query().Get("priority"); p != "" {
			pi, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				retErr = ErrLinkPriorityInvalid
				return
			}
			options.priority = uint8(pi)
		}
		if p := u.Query().Get("password"); p != "" {
			// ИЗМЕНЕНО: Добавлена проверка минимальной длины
			if len(p) < 12 || len(p) > 64 {
				retErr = ErrLinkPasswordInvalid
				return
			}
			options.password = []byte(p)
		}
		if p := u.Query().Get("maxbackoff"); p != "" {
			d, err := time.ParseDuration(p)
			if err != nil || d < minimumBackoffLimit {
				retErr = ErrLinkMaxBackoffInvalid
				return
			}
			options.maxBackoff = d
		}
		if sni := u.Query().Get("sni"); sni != "" {
			if net.ParseIP(sni) == nil {
				options.tlsSNI = sni
			}
		}
		if options.tlsSNI == "" {
			if host, _, err := net.SplitHostPort(u.Host); err == nil && net.ParseIP(host) == nil {
				options.tlsSNI = host
			}
		}

		state, ok := l._links[info]
		if ok && state != nil {
			select {
			case state.kick <- struct{}{}:
			default:
			}
			retErr = ErrLinkAlreadyConfigured
			return
		}

		state = &link{
			linkType:  linkType,
			linkProto: strings.ToUpper(u.Scheme),
			kick:      make(chan struct{}),
		}
		state.ctx, state.cancel = context.WithCancel(l.core.ctx)

		l._links[info] = state

		var backoff int

		backoffNow := func() bool {
			if backoff < 32 {
				backoff++
			}
			duration := time.Second << backoff
			if duration > options.maxBackoff {
				duration = options.maxBackoff
			}
			select {
			case <-state.kick:
				return true
			case <-state.ctx.Done():
				return false
			case <-l.core.ctx.Done():
				return false
			case <-time.After(duration):
				return true
			}
		}

		resetBackoff := func() {
			backoff = 0
		}

		go func() {
			defer phony.Block(l, func() {
				if l._links[info] == state {
					delete(l._links, info)
				}
			})
			for {
				select {
				case <-state.ctx.Done():
					return
				default:
				}

				conn, err := l.connect(state.ctx, u, info, options)
				if err != nil || conn == nil {
					if err == nil && conn == nil {
						l.core.log.Warnf("Link %q reached inconsistent error state", u.String())
					}
					if linkType == linkTypePersistent {
						phony.Block(l, func() {
							state._conn = nil
							state._err = err
							state._errtime = time.Now()
						})
						if backoffNow() {
							continue
						}
						return
					}
					break
				}

				lc := &linkConn{
					Conn: conn,
					up:   time.Now(),
				}

				var doRet bool
				phony.Block(l, func() {
					if state._conn != nil {
						doRet = true
					}
					state._conn = lc
				})
				if doRet {
					return
				}

				switch err = l.handler(linkType, options, lc, resetBackoff, false); {
				case err == nil:
				case errors.Is(err, io.EOF):
				case errors.Is(err, net.ErrClosed):
				default:
					l.core.log.Debugf("Link %s error: %s\n", u.Host, err)
				}

				_ = lc.Close()
				phony.Block(l, func() {
					state._conn = nil
					if err == nil {
						err = fmt.Errorf("remote side closed the connection")
					}
					state._err = err
					state._errtime = time.Now()
				})

				if linkType == linkTypePersistent {
					if backoffNow() {
						continue
					}
				}
				return
			}
		}()
	})
	return retErr
}

func (l *links) remove(u *url.URL, sintf string, _ linkType) error {
	var retErr error
	phony.Block(l, func() {
		lu := urlForLinkInfo(*u)
		info := linkInfo{
			uri:   lu.String(),
			sintf: sintf,
		}

		state, ok := l._links[info]
		if ok && state != nil {
			state.cancel()
			if conn := state._conn; conn != nil {
				retErr = conn.Close()
			}
			return
		}

		retErr = ErrLinkNotConfigured
	})
	return retErr
}

func (l *links) listen(u *url.URL, sintf string, local bool) (*Listener, error) {
	ctx, ctxcancel := context.WithCancel(l.core.ctx)
	var protocol linkProtocol
	switch strings.ToLower(u.Scheme) {
	case "tcp":
		protocol = l.tcp
	case "tls":
		protocol = l.tls
	case "unix":
		protocol = l.unix
	case "quic":
		protocol = l.quic
	case "ws":
		protocol = l.ws
	case "wss":
		protocol = l.wss
	default:
		ctxcancel()
		return nil, ErrLinkUnrecognisedSchema
	}
	listener, err := protocol.listen(ctx, u, sintf)
	if err != nil {
		ctxcancel()
		return nil, err
	}
	addr := listener.Addr()
	cancel := func() {
		ctxcancel()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			l.core.log.Warnf("Error closing %s listener %s: %s", strings.ToUpper(u.Scheme), addr, err)
		}
	}
	li := &Listener{
		listener: listener,
		ctx:      ctx,
		Cancel:   cancel,
	}

	var options linkOptions
	if p := u.Query().Get("priority"); p != "" {
		pi, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, ErrLinkPriorityInvalid
		}
		options.priority = uint8(pi)
	}
	if p := u.Query().Get("password"); p != "" {
		// ИЗМЕНЕНО: Добавлена проверка минимальной длины
		if len(p) < 12 || len(p) > 64 {
			return nil, ErrLinkPasswordInvalid
		}
		options.password = []byte(p)
	}

	phony.Block(l, func() {
		l._listeners[li] = cancel
	})

	go func() {
		l.core.log.Infof("%s listener started on %s", strings.ToUpper(u.Scheme), addr)
		defer phony.Block(l, func() {
			cancel()
			delete(l._listeners, li)
			l.core.log.Infof("%s listener stopped on %s", strings.ToUpper(u.Scheme), addr)
		})
		for {
			conn, err := li.listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()

				pu := *u
				pu.Host = conn.RemoteAddr().String()
				lu := urlForLinkInfo(pu)
				info := linkInfo{
					uri:   lu.String(),
					sintf: sintf,
				}

				var lc *linkConn
				var state *link
				phony.Block(l, func() {
					var ok bool
					state, ok = l._links[info]
					if !ok || state == nil {
						state = &link{
							linkType:  linkTypeIncoming,
							linkProto: strings.ToUpper(u.Scheme),
							kick:      make(chan struct{}),
						}
					}
					if state._conn != nil {
						return
					}

					lc = &linkConn{
						Conn: conn,
						up:   time.Now(),
					}

					state._conn = lc
					state._err = nil
					state._errtime = time.Time{}

					l._links[info] = state
				})
				defer phony.Block(l, func() {
					if l._links[info] == state {
						delete(l._links, info)
					}
				})
				if lc == nil {
					return
				}

				switch err = l.handler(linkTypeIncoming, options, lc, nil, local); {
				case err == nil:
				case errors.Is(err, io.EOF):
				case errors.Is(err, net.ErrClosed):
				default:
					l.core.log.Debugf("Link %s error: %s\n", u.Host, err)
				}

				_ = lc.Close()
			}(conn)
		}
	}()
	return li, nil
}

func (l *links) connect(ctx context.Context, u *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	var dialer linkProtocol
	switch strings.ToLower(u.Scheme) {
	case "tcp":
		dialer = l.tcp
	case "tls":
		dialer = l.tls
	case "socks", "sockstls":
		dialer = l.socks
	case "unix":
		dialer = l.unix
	case "quic":
		dialer = l.quic
	case "ws":
		dialer = l.ws
	case "wss":
		dialer = l.wss
	default:
		return nil, ErrLinkUnrecognisedSchema
	}
	return dialer.dial(ctx, u, info, options)
}

func (l *links) handler(linkType linkType, options linkOptions, conn net.Conn, success func(), local bool) error {
	meta := version_getBaseMetadata()
	meta.publicKey = l.core.public
	meta.priority = options.priority
	metaBytes, err := meta.encode(l.core.secret, options.password)
	if err != nil {
		return fmt.Errorf("failed to generate handshake: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(time.Second * 6)); err != nil {
		return fmt.Errorf("failed to set handshake deadline: %w", err)
	}
	n, err := conn.Write(metaBytes)
	switch {
	case err != nil:
		return fmt.Errorf("write handshake: %w", err)
	case n != len(metaBytes):
		return fmt.Errorf("incomplete handshake send")
	}
	meta = version_metadata{}
	base := version_getBaseMetadata()
	if err := meta.decode(conn, options.password); err != nil {
		_ = conn.Close()
		return err
	}
	if !meta.check() {
		return fmt.Errorf("remote node incompatible version (local %s, remote %s)",
			fmt.Sprintf("%d.%d", base.majorVer, base.minorVer),
			fmt.Sprintf("%d.%d", meta.majorVer, meta.minorVer),
		)
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear handshake deadline: %w", err)
	}
	if pinned := options.pinnedEd25519Keys; len(pinned) > 0 {
		var key keyArray
		copy(key[:], meta.publicKey)
		if _, allowed := pinned[key]; !allowed {
			return fmt.Errorf("node public key that does not match pinned keys")
		}
	}
	if !local {
		var allowed map[[32]byte]struct{}
		phony.Block(l.core, func() {
			allowed = l.core.config._allowedPublicKeys
		})
		isallowed := len(allowed) == 0
		for k := range allowed {
			if bytes.Equal(k[:], meta.publicKey) {
				isallowed = true
				break
			}
		}
		if linkType == linkTypeIncoming && !isallowed {
			return fmt.Errorf("node public key %q is not in AllowedPublicKeys", hex.EncodeToString(meta.publicKey))
		}
	}

	dir := "outbound"
	if linkType == linkTypeIncoming {
		dir = "inbound"
	}
	remoteAddr := net.IP(address.AddrForKey(meta.publicKey)[:]).String()
	remoteStr := fmt.Sprintf("%s@%s", remoteAddr, conn.RemoteAddr())
	localStr := conn.LocalAddr()
	priority := options.priority
	if meta.priority > priority {
		priority = meta.priority
	}
	l.core.log.Infof("Connected %s: %s, source %s",
		dir, remoteStr, localStr)
	if success != nil {
		success()
	}

	err = l.core.HandleConn(meta.publicKey, conn, priority)
	switch err {
	case io.EOF, net.ErrClosed, nil:
		l.core.log.Infof("Disconnected %s: %s, source %s",
			dir, remoteStr, localStr)
	default:
		l.core.log.Infof("Disconnected %s: %s, source %s; error: %s",
			dir, remoteStr, localStr, err)
	}
	return err
}

func (l *links) findSuitableIP(url *url.URL, fn func(hostname string, ip net.IP, port int) (net.Conn, error)) (net.Conn, error) {
	host, p, err := net.SplitHostPort(url.Host)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, err
	}
	resp, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	var _ips [64]net.IP
	ips := _ips[:0]
	for _, ip := range resp {
		switch {
		case ip.IsUnspecified():
			continue
		case ip.IsMulticast():
			continue
		case ip.IsLinkLocalMulticast():
			continue
		case ip.IsInterfaceLocalMulticast():
			continue
		case l.core.config.peerFilter != nil && !l.core.config.peerFilter(ip):
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, ErrLinkNoSuitableIPs
	}
	for _, ip := range ips {
		var conn net.Conn
		if conn, err = fn(host, ip, port); err != nil {
			url := *url
			url.RawQuery = ""
			l.core.log.Debugln("Dialling", url.Redacted(), "reported error:", err)
			continue
		}
		return conn, nil
	}
	return nil, err
}

func urlForLinkInfo(u url.URL) url.URL {
	u.RawQuery = ""
	return u
}

type linkConn struct {
	// tx and rx are at the beginning of the struct to ensure 64-bit alignment
	// on 32-bit platforms, see https://pkg.go.dev/sync/atomic#pkg-note-BUG
	rx     uint64
	tx     uint64
	rxrate uint64
	txrate uint64
	lastrx uint64
	lasttx uint64
	up     time.Time
	net.Conn
}

func (c *linkConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	atomic.AddUint64(&c.rx, uint64(n))
	return
}

func (c *linkConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	atomic.AddUint64(&c.tx, uint64(n))
	return
}
