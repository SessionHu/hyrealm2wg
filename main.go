// hyrealm2wg, phase 1: reuse Hysteria's extras/v2/realm package to
//  1. discover our external UDP address(es) via STUN on the socket bound to
//     the future WireGuard listen port,
//  2. exchange addresses through the rendezvous server,
//  3. hole-punch,
//
// and print the resulting tuples as one JSON line on stdout. No WireGuard yet.
//
//	wait    side: registers the realm, answers connect requests
//	connect side: asks the rendezvous to connect to that realm
//
// With -verify, right after a successful punch the punch socket is closed, the same
// local port is re-bound by a plain socket (a stand-in for WireGuard), and ping/pong
// packets are exchanged with the peer to prove the NAT mapping survives the hand-off.
//
// Logs go to stderr, results go to stdout (one JSON object per line).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/apernet/hysteria/extras/v2/realm"
)

type config struct {
	network string // "udp4" | "udp6" | "udp"
	stun    realm.STUNConfig
	punch   realm.PunchConfig
	wg      *wgHandoff // nil unless -wg-if is given
}

type result struct {
	Mode       string        `json:"mode"`
	LocalPort  int           `json:"local_port"`
	LocalAddrs []string      `json:"local_addrs"`
	PeerAddr   string        `json:"peer_addr"`
	WG         *handoffStats `json:"wg,omitempty"`

	punchedAt time.Time // when Punch/Respond returned; used by -verify
}

type verifyOpts struct {
	on  bool
	dur time.Duration
}

func main() {
	var (
		realmURI  = flag.String("realm", "", "realm://TOKEN@host[:port]/name[?lport=N]")
		mode      = flag.String("mode", "", "wait | connect")
		stunList  = flag.String("stun", "stun.l.google.com:19302,stun.cloudflare.com:3478", "comma-separated STUN servers")
		family    = flag.String("family", "4", "4 | 6 | any")
		once      = flag.Bool("once", false, "wait mode: exit after the first successful punch")
		punchTO   = flag.Duration("punch-timeout", 10*time.Second, "punch timeout")
		punchIv   = flag.Duration("punch-interval", 100*time.Millisecond, "punch hello interval")
		verifyF   = flag.Bool("verify", false, "after punching: close socket, re-bind same port, ping/pong with peer (implies -once)")
		verifyD   = flag.Duration("verify-duration", 10*time.Second, "how long to exchange ping/pong")
		wgIf      = flag.String("wg-if", "", "existing WireGuard interface to hand the punched port to")
		wgPeer    = flag.String("wg-peer", "", "base64 public key of the peer on -wg-if (must already be configured there)")
		keepalive = flag.Duration("keepalive", 25*time.Second, "PersistentKeepalive set on the peer at hand-off")
		wgWait    = flag.Duration("wg-wait", 15*time.Second, "how long to watch for the handshake after hand-off")
		release   = flag.Bool("release-port", false, "if -wg-if currently listens on the lport, move it to a random port first")
	)
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if *realmURI == "" || (*mode != "wait" && *mode != "connect") {
		flag.Usage()
		os.Exit(2)
	}

	cfg := config{}
	var fam realm.AddrFamily
	switch *family {
	case "4":
		cfg.network, fam = "udp4", realm.AddrFamilyIPv4
	case "6":
		cfg.network, fam = "udp6", realm.AddrFamilyIPv6
	case "any":
		cfg.network, fam = "udp", realm.AddrFamilyAny
	default:
		log.Fatalf("bad -family %q", *family)
	}
	cfg.stun = realm.STUNConfig{
		Servers:  strings.Split(*stunList, ","),
		Timeout:  3 * time.Second,
		Resolver: net.DefaultResolver,
		Family:   fam,
	}
	cfg.punch = realm.PunchConfig{Timeout: *punchTO, Interval: *punchIv, Family: fam}

	ra, err := realm.ParseAddr(*realmURI)
	if err != nil {
		log.Fatalf("parse realm addr: %v", err)
	}
	cl, err := realm.NewClientFromAddr(ra, &http.Client{})
	if err != nil {
		log.Fatalf("realm client: %v", err)
	}

	if *wgIf != "" {
		if *verifyF {
			log.Fatal("-verify and -wg-if are mutually exclusive")
		}
		h, err := newWGHandoff(*wgIf, *wgPeer, ra.LocalPort, *keepalive, *wgWait, *release)
		if err != nil {
			log.Fatalf("wireguard: %v", err)
		}
		defer h.Close()
		cfg.wg = h
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *mode {
	case "connect":
		res, err := runConnect(ctx, cl, ra, cfg)
		if res == nil {
			log.Fatalf("connect: %v", err)
		}
		if *verifyF {
			rep, verr := verify(ctx, "connect", cfg.network, res.LocalPort, res.PeerAddr, res.punchedAt, *verifyD)
			emit(res)
			emitVerify(rep, verr)
		} else {
			emit(res)
		}
		if err != nil { // punched, but the WireGuard hand-off failed
			log.Fatalf("connect: %v", err)
		}
	case "wait":
		if err := runWait(ctx, cl, ra, cfg, *once, verifyOpts{on: *verifyF, dur: *verifyD}); err != nil && ctx.Err() == nil {
			log.Fatalf("wait: %v", err)
		}
	}
}

// ---------------------------------------------------------------- connect side

func runConnect(ctx context.Context, cl *realm.Client, ra *realm.Addr, c config) (*result, error) {
	// The socket must be bound to the port WireGuard will use later.
	conn, port, err := listen(c.network, ra.LocalPort)
	if err != nil {
		return nil, err
	}
	defer conn.Close() // closed as soon as we return: this is the hand-off point

	local, err := realm.Discover(ctx, conn, c.stun)
	if err != nil {
		return nil, fmt.Errorf("stun: %w", err)
	}
	log.Printf("local port %d, external addrs %v", port, local)

	meta, err := realm.NewPunchMetadata()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Connect(ctx, ra.RealmID, realm.ConnectRequest{
		Addresses:     strs(local),
		PunchMetadata: meta,
	})
	if err != nil {
		return nil, fmt.Errorf("rendezvous connect: %w", err)
	}
	peer, err := parseAddrs(resp.Addresses)
	if err != nil {
		return nil, err
	}
	log.Printf("peer addrs %v, punching", peer)

	// Punch owns reads on conn until it returns.
	pr, err := realm.Punch(ctx, conn, local, peer, meta, c.punch)
	punchedAt := time.Now()
	if err != nil {
		return nil, fmt.Errorf("punch: %w", err)
	}
	res := &result{Mode: "connect", LocalPort: port, LocalAddrs: strs(local), PeerAddr: pr.PeerAddr.String(), punchedAt: punchedAt}
	if c.wg != nil {
		conn.Close() // free the port first, then give it to WireGuard
		st, err := c.wg.apply(ctx, port, res.PeerAddr, punchedAt)
		res.WG = st
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// ------------------------------------------------------------------- wait side

type waiter struct {
	cl      *realm.Client
	ra      *realm.Addr
	cfg     config
	pc      *realm.PunchPacketConn
	puncher *realm.ServerPuncher
	raw     net.PacketConn
	port    int
	vo      verifyOpts
	stunMu  sync.Mutex // DiscoverWithDemux consumes pc.STUNEvents(); keep it single-flight
}

func runWait(ctx context.Context, cl *realm.Client, ra *realm.Addr, c config, once bool, vo verifyOpts) error {
	raw, port, err := listen(c.network, ra.LocalPort)
	if err != nil {
		return err
	}
	defer raw.Close()

	pc, err := realm.NewPunchPacketConn(raw, 64)
	if err != nil {
		return err
	}
	// ASSUMPTION (verify in punch_conn.go): PunchPacketConn demultiplexes punch/STUN
	// packets inside ReadFrom, so something must keep calling it. In Hysteria, QUIC
	// does that; here we just drain and drop everything else.
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	puncher, err := realm.NewServerPuncher(ctx, pc)
	if err != nil {
		return err
	}
	w := &waiter{cl: cl, ra: ra, cfg: c, pc: pc, puncher: puncher, raw: raw, port: port, vo: vo}

	for ctx.Err() == nil {
		done, err := w.session(ctx, once)
		if done {
			return err
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("session ended: %v; re-registering in 2s", err)
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
	return ctx.Err()
}

func (w *waiter) discover(ctx context.Context) ([]netip.AddrPort, error) {
	w.stunMu.Lock()
	defer w.stunMu.Unlock()
	return realm.DiscoverWithDemux(ctx, w.pc, w.cfg.stun)
}

// session registers the realm, keeps it alive and serves punch events until the
// session breaks (returns done=false) or, with once, the first punch succeeds.
func (w *waiter) session(parent context.Context, once bool) (bool, error) {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)

	local, err := w.discover(ctx)
	if err != nil {
		return false, fmt.Errorf("stun: %w", err)
	}
	log.Printf("local port %d, external addrs %v", w.port, local)

	reg, err := w.cl.Register(ctx, w.ra.RealmID, strs(local))
	if err != nil {
		return false, fmt.Errorf("register: %w", err)
	}
	sid := reg.SessionID
	log.Printf("registered realm %q, ttl=%d", w.ra.RealmID, reg.TTL)
	defer func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer dcancel()
		_ = w.cl.Deregister(dctx, w.ra.RealmID, sid)
	}()

	go w.heartbeat(ctx, cancel, sid, reg.TTL)

	es, err := w.cl.Events(ctx, w.ra.RealmID, sid)
	if err != nil {
		return false, fmt.Errorf("events: %w", err)
	}
	defer es.Close()
	go func() { <-ctx.Done(); es.Close() }()

	for {
		ev, err := es.Next()
		if err != nil {
			if cause := context.Cause(ctx); cause != nil {
				err = cause
			}
			return false, err
		}
		res, err := w.respond(ctx, sid, local, ev)
		if err != nil {
			log.Printf("punch attempt failed: %v", err)
			continue
		}
		if w.cfg.wg != nil {
			w.raw.Close() // free the port first, then give it to WireGuard
			st, werr := w.cfg.wg.apply(ctx, w.port, res.PeerAddr, res.punchedAt)
			res.WG = st
			emit(res)
			return true, werr
		}
		if w.vo.on {
			// Hand-off: free the port right away, then re-bind it like WireGuard would.
			w.raw.Close()
			rep, verr := verify(ctx, "wait", w.cfg.network, w.port, res.PeerAddr, res.punchedAt, w.vo.dur)
			emit(res)
			emitVerify(rep, verr)
			return true, nil
		}
		emit(res)
		if once {
			return true, nil
		}
	}
}

func (w *waiter) heartbeat(ctx context.Context, cancel context.CancelCauseFunc, sid string, ttl int) {
	next := func(ttl int) time.Duration {
		d := time.Duration(ttl) * time.Second / 2 // ASSUMPTION: ttl is in seconds
		if d < time.Second {
			d = time.Second
		}
		return d
	}
	t := time.NewTimer(next(ttl))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		req := realm.HeartbeatRequest{}
		if addrs, err := w.discover(ctx); err == nil {
			req.Addresses = strs(addrs)
		} else {
			log.Printf("heartbeat stun: %v", err)
		}
		resp, err := w.cl.Heartbeat(ctx, w.ra.RealmID, sid, req)
		if err != nil {
			cancel(fmt.Errorf("heartbeat: %w", err))
			return
		}
		if resp.TTL > 0 {
			ttl = resp.TTL
		}
		t.Reset(next(ttl))
	}
}

func (w *waiter) respond(ctx context.Context, sid string, lastLocal []netip.AddrPort, ev *realm.PunchEvent) (*result, error) {
	peer, err := parseAddrs(ev.Addresses)
	if err != nil {
		return nil, err
	}
	// Fresh STUN right before punching; fall back to the last known addresses.
	fresh, err := w.discover(ctx)
	if err != nil {
		log.Printf("connect-time stun failed (%v); using last-known addresses", err)
		fresh = lastLocal
	}
	// Same order as Hysteria's own server: post our addresses, then Respond.
	if err := w.cl.ConnectResponse(ctx, w.ra.RealmID, sid, ev.Nonce, strs(fresh)); err != nil {
		return nil, fmt.Errorf("connect-response: %w", err)
	}
	log.Printf("peer addrs %v, responding", peer)
	pr, err := w.puncher.Respond(ctx, ev.Nonce, fresh, peer, ev.PunchMetadata, w.cfg.punch)
	punchedAt := time.Now()
	if err != nil {
		return nil, fmt.Errorf("respond: %w", err)
	}
	return &result{Mode: "wait", LocalPort: w.port, LocalAddrs: strs(fresh), PeerAddr: pr.PeerAddr.String(), punchedAt: punchedAt}, nil
}

// --------------------------------------------------------------------- helpers

func listen(network string, port int) (net.PacketConn, int, error) {
	conn, err := net.ListenPacket(network, fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, 0, fmt.Errorf("listen %s :%d: %w", network, port, err)
	}
	return conn, conn.LocalAddr().(*net.UDPAddr).Port, nil
}

func strs(as []netip.AddrPort) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

func parseAddrs(ss []string) ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(ss))
	for _, s := range ss {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return nil, fmt.Errorf("bad address %q: %w", s, err)
		}
		out = append(out, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	}
	return out, nil
}

func emit(r *result) {
	_ = json.NewEncoder(os.Stdout).Encode(r)
}

// ---------------------------------------------------------------------- verify

type verifyReport struct {
	Mode          string  `json:"mode"`
	PunchToBindMs float64 `json:"punch_to_bind_ms"`       // Punch returned -> new socket bound
	BindAttempts  int     `json:"bind_attempts"`          // >1 means the port was briefly still busy
	FirstRxMs     float64 `json:"first_rx_after_bind_ms"` // -1: nothing received
	FirstRxKind   string  `json:"first_rx_kind"`
	Tx            int32   `json:"tx"`
	RxPing        int32   `json:"rx_ping"`
	RxPong        int32   `json:"rx_pong"` // >0 means: our packet reached the peer AND its reply came back
	OK            bool    `json:"ok"`
}

const (
	pingMsg = "hyrealm2wg-ping"
	pongMsg = "hyrealm2wg-pong"
)

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// verify re-binds the punch port with an ordinary socket (stand-in for WireGuard) and
// exchanges ping/pong with the peer for dur. The caller must have closed the punch
// socket already.
func verify(ctx context.Context, mode, network string, port int, peerStr string, punchedAt time.Time, dur time.Duration) (*verifyReport, error) {
	peer, err := netip.ParseAddrPort(peerStr)
	if err != nil {
		return nil, err
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())

	var conn net.PacketConn
	attempts := 0
	for {
		attempts++
		conn, err = net.ListenPacket(network, fmt.Sprintf(":%d", port))
		if err == nil {
			break
		}
		if ctx.Err() != nil || time.Since(punchedAt) > 2*time.Second {
			return nil, fmt.Errorf("re-bind :%d: %w", port, err)
		}
		time.Sleep(time.Millisecond)
	}
	defer conn.Close()
	bound := time.Now()
	rep := &verifyReport{Mode: mode, PunchToBindMs: ms(bound.Sub(punchedAt)), BindAttempts: attempts, FirstRxMs: -1}
	log.Printf("verify: re-bound :%d %.3f ms after punch (attempts=%d); exchanging ping/pong for %s", port, rep.PunchToBindMs, attempts, dur)

	var tx, rxPing, rxPong atomic.Int32
	end := bound.Add(dur)
	dst := net.UDPAddrFromAddrPort(peer)

	go func() { // sender
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			if _, err := conn.WriteTo([]byte(pingMsg), dst); err == nil {
				tx.Add(1)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if time.Now().After(end) {
					return
				}
			}
		}
	}()

	_ = conn.SetReadDeadline(end)
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			break // deadline reached (or closed)
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := ua.AddrPort()
		if netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) != peer {
			continue
		}
		kind := string(buf[:n])
		if kind != pingMsg && kind != pongMsg {
			continue
		}
		if rep.FirstRxMs < 0 {
			rep.FirstRxMs = ms(time.Since(bound))
			rep.FirstRxKind = kind
			log.Printf("verify: first packet from peer after %.3f ms (%s)", rep.FirstRxMs, kind)
		}
		if kind == pingMsg {
			rxPing.Add(1)
			_, _ = conn.WriteTo([]byte(pongMsg), dst)
		} else {
			rxPong.Add(1)
		}
	}
	rep.Tx, rep.RxPing, rep.RxPong = tx.Load(), rxPing.Load(), rxPong.Load()
	rep.OK = rep.RxPong > 0
	return rep, nil
}

func emitVerify(rep *verifyReport, err error) {
	if err != nil {
		log.Printf("verify failed: %v", err)
		return
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"verify": rep})
}
