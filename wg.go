package main

// Phase 2: hand the punched port over to an existing, already configured WireGuard
// interface with a single netlink call (wgctrl).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type wgHandoff struct {
	cl        *wgctrl.Client
	iface     string
	peer      wgtypes.Key
	keepalive time.Duration
	wait      time.Duration // how long to watch for the handshake after hand-off
}

type handoffStats struct {
	Iface       string  `json:"iface"`
	HandoffMs   float64 `json:"handoff_ms"`   // Punch returned -> netlink call returned
	HandshakeMs float64 `json:"handshake_ms"` // Punch returned -> new handshake seen; -1 if none
	OK          bool    `json:"ok"`
}

// newWGHandoff opens the netlink client and checks everything we can check before the
// punch, so that after the punch only one netlink call is left to do.
func newWGHandoff(iface, peerKey string, lport int, keepalive, wait time.Duration, release bool) (*wgHandoff, error) {
	if peerKey == "" {
		return nil, errors.New("-wg-peer (peer public key) is required with -wg-if")
	}
	key, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return nil, fmt.Errorf("bad -wg-peer: %w", err)
	}
	cl, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	dev, err := cl.Device(iface)
	if err != nil {
		cl.Close()
		return nil, fmt.Errorf("open interface %s: %w", iface, err)
	}
	found := false
	for _, p := range dev.Peers {
		if p.PublicKey == key {
			found = true
			break
		}
	}
	if !found {
		cl.Close()
		return nil, fmt.Errorf("peer %s is not configured on %s (add it with its allowed-ips first)", peerKey, iface)
	}
	// The punch socket needs the port, so WireGuard must not be holding it.
	if lport != 0 && dev.ListenPort == lport {
		if !release {
			cl.Close()
			return nil, fmt.Errorf("%s currently listens on %d, the port the punch must use; "+
				"move it away first or pass -release-port", iface, lport)
		}
		zero := 0 // 0 = let the kernel pick a random port
		if err := cl.ConfigureDevice(iface, wgtypes.Config{ListenPort: &zero}); err != nil {
			cl.Close()
			return nil, fmt.Errorf("release port %d on %s: %w", lport, iface, err)
		}
		log.Printf("moved %s off port %d (random port) so the punch socket can use it", iface, lport)
	}
	return &wgHandoff{cl: cl, iface: iface, peer: key, keepalive: keepalive, wait: wait}, nil
}

func (h *wgHandoff) Close() { h.cl.Close() }

const recentHandshakeWindow = 2*time.Minute + 15*time.Second

// apply must be called right after the punch socket has been closed. One netlink message
// sets the listen port, the peer endpoint and the keepalive. (Setting a keepalive on a
// running interface should make the kernel send one at once, which starts the handshake;
// the printed handshake_ms shows whether that really happens.)
func (h *wgHandoff) apply(ctx context.Context, port int, peerStr string, punchedAt time.Time) (*handoffStats, error) {
	ap, err := netip.ParseAddrPort(peerStr)
	if err != nil {
		return nil, err
	}
	ep := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
	ka := h.keepalive

	err = h.cl.ConfigureDevice(h.iface, wgtypes.Config{
		ListenPort: &port,
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   h.peer,
			UpdateOnly:                  true,
			Endpoint:                    ep,
			PersistentKeepaliveInterval: &ka,
		}},
	})
	st := &handoffStats{Iface: h.iface, HandoffMs: ms(time.Since(punchedAt)), HandshakeMs: -1}
	if err != nil {
		return st, fmt.Errorf("configure %s: %w", h.iface, err)
	}
	log.Printf("wg: %s now on port %d, endpoint %s, %.3f ms after punch", h.iface, port, ep, st.HandoffMs)

	deadline := time.Now().Add(h.wait)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		dev, err := h.cl.Device(h.iface)
		if err != nil {
			return st, fmt.Errorf("read %s: %w", h.iface, err)
		}
		for _, p := range dev.Peers {
			if p.PublicKey == h.peer && p.LastHandshakeTime.After(punchedAt) {
				st.HandshakeMs = ms(p.LastHandshakeTime.Sub(punchedAt))
				st.OK = true
				log.Printf("wg: handshake completed %.1f ms after punch", st.HandshakeMs)
				return st, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if dev, err := h.cl.Device(h.iface); err == nil {
		for _, p := range dev.Peers {
			if p.PublicKey == h.peer {
				if !p.LastHandshakeTime.IsZero() {
					age := time.Since(p.LastHandshakeTime)
					if age < recentHandshakeWindow {
						st.OK = true
						log.Printf("wg: no new handshake within %s, but peer had a handshake %.1fs ago (< %s); treating as ok",
							h.wait, age.Seconds(), recentHandshakeWindow)
						return st, nil
					}
				}
				break
			}
		}
	}

	log.Printf("wg: no new handshake within %s", h.wait)
	return st, nil
}
