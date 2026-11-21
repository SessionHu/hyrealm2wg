# hyrealm2wg

NAT traversal for **kernel WireGuard**, built on [Hysteria Realms](https://v2.hysteria.network/docs/advanced/Realms/).

Once the hole is punched, the program immediately closes the punching socket and, via netlink, lets an existing WireGuard interface take over the same local UDP port and fills in the peer endpoint. A NAT or firewall only tracks `(internal IP:port) <-> (peer IP:port)`; it does not and it is impossible to care which process owns the socket, so the hole stays valid. From then on all traffic goes through kernel WireGuard, with no userspace forwarding.

## Requirements

- A device with Linux Kernel with WireGuard (5.6+)
- A [hysteria-realm-server](https://github.com/apernet/hysteria-realm-server).

## Build

```bash
./build.sh
```

## Usage

### Flags

| Flag | Default | Description |
|---|---|---|
| `-mode` | (required) | `wait` registers the realm and waits; `connect` initiates a connection to it |
| `-realm` | (required) | realm address |
| `-stun` | `stun.l.google.com:19302,stun.cloudflare.com:3478` | comma-separated STUN servers |
| `-family` | `4` | `4`, `6` or `any` |
| `-punch-timeout` | `10s` | punch timeout |
| `-punch-interval` | `100ms` | interval between punch hello packets |
| `-once` | `false` | wait mode: exit after the first successful punch |
| `-wg-if` | | existing WG interface to hand the port to |
| `-wg-peer` | | public key (base64) of the peer on that interface |
| `-keepalive` | `25s` | PersistentKeepalive set on the peer at hand-off |
| `-wg-wait` | `15s` | how long to watch for a new handshake after hand-off |
| `-release-port` | `false` | if `-wg-if` currently listens on `lport`, move it to a random port first |
| `-verify` | `false` | skip WG and run the hand-off test instead (see below) |
| `-verify-duration` | `10s` | how long `-verify` exchanges ping/pong |

### Output

```
$ sudo ./hyrealm2wg_linux-gnu_amd64 -mode wait -realm 'realm://public@realm.hy2.io/kfccrazythursdayvivo50' -wg-if i-octo-3 -wg-peer VQEJRVW/HoivcGPaiSfc/NJO/ripO+Ot0Mst5IJCqQw=
19:43:28.080860 local port 47873, external addrs [60.3.114.51:47873]
19:43:28.843647 registered realm "kfccrazythursdayvivo50", ttl=60
19:43:49.187796 peer addrs [122.237.114.51:38311], responding
19:43:49.306036 wg: i-octo-3 now on port 47873, endpoint 122.237.114.51:38311, 21.167 ms after punch
19:43:49.356601 wg: handshake completed 59.3 ms after punch
{"mode":"wait","local_port":47873,"local_addrs":["60.3.114.51:47873"],"peer_addr":"122.237.114.51:38311","wg":{"iface":"i-octo-3","handoff_ms":21.167,"handshake_ms":59.312,"ok":true}}
```

```
$ sudo ./hyrealm2wg_linux-gnu_amd64 -mode connect -realm 'realm://public@realm.hy2.io/kfccrazythursdayvivo50' -wg-if i-flint-3 -wg-peer imexon9/LXN4mDV4VI0iBqjPQ/GGsVA2NC84exeRWHM=
19:43:47.552840 local port 38311, external addrs [122.237.114.51:38311]
19:43:49.266623 peer addrs [60.3.114.51:47873], punching
19:43:49.342262 wg: i-flint-3 now on port 38311, endpoint 60.3.114.51:47873, 35.612 ms after punch
19:43:49.392774 wg: handshake completed 58.2 ms after punch
{"mode":"connect","local_port":38311,"local_addrs":["122.237.114.51:38311"],"peer_addr":"60.3.114.51:47873","wg":{"iface":"i-flint-3","handoff_ms":35.612,"handshake_ms":58.224,"ok":true}}
```

### Testing (`-verify`)

```bash
./hyrealm2wg -mode wait    -verify -realm '...'
./hyrealm2wg -mode connect -verify -realm '...'
```

## Notes

- One-time use.
- No multi-peer management yet.
- Does not create the WG interface for you.
- Design for dn42.

## Acknowledgements

- [Hysteria](https://github.com/apernet/hysteria) Realms (`extras/v2/realm`): rendezvous, STUN and punching logic.
- [wgctrl-go](https://github.com/WireGuard/wgctrl-go): configuring WireGuard over netlink.

## License

GPLv3 or later.
