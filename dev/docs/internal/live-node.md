# Live node

`interplanetary-node` is the socket runtime. The facade feature `live-node` re-exports it as `interplanetary_sdk::live`. The protocol kernel stays synchronous: it does not open a socket, start TLS, or read the wall clock. The node does those things and calls `BundleAgent` with the results.

`stable-full` and `full` do not enable `live-node`. BPSec is a separate node feature (`bpsec`). Enabling `live-node` does not turn on `bpsec-default` for the rest of the workspace.

## Transports

| Path | What it speaks |
| --- | --- |
| TCP | TCPCLv4 (RFC 9174). Mutual TLS starts after the contact header when `TlsMode::Mutual` is set. `InsecurePlaintext` refuses any non-loopback TCP listen address and any non-loopback TCP peer with `dial: true`. |
| UDP | One CBOR-encoded BPv7 bundle per datagram. No extra header. The receive buffer is 65,535 bytes. A bundle that does not fit in one datagram is not fragmented across datagrams. |
| LTP | RFC 5326 red-part block over UDP, one segment per datagram. Client service number 1 (`BUNDLE_SERVICE_ID`). Checkpoints, reports, report acknowledgements, and gap retransmission are implemented. |

UDP and LTP listeners are separate sockets. A peer is `Transport::Udp` or `Transport::Ltp`, not both on one address.

## API

```rust
live::Node::bind(NodeConfig) -> Result<Node>
node.send(destination, payload, lifetime_ms) -> Result<BundleId>
node.recv() -> Result<DeliveredBundle>
node.shutdown() -> Result<()>
node.tcp_addr() / udp_addr() / ltp_addr() -> Option<SocketAddr>
```

`send` returns when the agent has admitted the bundle. It does not wait for the peer to acknowledge it. `recv` returns the next bundle delivered to this node. `Drop` aborts the node task; `shutdown` asks TCP sessions to send `SESS_TERM` and then stops.

`bpsec` and `allow_zero_iv_counter` exist on `NodeConfig` only when the node crate is built with `bpsec` (the facade turns that on through `bpsec-default`). A struct literal in an example that is also built with `--all-features` has to set them behind `cfg(feature = "bpsec-default")`.

At least one of `tcp_listen`, `udp_listen`, and `ltp_listen` is required. Port 0 asks the OS for a port. Read the bound address back from the node before a peer dials it.

`NodeConfig` fields:

| Field | Meaning |
| --- | --- |
| `local_node` | Node id. TCPCL sends `NodeId`'s display form (`ipn:1` for allocator 0). |
| `local_eid` | Source endpoint of bundles this node originates. |
| `ltp_engine_id` | LTP engine number. `0` uses the ipn node number. |
| `ltp_segment_payload` | Maximum client-service bytes in one LTP data segment. `0` means 1400. |
| `peers` | Neighbors. Each peer lists destination endpoint ids and one transport. |
| `storage_capacity` | Cap on the in-memory store. |
| `tls` | `Mutual { ca_pem, cert_pem, key_pem }` or `InsecurePlaintext`. `Debug` redacts PEM bytes. |
| `administrative_domain` | Shared domain number. Required to forward Private Use ipn node numbers (`1..=16_777_215`). |
| `bpsec` | Present only with the node `bpsec` feature. Outbound BCB. The IV counter must be non-zero unless `allow_zero_iv_counter` is set. |

## Routing

Routes are static. Each endpoint in `Peer.destinations` maps to `Peer.node`.

The agent queues a transmission under the **destination** node id (`NodeId::from_endpoint` of the bundle destination), and the node sends that queue on the link registered for the same node id. A `Peer` therefore has to be the destination node, not an intermediate next hop. Multi-hop through a neighbor that is not the bundle's destination node is not implemented.

UDP and LTP links are registered at startup. A TCP peer is registered when the session reaches Established. `dial: true` means this node connects. `dial: false` means it only accepts. The active TCPCL entity writes `SESS_INIT` first. The passive entity reads the peer's contact header and `SESS_INIT`, sends its own `SESS_INIT`, and then processes the peer's message. Processing first would move the session to Established and reject the local `SESS_INIT`.

A failed TCP dial waits on `ReconnectScheduler`: at least 1 second, exponential, at most 60 seconds. A session generation counter ignores a `Down` from an older attempt after a newer session is up.

## TCPCL and TLS

Contact headers (`dtn!`, version 4) are exchanged in the clear. `set_nodelay(true)` is set on the socket.

With `TlsMode::Mutual`, both contact headers must set `CAN_TLS`. TLS is STARTTLS on that connection (RFC 9174 §4.4.3). The active entity is the TLS client. The server requires a client certificate (`WebPkiClientVerifier`). RFC 9174 does not define an ALPN id, and none is sent. The client `ServerName` is `Transport::Tcp.server_name` (a DNS name).

After `SESS_INIT`, the peer certificate must contain the announced node id. Accepted forms are a URI subjectAltName equal to that string (for example `ipn:1`) or an `otherName` with OID `1.3.6.1.5.5.7.8.11` (`id-on-bundleEID`) whose value is an IA5String, UTF8String, or PrintableString. A mismatch sends `SESS_TERM` with reason `CONTACT_FAILURE`.

The model advertises a 30-second keepalive (clamped to 30..=600; 0 disables). The contact-header timeout is 60 seconds. Idle timeout is twice the negotiated keepalive. The live driver polls the session once a second. `SESS_TERM` on the wire is the 3-octet header in RFC 9174 Figure 27. `Message::encode` can append a diagnostic with no length; the live path strips that trailer. `Message::decode_frame` returns `Ok(None)` until a full message is buffered. Frames larger than 16 MiB are rejected.

## Time

`DtnTimeMs::from_system_time` converts a `SystemTime` the caller already read. It does not read the clock. Instants before the Unix epoch or before 2000-01-01 UTC are errors. The DTN epoch offset is 946684800 Unix seconds.

The node maps that millisecond value to `SimInstant::from_nanos(dtn_ms * 1_000_000)` and passes it to `BundleAgent::poll`, which expires bundles against creation time plus lifetime. Originated bundles use CRC-16 and a per-process creation sequence that starts at 1.

## LTP subset

`interplanetary-ltp` encodes and accepts segments. It does not open sockets. In scope:

- Red data (type 0), checkpoint (1), checkpoint + end of red part (2), checkpoint + end of red part + end of block (3)
- Report (8) and report acknowledgement (9)
- SDNV fields (RFC 6256)
- Header and trailer extension counts of zero
- Retransmission of gaps named in a report

End of block is set only when the segment ends at the true block length. A gap fill must not advertise a shorter block.

Out of scope: green data, session cancellation, cookies, security extensions, and a retransmission timer. A lost checkpoint or report is not retried until another segment for that session arrives. Sessions stay in memory until the report acknowledges full reception (sender) or the report acknowledgement arrives (receiver).

## BPSec

UDP and LTP are not encrypted. TCP plaintext is loopback-only. Payload protection is BPSec on the node `bpsec` feature, which the facade's `bpsec-default` feature enables with `interplanetary-node?/bpsec` when the node dependency is present.

Set `NodeConfig.bpsec` to an `OutboundBcbConfig` whose IV counter is unique across restarts. A zero counter is rejected unless `allow_zero_iv_counter` is set, because a restart would reuse an AES-GCM nonce.

## v1 limits

- The bundle store is the in-memory `StorageManager`. A process restart drops every stored bundle.
- Links are configured peers, not a contact plan. The simulator remains the scheduled-contact tool.
- Forwarding is single destination-node hop, as described under Routing.
- A bundle the agent refuses (`receive_bytes_from_cla` error) is dropped with no status report to the peer.
- LTP is the red-part subset above.
- Wire interoperability with ION or another stack has not been run.
- The threat model still requires an independent review before a node is exposed to untrusted peers.
- Orbital dynamics, a durable store, a contact scheduler, and production QUIC/TIPTOP are out of this runtime.

## Example and tests

Two loopback nodes, plaintext TCP:

```bash
cargo run -p interplanetary-sdk --features live-node --example live_exchange
```

`make example EXAMPLE=live_exchange FEATURES=live-node` is the same command. `make examples` does not build it, because the default feature set does not include `live-node`.

```bash
cargo test -p interplanetary-node --test exchange
cargo test -p interplanetary-ltp
```

The exchange test covers plaintext TCP (including the non-loopback refusal), one UDP datagram, a multi-segment LTP block, and mutual TLS with a URI subjectAltName. The listener and the sender share `administrative_domain: Some(1)` so Private Use ipn numbers can be forwarded.
