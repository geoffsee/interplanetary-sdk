//! Two loopback nodes exchange one bundle over TCPCLv4.
//!
//! ```text
//! cargo run -p interplanetary-sdk --features live-node --example live_exchange
//! ```

use interplanetary_sdk::live::{Node, NodeConfig, Peer, TlsMode, Transport};
use interplanetary_types::{Bytes, EndpointId, NodeId};
use std::time::Duration;

#[tokio::main]
async fn main() -> interplanetary_types::Result<()> {
    let local = |node: u64| EndpointId::ipn(0, node, 1).unwrap();
    let mut listener = Node::bind(NodeConfig {
        local_node: NodeId::ipn(0, 1),
        local_eid: local(1),
        tcp_listen: Some("127.0.0.1:0".parse().unwrap()),
        udp_listen: None,
        ltp_listen: None,
        ltp_engine_id: 1,
        ltp_segment_payload: 1400,
        peers: vec![Peer {
            node: NodeId::ipn(0, 2),
            destinations: vec![local(2)],
            transport: Transport::Tcp {
                addr: "127.0.0.1:9".parse().unwrap(),
                dial: false,
                server_name: None,
            },
        }],
        storage_capacity: Bytes::from_kib(256).unwrap(),
        tls: TlsMode::InsecurePlaintext,
        #[cfg(feature = "bpsec-default")]
        bpsec: None,
        #[cfg(feature = "bpsec-default")]
        allow_zero_iv_counter: false,
        administrative_domain: Some(1),
    })
    .await?;

    let dialer = Node::bind(NodeConfig {
        local_node: NodeId::ipn(0, 2),
        local_eid: local(2),
        tcp_listen: Some("127.0.0.1:0".parse().unwrap()),
        udp_listen: None,
        ltp_listen: None,
        ltp_engine_id: 2,
        ltp_segment_payload: 1400,
        peers: vec![Peer {
            node: NodeId::ipn(0, 1),
            destinations: vec![local(1)],
            transport: Transport::Tcp {
                addr: listener.tcp_addr().unwrap(),
                dial: true,
                server_name: None,
            },
        }],
        storage_capacity: Bytes::from_kib(256).unwrap(),
        tls: TlsMode::InsecurePlaintext,
        #[cfg(feature = "bpsec-default")]
        bpsec: None,
        #[cfg(feature = "bpsec-default")]
        allow_zero_iv_counter: false,
        administrative_domain: Some(1),
    })
    .await?;

    dialer
        .send(local(1), b"hello from a live node".to_vec(), 60_000)
        .await?;
    let got = tokio::time::timeout(Duration::from_secs(3), listener.recv())
        .await
        .expect("delivery timed out")?;
    println!("{}", String::from_utf8_lossy(&got.payload));
    listener.shutdown().await?;
    dialer.shutdown().await?;
    Ok(())
}
