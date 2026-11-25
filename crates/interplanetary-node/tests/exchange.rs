//! Loopback exchanges over TCP, UDP, and LTP.

use interplanetary_node::{Node, NodeConfig, Peer, TlsMode, Transport};
use interplanetary_types::{Bytes, DtnTimeMs, EndpointId, ErrorKind, NodeId};
use rcgen::{BasicConstraints, CertificateParams, DnType, Ia5String, IsCa, KeyPair, SanType};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

fn eid(node: u64) -> EndpointId {
    EndpointId::ipn(0, node, 1).unwrap()
}

fn node(node_number: u64) -> NodeId {
    NodeId::ipn(0, node_number)
}

fn config(
    number: u64,
    tcp: Option<SocketAddr>,
    udp: Option<SocketAddr>,
    ltp: Option<SocketAddr>,
    peers: Vec<Peer>,
    tls: TlsMode,
) -> NodeConfig {
    NodeConfig {
        local_node: node(number),
        local_eid: eid(number),
        tcp_listen: tcp,
        udp_listen: udp,
        ltp_listen: ltp,
        ltp_engine_id: number,
        ltp_segment_payload: 16,
        peers,
        storage_capacity: Bytes::from_kib(64).unwrap(),
        tls,
        #[cfg(feature = "bpsec")]
        bpsec: None,
        #[cfg(feature = "bpsec")]
        allow_zero_iv_counter: false,
        administrative_domain: Some(1),
    }
}

#[tokio::test]
async fn plaintext_rejects_non_loopback() {
    let err = Node::bind(config(
        1,
        Some("0.0.0.0:4556".parse().unwrap()),
        None,
        None,
        Vec::new(),
        TlsMode::InsecurePlaintext,
    ))
    .await
    .unwrap_err();
    assert_eq!(err.kind(), &ErrorKind::InvalidConfig);
}

#[tokio::test]
async fn tcp_exchanges_a_bundle() {
    let mut listener = Node::bind(config(
        1,
        Some("127.0.0.1:0".parse().unwrap()),
        None,
        None,
        vec![Peer {
            node: node(2),
            destinations: vec![eid(2)],
            transport: Transport::Tcp {
                addr: "127.0.0.1:9".parse().unwrap(),
                dial: false,
                server_name: None,
            },
        }],
        TlsMode::InsecurePlaintext,
    ))
    .await
    .unwrap();
    let listener_addr = listener.tcp_addr().unwrap();

    let dialer = Node::bind(config(
        2,
        Some("127.0.0.1:0".parse().unwrap()),
        None,
        None,
        vec![Peer {
            node: node(1),
            destinations: vec![eid(1)],
            transport: Transport::Tcp {
                addr: listener_addr,
                dial: true,
                server_name: None,
            },
        }],
        TlsMode::InsecurePlaintext,
    ))
    .await
    .unwrap();

    dialer
        .send(eid(1), b"over-tcp".to_vec(), 60_000)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), listener.recv())
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(got.payload, b"over-tcp");
    let now = DtnTimeMs::from_system_time(SystemTime::now()).unwrap();
    let skew = now.as_millis().abs_diff(got.creation.as_millis());
    assert!(skew < 10_000, "creation time skew {skew} ms");

    listener.shutdown().await.unwrap();
    dialer.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_delivers_one_datagram() {
    let mut listener = Node::bind(config(
        1,
        None,
        Some("127.0.0.1:0".parse().unwrap()),
        None,
        Vec::new(),
        TlsMode::InsecurePlaintext,
    ))
    .await
    .unwrap();
    let sender = Node::bind(config(
        2,
        None,
        Some("127.0.0.1:0".parse().unwrap()),
        None,
        vec![Peer {
            node: node(1),
            destinations: vec![eid(1)],
            transport: Transport::Udp {
                addr: listener.udp_addr().unwrap(),
            },
        }],
        TlsMode::InsecurePlaintext,
    ))
    .await
    .unwrap();

    sender
        .send(eid(1), b"over-udp".to_vec(), 60_000)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), listener.recv())
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(got.payload, b"over-udp");
    listener.shutdown().await.unwrap();
    sender.shutdown().await.unwrap();
}

#[tokio::test]
async fn ltp_red_part_delivers_a_bundle() {
    let mut listener = Node::bind(config(
        1,
        None,
        None,
        Some("127.0.0.1:0".parse().unwrap()),
        Vec::new(),
        TlsMode::InsecurePlaintext,
    ))
    .await
    .unwrap();
    let sender = Node::bind(config(
        2,
        None,
        None,
        Some("127.0.0.1:0".parse().unwrap()),
        vec![Peer {
            node: node(1),
            destinations: vec![eid(1)],
            transport: Transport::Ltp {
                addr: listener.ltp_addr().unwrap(),
            },
        }],
        TlsMode::InsecurePlaintext,
    ))
    .await
    .unwrap();

    let payload = b"ltp-block-over-udp-red-part".to_vec();
    sender.send(eid(1), payload.clone(), 60_000).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), listener.recv())
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(got.payload, payload);
    listener.shutdown().await.unwrap();
    sender.shutdown().await.unwrap();
}

#[tokio::test]
async fn tls_tcp_exchanges_a_bundle() {
    let certs = test_certs();
    let mut listener = Node::bind(config(
        1,
        Some("127.0.0.1:0".parse().unwrap()),
        None,
        None,
        vec![Peer {
            node: node(2),
            destinations: vec![eid(2)],
            transport: Transport::Tcp {
                addr: "127.0.0.1:9".parse().unwrap(),
                dial: false,
                server_name: None,
            },
        }],
        TlsMode::Mutual {
            ca_pem: certs.ca_pem.clone(),
            cert_pem: certs.listener_cert,
            key_pem: certs.listener_key,
        },
    ))
    .await
    .unwrap();

    let dialer = Node::bind(config(
        2,
        Some("127.0.0.1:0".parse().unwrap()),
        None,
        None,
        vec![Peer {
            node: node(1),
            destinations: vec![eid(1)],
            transport: Transport::Tcp {
                addr: listener.tcp_addr().unwrap(),
                dial: true,
                server_name: Some("localhost".to_string()),
            },
        }],
        TlsMode::Mutual {
            ca_pem: certs.ca_pem,
            cert_pem: certs.dialer_cert,
            key_pem: certs.dialer_key,
        },
    ))
    .await
    .unwrap();

    dialer
        .send(eid(1), b"over-tls".to_vec(), 60_000)
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(3), listener.recv())
        .await
        .expect("timed out")
        .unwrap();
    assert_eq!(got.payload, b"over-tls");
    listener.shutdown().await.unwrap();
    dialer.shutdown().await.unwrap();
}

struct TestCerts {
    ca_pem: Vec<u8>,
    listener_cert: Vec<u8>,
    listener_key: Vec<u8>,
    dialer_cert: Vec<u8>,
    dialer_key: Vec<u8>,
}

fn test_certs() -> TestCerts {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "interplanetary-test-ca");
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let issue = |node_id: &str| {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params
            .subject_alt_names
            .push(SanType::URI(Ia5String::try_from(node_id).unwrap()));
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    };
    let (listener_cert, listener_key) = issue("ipn:1");
    let (dialer_cert, dialer_key) = issue("ipn:2");
    TestCerts {
        ca_pem: ca.pem().into_bytes(),
        listener_cert,
        listener_key,
        dialer_cert,
        dialer_key,
    }
}
