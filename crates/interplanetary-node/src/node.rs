//! One live bundle node.

use crate::tcp::{self, DriveArgs, TlsSide};
use crate::tls::TlsMaterial;
use interplanetary_bp::{BundleBuilder, CrcType, encode};
use interplanetary_bpa::{
    BpaConfig, BundleAgent, StatusReportPolicy, policy::ForwardingFailedPolicy,
};
use interplanetary_cla::ReconnectScheduler;
use interplanetary_ltp::{LtpEngine, Segment};
use interplanetary_store::StorageManager;
use interplanetary_tcpcl::Role;
use interplanetary_types::{
    BundleId, Bytes, CreationTimestamp, DtnTimeMs, EndpointId, Error, NodeId, Result, SimInstant,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, watch};

/// How a configured peer is reached.
#[derive(Debug, Clone)]
pub enum Transport {
    /// TCPCLv4. `dial` opens the connection; listeners leave it false.
    Tcp {
        /// Peer socket address.
        addr: SocketAddr,
        /// When true, this node connects. When false, it only accepts.
        dial: bool,
        /// DNS name for the TLS client handshake. Ignored for plaintext.
        server_name: Option<String>,
    },
    /// One BPv7 bundle per UDP datagram.
    Udp {
        /// Peer socket address.
        addr: SocketAddr,
    },
    /// RFC 5326 red-part LTP, one segment per UDP datagram.
    Ltp {
        /// Peer socket address.
        addr: SocketAddr,
    },
}

/// A neighbor and the endpoint ids that route to it.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Peer node id.
    pub node: NodeId,
    /// Destination endpoints forwarded to this peer.
    pub destinations: Vec<EndpointId>,
    /// Link used to reach the peer.
    pub transport: Transport,
}

/// TLS for TCPCLv4, or plaintext restricted to loopback.
#[derive(Clone)]
pub enum TlsMode {
    /// Mutual TLS. Certificates are PEM.
    Mutual {
        /// Trust anchor PEM.
        ca_pem: Vec<u8>,
        /// End-entity certificate PEM.
        cert_pem: Vec<u8>,
        /// Private key PEM.
        key_pem: Vec<u8>,
    },
    /// No TLS. Listen and dial addresses must be loopback.
    InsecurePlaintext,
}

impl std::fmt::Debug for TlsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsMode::Mutual { .. } => f.write_str("Mutual"),
            TlsMode::InsecurePlaintext => f.write_str("InsecurePlaintext"),
        }
    }
}

/// Configuration for [`Node::bind`].
pub struct NodeConfig {
    /// Local node id. Sent as the TCPCL node id and used as the LTP engine id when `ltp_engine_id` is 0.
    pub local_node: NodeId,
    /// Local endpoint that originated bundles use as their source.
    pub local_eid: EndpointId,
    /// TCP listen address. Port 0 asks the OS for a port.
    pub tcp_listen: Option<SocketAddr>,
    /// UDP listen address for bundle datagrams.
    pub udp_listen: Option<SocketAddr>,
    /// UDP listen address for LTP segments.
    pub ltp_listen: Option<SocketAddr>,
    /// LTP engine number. `0` uses the ipn node number.
    pub ltp_engine_id: u64,
    /// Maximum client-service bytes in one LTP data segment.
    pub ltp_segment_payload: usize,
    /// Neighbors.
    pub peers: Vec<Peer>,
    /// In-memory bundle store capacity. Contents are dropped on process exit.
    pub storage_capacity: Bytes,
    /// TCP security mode.
    pub tls: TlsMode,
    /// Optional outbound BPSec BCB. The IV counter must be non-zero unless `allow_zero_iv_counter` is set.
    #[cfg(feature = "bpsec")]
    pub bpsec: Option<interplanetary_bpa::OutboundBcbConfig>,
    /// Permit an AES-GCM IV counter of zero. A restart then risks nonce reuse.
    #[cfg(feature = "bpsec")]
    pub allow_zero_iv_counter: bool,
    /// Administrative domain shared with neighbors. Required for Private Use ipn numbers.
    pub administrative_domain: Option<u32>,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("local_node", &self.local_node)
            .field("local_eid", &self.local_eid)
            .field("tcp_listen", &self.tcp_listen)
            .field("udp_listen", &self.udp_listen)
            .field("ltp_listen", &self.ltp_listen)
            .finish_non_exhaustive()
    }
}

/// A bundle delivered to the local node.
#[derive(Debug, Clone)]
pub struct DeliveredBundle {
    /// Bundle identity.
    pub bundle_id: BundleId,
    /// Source endpoint.
    pub source: EndpointId,
    /// Destination endpoint.
    pub destination: EndpointId,
    /// Payload bytes.
    pub payload: Vec<u8>,
    /// Creation time.
    pub creation: DtnTimeMs,
}

/// A running bundle node.
pub struct Node {
    cmd_tx: mpsc::Sender<Cmd>,
    recv_rx: mpsc::Receiver<DeliveredBundle>,
    join: Option<tokio::task::JoinHandle<()>>,
    tcp_addr: Option<SocketAddr>,
    udp_addr: Option<SocketAddr>,
    ltp_addr: Option<SocketAddr>,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("tcp_addr", &self.tcp_addr)
            .field("udp_addr", &self.udp_addr)
            .field("ltp_addr", &self.ltp_addr)
            .finish_non_exhaustive()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

enum Cmd {
    Send {
        destination: EndpointId,
        payload: Vec<u8>,
        lifetime_ms: u64,
        reply: oneshot::Sender<Result<BundleId>>,
    },
    Shutdown,
}

enum OutLink {
    Tcp(mpsc::UnboundedSender<Vec<u8>>),
    Udp(SocketAddr),
    Ltp(SocketAddr),
}

enum NetEvent {
    Up {
        node: NodeId,
        tx: mpsc::UnboundedSender<Vec<u8>>,
        generation: u64,
    },
    Down {
        node: NodeId,
        generation: u64,
    },
    Bundle(Vec<u8>),
}

struct LinkSlot {
    generation: u64,
    link: OutLink,
}

impl Node {
    /// Bind the configured listeners and start dialing peers that set `dial`.
    ///
    /// At least one of `tcp_listen`, `udp_listen`, and `ltp_listen` is required.
    /// `InsecurePlaintext` rejects a non-loopback TCP listen address and any
    /// non-loopback TCP peer with `dial` set.
    pub async fn bind(config: NodeConfig) -> Result<Self> {
        validate(&config)?;
        let tls = match &config.tls {
            TlsMode::Mutual {
                ca_pem,
                cert_pem,
                key_pem,
            } => Some(crate::tls::build(ca_pem, cert_pem, key_pem)?),
            TlsMode::InsecurePlaintext => None,
        };

        let tcp_listener = match config.tcp_listen {
            Some(addr) => Some(
                TcpListener::bind(addr)
                    .await
                    .map_err(|err| Error::invalid_config(format!("TCP listen {addr}: {err}")))?,
            ),
            None => None,
        };
        let tcp_addr = tcp_listener
            .as_ref()
            .map(|listener| listener.local_addr())
            .transpose()
            .map_err(|err| Error::invalid_config(format!("TCP local address: {err}")))?;
        let udp = match config.udp_listen {
            Some(addr) => Some(Arc::new(UdpSocket::bind(addr).await.map_err(|err| {
                Error::invalid_config(format!("UDP listen {addr}: {err}"))
            })?)),
            None => None,
        };
        let udp_addr = udp
            .as_ref()
            .map(|sock| sock.local_addr())
            .transpose()
            .map_err(|err| Error::invalid_config(format!("UDP local address: {err}")))?;
        let ltp = match config.ltp_listen {
            Some(addr) => Some(Arc::new(UdpSocket::bind(addr).await.map_err(|err| {
                Error::invalid_config(format!("LTP listen {addr}: {err}"))
            })?)),
            None => None,
        };
        let ltp_addr = ltp
            .as_ref()
            .map(|sock| sock.local_addr())
            .transpose()
            .map_err(|err| Error::invalid_config(format!("LTP local address: {err}")))?;

        let (cmd_tx, cmd_rx) = mpsc::channel(32);
        let (recv_tx, recv_rx) = mpsc::channel(32);
        let (stop_tx, stop_rx) = watch::channel(false);
        let generation = Arc::new(AtomicU64::new(1));

        let join = tokio::spawn(async move {
            if let Err(err) = run(
                config,
                tls,
                tcp_listener,
                udp,
                ltp,
                cmd_rx,
                recv_tx,
                stop_tx,
                stop_rx,
                generation,
            )
            .await
            {
                eprintln!("interplanetary-node stopped: {err}");
            }
        });

        Ok(Self {
            cmd_tx,
            recv_rx,
            join: Some(join),
            tcp_addr,
            udp_addr,
            ltp_addr,
        })
    }

    /// Bound TCP address, when a TCP listener was configured.
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    /// Bound UDP address, when a UDP listener was configured.
    pub fn udp_addr(&self) -> Option<SocketAddr> {
        self.udp_addr
    }

    /// Bound LTP address, when an LTP listener was configured.
    pub fn ltp_addr(&self) -> Option<SocketAddr> {
        self.ltp_addr
    }

    /// Originate a bundle. Creation time is the current DTN time.
    ///
    /// The id is returned when the agent admits the bundle. It does not mean
    /// the peer has acknowledged it. Local delivery is observed with [`Node::recv`].
    pub async fn send(
        &self,
        destination: EndpointId,
        payload: Vec<u8>,
        lifetime_ms: u64,
    ) -> Result<BundleId> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::Send {
                destination,
                payload,
                lifetime_ms,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::transfer_failed("node stopped"))?;
        reply_rx
            .await
            .map_err(|_| Error::transfer_failed("node stopped"))?
    }

    /// Next locally delivered payload.
    pub async fn recv(&mut self) -> Result<DeliveredBundle> {
        self.recv_rx
            .recv()
            .await
            .ok_or_else(|| Error::transfer_failed("node stopped"))
    }

    /// Ask the node to close sessions and stop.
    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.cmd_tx.send(Cmd::Shutdown).await;
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
        Ok(())
    }
}

fn validate(config: &NodeConfig) -> Result<()> {
    if config.tcp_listen.is_none() && config.udp_listen.is_none() && config.ltp_listen.is_none() {
        return Err(Error::invalid_config(
            "configure a TCP, UDP, or LTP listen address",
        ));
    }
    #[cfg(feature = "bpsec")]
    if let Some(bpsec) = &config.bpsec
        && bpsec.next_iv_counter == 0
        && !config.allow_zero_iv_counter
    {
        return Err(Error::invalid_config(
            "BPSec IV counter is 0; set a unique counter or allow_zero_iv_counter",
        ));
    }
    if matches!(config.tls, TlsMode::InsecurePlaintext) {
        if let Some(addr) = config.tcp_listen {
            require_loopback(addr)?;
        }
        for peer in &config.peers {
            if let Transport::Tcp { addr, dial, .. } = &peer.transport
                && *dial
            {
                require_loopback(*addr)?;
            }
        }
    }
    Ok(())
}

fn require_loopback(addr: SocketAddr) -> Result<()> {
    if addr.ip().is_loopback() {
        Ok(())
    } else {
        Err(Error::invalid_config(format!(
            "InsecurePlaintext refuses non-loopback address {addr}"
        )))
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    config: NodeConfig,
    tls: Option<TlsMaterial>,
    tcp_listener: Option<TcpListener>,
    udp: Option<Arc<UdpSocket>>,
    ltp_sock: Option<Arc<UdpSocket>>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    recv_tx: mpsc::Sender<DeliveredBundle>,
    stop_tx: watch::Sender<bool>,
    stop_rx: watch::Receiver<bool>,
    generation: Arc<AtomicU64>,
) -> Result<()> {
    let mut routes = HashMap::new();
    for peer in &config.peers {
        for dest in &peer.destinations {
            routes.insert(dest.clone(), peer.node.clone());
        }
    }
    let mut agent = BundleAgent::new(
        BpaConfig {
            local_node: config.local_node.clone(),
            local_eid: config.local_eid.clone(),
            enable_forwarding: true,
            enable_delivery: true,
            status_report_policy: StatusReportPolicy::none(),
            cla_mtu: None,
            #[cfg(feature = "bpsec")]
            security_context: None,
            #[cfg(feature = "bpsec")]
            security_policy: None,
            enforce_private_use_restrictions: true,
            administrative_domain: config.administrative_domain,
            static_routes: Some(routes),
            forwarding_failed_policy: ForwardingFailedPolicy::Delete,
            #[cfg(feature = "bpsec")]
            outbound_bcb: config.bpsec.clone(),
        },
        StorageManager::new(config.storage_capacity),
    );
    if let Some(domain) = config.administrative_domain {
        for peer in &config.peers {
            agent.set_neighbor_domain(peer.node.clone(), domain)?;
        }
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel();
    let (ltp_tx, ltp_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();

    let mut links: HashMap<NodeId, LinkSlot> = HashMap::new();
    for peer in &config.peers {
        match &peer.transport {
            Transport::Udp { addr } => {
                links.insert(
                    peer.node.clone(),
                    LinkSlot {
                        generation: 0,
                        link: OutLink::Udp(*addr),
                    },
                );
            }
            Transport::Ltp { addr } => {
                links.insert(
                    peer.node.clone(),
                    LinkSlot {
                        generation: 0,
                        link: OutLink::Ltp(*addr),
                    },
                );
            }
            Transport::Tcp {
                addr,
                dial,
                server_name,
            } if *dial => {
                spawn_dialer(
                    *addr,
                    server_name.clone(),
                    config.local_node.to_string(),
                    tls.clone(),
                    event_tx.clone(),
                    stop_rx.clone(),
                    Arc::clone(&generation),
                );
            }
            Transport::Tcp { .. } => {}
        }
    }

    if let Some(listener) = tcp_listener {
        let local = config.local_node.to_string();
        let events = event_tx.clone();
        let stop = stop_rx.clone();
        let tls = tls.clone();
        let generation = Arc::clone(&generation);
        tokio::spawn(async move {
            accept_loop(listener, local, tls, events, stop, generation).await;
        });
    }
    if let Some(sock) = udp.clone() {
        let events = event_tx.clone();
        let mut stop = stop_rx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                tokio::select! {
                    _ = stop.changed() => {
                        if *stop.borrow() { break; }
                    }
                    received = sock.recv_from(&mut buf) => {
                        if let Ok((n, _)) = received {
                            let _ = events.send(NetEvent::Bundle(buf[..n].to_vec()));
                        }
                    }
                }
            }
        });
    }
    if let Some(sock) = ltp_sock.clone() {
        let engine_id = if config.ltp_engine_id == 0 {
            engine_from_node(&config.local_node)
        } else {
            config.ltp_engine_id
        };
        let payload = if config.ltp_segment_payload == 0 {
            1400
        } else {
            config.ltp_segment_payload
        };
        let events = event_tx.clone();
        let stop = stop_rx.clone();
        tokio::spawn(async move {
            run_ltp(sock, engine_id, payload, ltp_rx, events, stop).await;
        });
    }

    let local_eid = config.local_eid.clone();
    let mut sequence = 1u64;
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(Cmd::Send { destination, payload, lifetime_ms, reply }) => {
                        let result = originate(&mut agent, &local_eid, &mut sequence, destination, payload, lifetime_ms);
                        let _ = reply.send(result);
                        dispatch(&mut agent, &links, udp.as_deref(), &ltp_tx, &recv_tx).await;
                    }
                    Some(Cmd::Shutdown) | None => {
                        let _ = stop_tx.send(true);
                        break;
                    }
                }
            }
            event = event_rx.recv() => {
                let Some(event) = event else { break };
                match event {
                    NetEvent::Up { node, tx, generation } => {
                        links.insert(node, LinkSlot { generation, link: OutLink::Tcp(tx) });
                        dispatch(&mut agent, &links, udp.as_deref(), &ltp_tx, &recv_tx).await;
                    }
                    NetEvent::Down { node, generation } => {
                        if links.get(&node).is_some_and(|slot| slot.generation == generation && matches!(slot.link, OutLink::Tcp(_))) {
                            links.remove(&node);
                        }
                    }
                    NetEvent::Bundle(bytes) => {
                        if agent.receive_bytes_from_cla(&bytes).is_ok() {
                            dispatch(&mut agent, &links, udp.as_deref(), &ltp_tx, &recv_tx).await;
                        }
                    }
                }
            }
            _ = tick.tick() => {
                dispatch(&mut agent, &links, udp.as_deref(), &ltp_tx, &recv_tx).await;
            }
        }
    }
    Ok(())
}

fn originate(
    agent: &mut BundleAgent,
    source: &EndpointId,
    sequence: &mut u64,
    destination: EndpointId,
    payload: Vec<u8>,
    lifetime_ms: u64,
) -> Result<BundleId> {
    let now = DtnTimeMs::from_system_time(SystemTime::now())?;
    let seq = *sequence;
    *sequence = sequence.saturating_add(1);
    let bundle = BundleBuilder::new()
        .source(source.clone())
        .destination(destination)
        .creation_timestamp(CreationTimestamp::new(now, seq))
        .lifetime(lifetime_ms)
        .payload(payload)
        .crc_type(CrcType::Crc16)
        .build()?;
    let id = agent.send(bundle)?;
    agent.poll(sim_now(now));
    Ok(id)
}

async fn dispatch(
    agent: &mut BundleAgent,
    links: &HashMap<NodeId, LinkSlot>,
    udp: Option<&UdpSocket>,
    ltp_tx: &mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    recv_tx: &mpsc::Sender<DeliveredBundle>,
) {
    let now = DtnTimeMs::from_system_time(SystemTime::now()).unwrap_or(DtnTimeMs::EPOCH);
    agent.poll(sim_now(now));
    let nodes: Vec<NodeId> = links.keys().cloned().collect();
    for node in nodes {
        let Some(slot) = links.get(&node) else {
            continue;
        };
        let batch = agent.take_cla_transmissions_for(&node);
        for item in batch {
            let Ok(bytes) = encode(&item.bundle) else {
                continue;
            };
            match &slot.link {
                OutLink::Tcp(tx) => {
                    let _ = tx.send(bytes);
                }
                OutLink::Udp(addr) => {
                    if let Some(sock) = udp {
                        let _ = sock.send_to(&bytes, *addr).await;
                    }
                }
                OutLink::Ltp(addr) => {
                    let _ = ltp_tx.send((*addr, bytes));
                }
            }
        }
    }
    for bundle in agent.take_delivered_adus() {
        let payload = bundle
            .payload_block()
            .map(|block| block.data.clone())
            .unwrap_or_default();
        let delivered = DeliveredBundle {
            bundle_id: bundle.id(),
            source: bundle.primary.source.clone(),
            destination: bundle.primary.destination.clone(),
            creation: bundle.primary.creation_timestamp.time,
            payload,
        };
        let _ = recv_tx.send(delivered).await;
    }
}

fn sim_now(now: DtnTimeMs) -> SimInstant {
    SimInstant::from_nanos(now.as_millis().saturating_mul(1_000_000))
}

fn engine_from_node(node: &NodeId) -> u64 {
    match node {
        NodeId::Ipn { node, .. } => *node,
        _ => 1,
    }
}

fn spawn_dialer(
    addr: SocketAddr,
    server_name: Option<String>,
    local_node: String,
    tls: Option<TlsMaterial>,
    events: mpsc::UnboundedSender<NetEvent>,
    stop: watch::Receiver<bool>,
    generation: Arc<AtomicU64>,
) {
    tokio::spawn(async move {
        let mut scheduler = ReconnectScheduler::new(interplanetary_cla::ReconnectConfig::default());
        loop {
            if *stop.borrow() {
                break;
            }
            let now = tcp::unix_ms();
            if !scheduler.can_attempt(now) {
                let wait = scheduler
                    .next_attempt_time()
                    .unwrap_or(now)
                    .saturating_sub(now);
                tokio::time::sleep(Duration::from_millis(wait.max(50))).await;
                continue;
            }
            scheduler.record_attempt(now);
            let connect =
                tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await;
            let Ok(Ok(stream)) = connect else {
                continue;
            };
            let session_generation = generation.fetch_add(1, Ordering::Relaxed);
            let (bundle_tx, bundle_rx) = mpsc::unbounded_channel();
            let (up_tx, mut up_rx) = mpsc::unbounded_channel();
            let tls_side = tls.clone().map(|material| TlsSide::Client {
                material,
                name: server_name
                    .clone()
                    .unwrap_or_else(|| "localhost".to_string()),
            });
            let drive = tcp::drive(
                stream,
                DriveArgs {
                    role: Role::Active,
                    local_node: local_node.clone(),
                    tls: tls_side,
                    bundles: bundle_rx,
                    bundles_tx: bundle_tx,
                    inbound: inbound_bridge(events.clone()),
                    up: up_tx,
                    stop: stop.clone(),
                },
            );
            tokio::pin!(drive);
            let mut announced = None;
            loop {
                tokio::select! {
                    result = &mut drive => {
                        if let Some(node) = announced.take() {
                            let _ = events.send(NetEvent::Down { node, generation: session_generation });
                        }
                        if result.is_ok() {
                            scheduler.record_success();
                        }
                        break;
                    }
                    up = up_rx.recv() => {
                        if let Some((text, tx)) = up
                            && let Ok(node) = parse_node_id(&text)
                        {
                            announced = Some(node.clone());
                            let _ = events.send(NetEvent::Up {
                                node,
                                tx,
                                generation: session_generation,
                            });
                            scheduler.record_success();
                        }
                    }
                }
            }
        }
    });
}

async fn accept_loop(
    listener: TcpListener,
    local_node: String,
    tls: Option<TlsMaterial>,
    events: mpsc::UnboundedSender<NetEvent>,
    mut stop: watch::Receiver<bool>,
    generation: Arc<AtomicU64>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() { break; }
            }
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let session_generation = generation.fetch_add(1, Ordering::Relaxed);
                let (bundle_tx, bundle_rx) = mpsc::unbounded_channel();
                let (up_tx, mut up_rx) = mpsc::unbounded_channel();
                let events_session = events.clone();
                let tls_side = tls.clone().map(|material| TlsSide::Server { material });
                let local = local_node.clone();
                let stop_session = stop.clone();
                tokio::spawn(async move {
                    let drive = tcp::drive(
                        stream,
                        DriveArgs {
                            role: Role::Passive,
                            local_node: local,
                            tls: tls_side,
                            bundles: bundle_rx,
                            bundles_tx: bundle_tx,
                            inbound: inbound_bridge(events_session.clone()),
                            up: up_tx,
                            stop: stop_session,
                        },
                    );
                    tokio::pin!(drive);
                    let mut announced = None;
                    loop {
                        tokio::select! {
                            result = &mut drive => {
                                if let Some(node) = announced.take() {
                                    let _ = events_session.send(NetEvent::Down { node, generation: session_generation });
                                }
                                let _ = result;
                                break;
                            }
                            up = up_rx.recv() => {
                                if let Some((text, tx)) = up
                                    && let Ok(node) = parse_node_id(&text)
                                {
                                    announced = Some(node.clone());
                                    let _ = events_session.send(NetEvent::Up {
                                        node,
                                        tx,
                                        generation: session_generation,
                                    });
                                }
                            }
                        }
                    }
                });
            }
        }
    }
}

fn inbound_bridge(events: mpsc::UnboundedSender<NetEvent>) -> mpsc::UnboundedSender<Vec<u8>> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if events.send(NetEvent::Bundle(bytes)).is_err() {
                break;
            }
        }
    });
    tx
}

async fn run_ltp(
    sock: Arc<UdpSocket>,
    engine_id: u64,
    segment_payload: usize,
    mut outbound: mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>,
    events: mpsc::UnboundedSender<NetEvent>,
    mut stop: watch::Receiver<bool>,
) {
    let mut engine = LtpEngine::new(engine_id, segment_payload);
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = stop.changed() => {
                if *stop.borrow() { break; }
            }
            received = sock.recv_from(&mut buf) => {
                let Ok((n, src)) = received else { continue };
                let Ok(segment) = Segment::decode(&buf[..n]) else { continue };
                emit_ltp(&sock, src, engine.handle(segment), &events).await;
            }
            next = outbound.recv() => {
                let Some((addr, block)) = next else { break };
                let segments = engine.send_block(block);
                for segment in segments {
                    let _ = sock.send_to(&segment.encode(), addr).await;
                }
            }
        }
    }
}

async fn emit_ltp(
    sock: &UdpSocket,
    src: SocketAddr,
    out: interplanetary_ltp::HandleOut,
    events: &mpsc::UnboundedSender<NetEvent>,
) {
    for segment in out.responses {
        let _ = sock.send_to(&segment.encode(), src).await;
    }
    for block in out.blocks {
        let _ = events.send(NetEvent::Bundle(block));
    }
}

fn parse_node_id(text: &str) -> Result<NodeId> {
    if let Some(rest) = text.strip_prefix("ipn:") {
        let parts: Vec<&str> = rest.split('.').collect();
        let number = |text: &str| {
            text.parse::<u64>()
                .map_err(|_| Error::malformed_input(format!("node id `{text}`")))
        };
        match parts.as_slice() {
            [node] => Ok(NodeId::ipn(0, number(node)?)),
            [allocator, node] => Ok(NodeId::ipn(number(allocator)?, number(node)?)),
            _ => Err(Error::malformed_input(format!("node id `{text}`"))),
        }
    } else if let Some(name) = text.strip_prefix("dtn:") {
        Ok(NodeId::dtn(name))
    } else {
        Err(Error::malformed_input(format!("node id `{text}`")))
    }
}
