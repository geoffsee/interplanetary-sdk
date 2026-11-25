//! TCPCLv4 session on a real TCP socket.
//!
//! Contact headers are exchanged in the clear. When TLS is configured, both
//! headers carry `CAN_TLS` and the handshake runs before `SESS_INIT`
//! (RFC 9174 §4.4.3).

use crate::tls::{self, TlsMaterial};
use interplanetary_tcpcl::{
    ContactHeader, Message, Role, SessionConfig, SessionState, TcpclSession, term_reason,
};
use interplanetary_types::{Error, Result};
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio_rustls::client::TlsStream as ClientTls;

pub(crate) trait ByteIo: AsyncRead + AsyncWrite + Send {}
impl<T> ByteIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(crate) type IoBox = Pin<Box<dyn ByteIo + Unpin>>;

pub(crate) enum TlsSide {
    Client { material: TlsMaterial, name: String },
    Server { material: TlsMaterial },
}

/// Drive one TCPCL session until the peer closes or `stop` is set.
///
/// `bundles` receives encoded bundles to transfer. Completed incoming
/// transfers are sent on `inbound`. On establishment the peer node id and a
/// clone of `bundles_tx` are reported through `up`.
pub(crate) struct DriveArgs {
    pub(crate) role: Role,
    pub(crate) local_node: String,
    pub(crate) tls: Option<TlsSide>,
    pub(crate) bundles: mpsc::UnboundedReceiver<Vec<u8>>,
    pub(crate) bundles_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub(crate) inbound: mpsc::UnboundedSender<Vec<u8>>,
    pub(crate) up: mpsc::UnboundedSender<(String, mpsc::UnboundedSender<Vec<u8>>)>,
    pub(crate) stop: watch::Receiver<bool>,
}

pub(crate) async fn drive(mut stream: TcpStream, mut args: DriveArgs) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let now = unix_ms();
    let mut session = TcpclSession::new_at_time(
        SessionConfig {
            role: args.role,
            node_id: args.local_node.clone(),
            ..SessionConfig::default()
        },
        now,
    )?;
    let require_tls = args.tls.is_some();
    exchange_contact(&mut session, &mut stream, args.role, require_tls).await?;

    let (peer_certs, mut io) = upgrade(stream, args.tls.take()).await?;
    let mut buf = Vec::new();
    let peer_id = exchange_init(&mut session, &mut io, &mut buf, args.role).await?;
    if require_tls && !tls::peer_authenticates(&peer_certs, &peer_id) {
        let term = session.send_session_term(term_reason::CONTACT_FAILURE, None)?;
        write_msg(&mut io, &mut session, &term).await?;
        return Err(Error::security_failure(format!(
            "peer certificate does not name TCPCL node id {peer_id}"
        )));
    }
    let _ = args.up.send((peer_id, args.bundles_tx.clone()));

    let mut scratch = vec![0u8; 8192];
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(1));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            changed = args.stop.changed() => {
                if changed.is_err() || *args.stop.borrow() {
                    close_session(&mut session, &mut io).await?;
                    break;
                }
            }
            incoming = args.bundles.recv() => {
                let Some(bytes) = incoming else { break };
                let id = session.start_transfer(bytes)?;
                let segments = session.create_segments_at(id, 65535, unix_ms())?;
                for segment in segments {
                    write_msg(&mut io, &mut session, &segment).await?;
                }
            }
            read = io.read(&mut scratch) => {
                let n = read.map_err(|err| Error::transfer_failed(format!("TCP read: {err}")))?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&scratch[..n]);
                while let Some((message, consumed)) = Message::decode_frame(&buf)
                    .map_err(Error::malformed_input)?
                {
                    buf.drain(..consumed);
                    if !handle_message(&mut session, &mut io, &args.inbound, message).await? {
                        let _ = io.shutdown().await;
                        return Ok(());
                    }
                }
            }
            _ = keepalive.tick() => {
                if let Some(message) = session.poll(unix_ms()) {
                    write_msg(&mut io, &mut session, &message).await?;
                    if matches!(message, Message::SessionTerm { .. }) {
                        let _ = io.shutdown().await;
                        return Ok(());
                    }
                }
                if session.state() == SessionState::Terminated {
                    let _ = io.shutdown().await;
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

async fn exchange_contact(
    session: &mut TcpclSession,
    stream: &mut TcpStream,
    role: Role,
    require_tls: bool,
) -> Result<()> {
    let flags = if require_tls {
        ContactHeader::FLAG_CAN_TLS
    } else {
        0
    };
    match role {
        Role::Active => {
            let _ = session.send_contact_header()?;
            write_all(stream, &ContactHeader::with_flags(flags).encode()).await?;
            let peer = read_exact(stream, 6).await?;
            let header = ContactHeader::decode(&peer).map_err(Error::malformed_input)?;
            session.process_contact_header(&header)?;
            if require_tls && header.flags & ContactHeader::FLAG_CAN_TLS == 0 {
                return Err(Error::protocol_violation(
                    "peer contact header did not offer TLS",
                ));
            }
        }
        Role::Passive => {
            let peer = read_exact(stream, 6).await?;
            let header = ContactHeader::decode(&peer).map_err(Error::malformed_input)?;
            session.process_contact_header(&header)?;
            if require_tls && header.flags & ContactHeader::FLAG_CAN_TLS == 0 {
                let _ = session.send_contact_header()?;
                write_all(stream, &ContactHeader::with_flags(flags).encode()).await?;
                return Err(Error::protocol_violation(
                    "peer contact header did not offer TLS",
                ));
            }
            let _ = session.send_contact_header()?;
            write_all(stream, &ContactHeader::with_flags(flags).encode()).await?;
        }
    }
    Ok(())
}

async fn upgrade(stream: TcpStream, tls: Option<TlsSide>) -> Result<(Vec<Vec<u8>>, IoBox)> {
    match tls {
        None => Ok((Vec::new(), Box::pin(stream))),
        Some(TlsSide::Client { material, name }) => {
            let connector = tokio_rustls::TlsConnector::from(material.client);
            let name = tls::server_name(&name)?;
            let tls_stream = connector
                .connect(name, stream)
                .await
                .map_err(|err| Error::security_failure(format!("TLS handshake: {err}")))?;
            let certs = peer_ders_client(&tls_stream);
            Ok((certs, Box::pin(tls_stream)))
        }
        Some(TlsSide::Server { material }) => {
            let tls_stream = material
                .server
                .accept(stream)
                .await
                .map_err(|err| Error::security_failure(format!("TLS handshake: {err}")))?;
            let certs = peer_ders_server(&tls_stream);
            Ok((certs, Box::pin(tls_stream)))
        }
    }
}

fn peer_ders_client(stream: &ClientTls<TcpStream>) -> Vec<Vec<u8>> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .map(ders_from)
        .unwrap_or_default()
}

fn peer_ders_server(stream: &tokio_rustls::server::TlsStream<TcpStream>) -> Vec<Vec<u8>> {
    stream
        .get_ref()
        .1
        .peer_certificates()
        .map(ders_from)
        .unwrap_or_default()
}

fn ders_from(certs: &[rustls::pki_types::CertificateDer<'_>]) -> Vec<Vec<u8>> {
    certs.iter().map(|cert| cert.as_ref().to_vec()).collect()
}

async fn exchange_init(
    session: &mut TcpclSession,
    io: &mut IoBox,
    buf: &mut Vec<u8>,
    role: Role,
) -> Result<String> {
    // RFC 9174 §4.4.3: the active entity sends SESS_INIT first.
    // The passive entity must emit its own SESS_INIT before processing the
    // peer's, because processing moves the session to Established.
    let peer = if role == Role::Active {
        let local = session.send_session_init()?;
        write_msg(io, session, &local).await?;
        read_message(io, buf).await?
    } else {
        let peer = read_message(io, buf).await?;
        let local = session.send_session_init()?;
        write_msg(io, session, &local).await?;
        peer
    };
    let node_id = match &peer {
        Message::SessionInit { node_id, .. } => node_id.clone(),
        _ => {
            return Err(Error::protocol_violation(
                "expected SESS_INIT from the peer",
            ));
        }
    };
    session.process_session_init(&peer)?;
    if session.state() != SessionState::Established {
        return Err(Error::protocol_violation("TCPCL session did not establish"));
    }
    Ok(node_id)
}

async fn handle_message(
    session: &mut TcpclSession,
    io: &mut IoBox,
    inbound: &mpsc::UnboundedSender<Vec<u8>>,
    message: Message,
) -> Result<bool> {
    session.record_receive(unix_ms());
    match &message {
        Message::TransferSegment {
            transfer_id, flags, ..
        } => {
            let id = *transfer_id;
            let ended = flags & interplanetary_tcpcl::transfer_flags::END != 0;
            if let Some(ack) = session.process_segment(&message)? {
                write_msg(io, session, &ack).await?;
            }
            if ended && let Some(data) = session.get_received_transfer(id) {
                let _ = inbound.send(data.to_vec());
            }
            Ok(true)
        }
        Message::TransferAck {
            transfer_id,
            acked_length,
            ..
        } => {
            session.process_ack(*transfer_id, *acked_length)?;
            Ok(true)
        }
        Message::Keepalive => Ok(true),
        Message::SessionInit { .. } => Err(Error::protocol_violation(
            "unexpected SESS_INIT after the handshake",
        )),
        Message::SessionTerm { .. } => {
            if let Some(reply) = session.process_session_term(&message)? {
                write_msg(io, session, &reply).await?;
            }
            Ok(false)
        }
        Message::TransferRefuse { .. } => Err(Error::transfer_failed("peer refused transfer")),
        Message::MessageReject { .. } => Err(Error::protocol_violation("peer rejected a message")),
    }
}

async fn close_session(session: &mut TcpclSession, io: &mut IoBox) -> Result<()> {
    if session.state() == SessionState::Established {
        let term = session.send_session_term(term_reason::UNKNOWN, None)?;
        write_msg(io, session, &term).await?;
    }
    let _ = io.shutdown().await;
    Ok(())
}

async fn read_message(io: &mut IoBox, buf: &mut Vec<u8>) -> Result<Message> {
    let mut scratch = vec![0u8; 4096];
    loop {
        if let Some((message, consumed)) =
            Message::decode_frame(buf).map_err(Error::malformed_input)?
        {
            buf.drain(..consumed);
            return Ok(message);
        }
        let n = io
            .read(&mut scratch)
            .await
            .map_err(|err| Error::transfer_failed(format!("TCP read: {err}")))?;
        if n == 0 {
            return Err(Error::transfer_failed("TCP connection closed"));
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

async fn write_msg(io: &mut IoBox, session: &mut TcpclSession, message: &Message) -> Result<()> {
    write_all(io, &encode_wire(message)).await?;
    session.record_send(unix_ms());
    Ok(())
}

fn encode_wire(message: &Message) -> Vec<u8> {
    match message {
        Message::SessionTerm {
            flags, reason_code, ..
        } => vec![Message::TYPE_SESS_TERM, *flags, *reason_code],
        other => other.encode(),
    }
}

async fn write_all(io: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
    io.write_all(bytes)
        .await
        .map_err(|err| Error::transfer_failed(format!("TCP write: {err}")))
}

async fn read_exact(io: &mut (impl AsyncRead + Unpin), len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf)
        .await
        .map_err(|err| Error::transfer_failed(format!("TCP read: {err}")))?;
    Ok(buf)
}

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| u64::try_from(dur.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
