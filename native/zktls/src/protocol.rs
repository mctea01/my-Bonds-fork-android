use crate::{Error, Result};
use futures::{AsyncReadExt as _, AsyncWriteExt as _};
use std::{future::IntoFuture, ops::Range};
use tlsn::{
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{CertBinding, HandshakeData, ServerName},
    prover::{state, Prover},
    transcript::{Direction, TranscriptCommitConfig, TranscriptCommitmentKind},
    verifier::VerifierCommitStart,
    webpki::{RootCertStore, ServerCertVerifier},
    Session,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;

pub struct Request {
    pub host: String,
    pub port: u16,
    pub request: Vec<u8>,
    pub max_sent: u32,
    pub max_recv: u32,
    pub mode: String,
}
#[derive(Clone)]
pub struct Transcript {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub server_name: String,
    pub cert_chain_der: Vec<Vec<u8>>,
    pub time: u64,
    pub cipher_suite: String,
}
pub struct Reveal {
    pub sent: Vec<Range<usize>>,
    pub received: Vec<Range<usize>>,
    pub commit_sha256: Vec<Range<usize>>,
}
pub struct Commitment {
    pub range: Range<usize>,
    pub digest: Vec<u8>,
}
pub struct Verified {
    /// Interactive verification and supplemental certificate check, excluding TLS setup.
    pub verify_ms: u64,
    pub server_name: String,
    pub cert_chain_der: Vec<Vec<u8>>,
    pub time: u64,
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub sent_mask: Vec<Range<usize>>,
    pub received_mask: Vec<Range<usize>>,
    pub commitments: Vec<Commitment>,
}

fn checked<T, E>(r: std::result::Result<T, E>) -> Result<T> {
    r.map_err(|_| Error::Protocol)
}

pub fn limits(host: &str, port: u16, sent: u32, received: u32, mode: &str) -> Result<()> {
    if port == 0
        || sent == 0
        || sent > 4096
        || received == 0
        || received > 262144
        || !matches!(mode, "proxy" | "mpc")
        || host.len() > 253
    {
        return Err(Error::Input);
    }
    tlsn::connection::DnsName::try_from(host).map_err(|_| Error::Input)?;
    Ok(())
}

// This gate is applied before the reveal chooser can disclose any request byte.
fn permitted_request(request: &Request) -> Result<Vec<Range<usize>>> {
    if request.request.len() > request.max_sent as usize {
        return Err(Error::Limit);
    }
    let data = &request.request;
    let head_end = data
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or(Error::Input)?;
    let head = std::str::from_utf8(&data[..head_end + 2]).map_err(|_| Error::Input)?;
    let mut lines = head.split("\r\n");
    let line = lines.next().ok_or(Error::Input)?;
    let pieces: Vec<_> = line.split(' ').collect();
    if pieces.len() != 3
        || pieces[0].is_empty()
        || !pieces[0].bytes().all(|b| b.is_ascii_uppercase())
        || !pieces[1].starts_with('/')
        || pieces[1].contains('#')
        || pieces[2] != "HTTP/1.1"
    {
        return Err(Error::Input);
    }
    let path_end = pieces[0].len() + 1 + pieces[1].find('?').unwrap_or(pieces[1].len());
    let mut permitted = vec![0..path_end];
    let (mut host, mut identity, mut close) = (false, false, false);
    let mut offset = line.len() + 2;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(Error::Input)?;
        if name.is_empty()
            || name
                .bytes()
                .any(|b| !b.is_ascii_alphanumeric() && b != b'-')
        {
            return Err(Error::Input);
        }
        match name.to_ascii_lowercase().as_str() {
            "host" => {
                if host
                    || !(value.trim() == request.host
                        || value.trim() == format!("{}:{}", request.host, request.port))
                {
                    return Err(Error::Input);
                }
                host = true;
                permitted.push(offset..offset + line.len() + 2);
            }
            "accept-encoding" => {
                if identity || value.trim() != "identity" {
                    return Err(Error::Input);
                }
                identity = true;
            }
            "connection" => {
                if close || !value.trim().eq_ignore_ascii_case("close") {
                    return Err(Error::Input);
                }
                close = true;
            }
            "transfer-encoding" => return Err(Error::Input),
            _ => (),
        }
        offset += line.len() + 2;
    }
    if !host || !identity || !close {
        return Err(Error::Input);
    }
    Ok(permitted)
}

fn ranges(ranges: &[Range<usize>], len: usize) -> Result<()> {
    if ranges.len() > 1024 || ranges.iter().any(|r| r.start >= r.end || r.end > len) {
        return Err(Error::Input);
    }
    Ok(())
}

async fn exchange<S: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static>(
    mut io: tlsn::prover::TlsConnection,
    prover: Prover<state::Connected<S>>,
    request: &[u8],
    max_recv: usize,
) -> Result<Prover<state::Committed>> {
    let send = async {
        checked(io.write_all(request).await)?;
        checked(io.flush().await)?;
        let mut bytes = vec![0; 4096];
        let mut count = 0;
        loop {
            let n = checked(io.read(&mut bytes).await)?;
            if n == 0 {
                break;
            }
            count += n;
            if count > max_recv {
                return Err(Error::Limit);
            }
        }
        checked(io.close().await)
    };
    let (_, prover) = tokio::try_join!(send, async { checked(prover.into_future().await) })?;
    Ok(prover)
}

pub async fn prove<S, F>(
    wire: S,
    request: Request,
    hash: [u8; 32],
    public: [u8; 32],
    roots: RootCertStore,
    choose: F,
) -> Result<Transcript>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: FnOnce(&Transcript) -> Result<Reveal>,
{
    limits(
        &request.host,
        request.port,
        request.max_sent,
        request.max_recv,
        &request.mode,
    )?;
    let permitted = permitted_request(&request)?;
    let mut secure = crate::noise::connect(wire, hash, public, true).await?;
    let stream = std::mem::replace(&mut secure.io, tokio::io::duplex(1).0);
    let (stream, frames) = session_frames(stream);
    let (driver, mut handle) = Session::new(stream.compat()).split();
    let mut driver = tokio::spawn(driver);
    let mut driver_ended = false;
    let run = async {
        let config = checked(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(checked(request.host.as_str().try_into())?))
                .root_store(roots)
                .build(),
        )?;
        let prover = checked(handle.new_prover(checked(ProverConfig::builder().build())?))?;
        let mut prover = if request.mode == "proxy" {
            let prover = checked(
                prover
                    .commit(checked(
                        ProxyTlsConfig::builder()
                            .server_name(checked(request.host.as_str().try_into())?)
                            .build(),
                    )?)
                    .await,
            )?;
            let (io, prover) = checked(prover.connect(config))?;
            exchange(io, prover, &request.request, request.max_recv as usize).await?
        } else {
            let prover = checked(
                prover
                    .commit(checked(
                        MpcTlsConfig::builder()
                            .max_sent_data(request.max_sent as usize)
                            .max_recv_data(request.max_recv as usize)
                            .build(),
                    )?)
                    .await,
            )?;
            let target = checked(
                tokio::net::TcpStream::connect((request.host.as_str(), request.port)).await,
            )?;
            let (io, prover) = checked(prover.connect(config, target.compat()))?;
            exchange(io, prover, &request.request, request.max_recv as usize).await?
        };
        let tls = prover.tls_transcript();
        let metadata = HandshakeData {
            certs: tls.server_cert_chain().ok_or(Error::Protocol)?.to_vec(),
            sig: tls.server_signature().ok_or(Error::Protocol)?.clone(),
            binding: tls.certificate_binding().clone(),
        };
        let output = Transcript {
            sent: prover.transcript().sent().to_vec(),
            received: prover.transcript().received().to_vec(),
            server_name: request.host,
            cert_chain_der: metadata.certs.iter().map(|c| c.0.clone()).collect(),
            time: tls.time(),
            cipher_suite: match metadata.sig.alg {
                tlsn::connection::SignatureAlgorithm::ECDSA_NISTP256_SHA256
                | tlsn::connection::SignatureAlgorithm::ECDSA_NISTP256_SHA384
                | tlsn::connection::SignatureAlgorithm::ECDSA_NISTP384_SHA256
                | tlsn::connection::SignatureAlgorithm::ECDSA_NISTP384_SHA384 => {
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
                }
                tlsn::connection::SignatureAlgorithm::ED25519 => return Err(Error::Protocol),
                _ => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            }
            .into(),
        };
        let reveal = choose(&output)?;
        ranges(&reveal.sent, output.sent.len())?;
        ranges(&reveal.received, output.received.len())?;
        ranges(&reveal.commit_sha256, output.received.len())?;
        if reveal.sent.iter().any(|r| {
            !permitted
                .iter()
                .any(|p| p.start <= r.start && r.end <= p.end)
        }) {
            return Err(Error::Input);
        }
        let mut builder = ProveConfig::builder(prover.transcript());
        builder.server_identity();
        for r in reveal.sent {
            checked(builder.reveal_sent(&r))?;
        }
        for r in reveal.received {
            checked(builder.reveal_recv(&r))?;
        }
        if !reveal.commit_sha256.is_empty() {
            let mut commits = TranscriptCommitConfig::builder(prover.transcript());
            for r in reveal.commit_sha256 {
                checked(commits.commit_with_kind(
                    r,
                    Direction::Received,
                    TranscriptCommitmentKind::Hash {
                        alg: tlsn::hash::HashAlgId::SHA256,
                    },
                ))?;
            }
            builder.transcript_commit(checked(commits.build())?);
        }
        checked(prover.prove(&checked(builder.build())?).await)?;
        checked(prover.close().await)?;
        Ok((output, metadata))
    };
    let run = while_session_runs(run, &mut driver, &mut driver_ended).await;
    if run.is_ok() {
        checked(frames.ready.send(()))?;
        checked(frames.peer_ready.await)??;
    }
    handle.close();
    if run.is_err() {
        if !driver_ended {
            driver.abort();
            let _ = driver.await;
        }
        return run.map(|x| x.0);
    }
    let (output, metadata) = run?;
    drop(checked(checked(driver.await)?)?);
    let mut stream = checked(frames.pump.await)??.compat();
    let metadata = checked(bincode::serialize(&metadata))?;
    if metadata.len() > 65536 {
        return Err(Error::Limit);
    }
    checked(
        stream
            .write_all(&(metadata.len() as u32).to_be_bytes())
            .await,
    )?;
    checked(stream.write_all(&metadata).await)?;
    checked(stream.flush().await)?;
    secure.io = stream.into_inner();
    secure.finish().await?;
    Ok(output)
}

pub async fn verify<S>(
    wire: S,
    host: String,
    port: u16,
    max_sent: u32,
    max_recv: u32,
    mode: String,
    hash: [u8; 32],
    private: [u8; 32],
    roots: RootCertStore,
) -> Result<Verified>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use bincode::Options;
    limits(&host, port, max_sent, max_recv, &mode)?;
    let mut secure = crate::noise::connect(wire, hash, private, false).await?;
    let stream = std::mem::replace(&mut secure.io, tokio::io::duplex(1).0);
    let (stream, frames) = session_frames(stream);
    let (driver, mut handle) = Session::new(stream.compat()).split();
    let mut driver = tokio::spawn(driver);
    let mut driver_ended = false;
    let run = async {
        let verifier = checked(handle.new_verifier(checked(
            VerifierConfig::builder().root_store(roots.clone()).build(),
        )?))?;
        let verifier = match checked(verifier.commit().await)? {
            VerifierCommitStart::Proxy(v) => {
                if mode != "proxy" || v.config().server_name().as_str() != host {
                    return Err(Error::Input);
                }
                let target = checked(tokio::net::TcpStream::connect((host.as_str(), port)).await)?;
                let target = LimitedIo {
                    inner: target,
                    read_left: max_recv as usize * 64 + 65536,
                    write_left: max_sent as usize * 64 + 65536,
                };
                checked(checked(v.accept().await)?.run(target.compat()).await)?
            }
            VerifierCommitStart::Mpc(v) => {
                if mode != "mpc"
                    || v.config().max_sent_data() > max_sent as usize
                    || v.config().max_recv_data() > max_recv as usize
                {
                    return Err(Error::Limit);
                }
                checked(checked(v.accept().await)?.run().await)?
            }
        };
        let time = verifier.tls_transcript().time();
        let binding = verifier.tls_transcript().certificate_binding().clone();
        let verifier = checked(verifier.verify().await)?;
        if !verifier.request().server_identity() {
            return Err(Error::Protocol);
        }
        let verify_started = std::time::Instant::now();
        let (output, verifier) = checked(verifier.accept().await)?;
        let verify_ms = verify_started.elapsed().as_millis() as u64;
        checked(verifier.close().await)?;
        let name = output.server_name.ok_or(Error::Protocol)?;
        let ServerName::Dns(ref dns) = name;
        if dns.as_str() != host {
            return Err(Error::Protocol);
        }
        let mut transcript = output.transcript.ok_or(Error::Protocol)?;
        if transcript.len_sent() > max_sent as usize
            || transcript.len_received() > max_recv as usize
        {
            return Err(Error::Limit);
        }
        transcript.set_unauthed(0);
        let mut commitments = Vec::new();
        for commitment in output.transcript_commitments {
            let tlsn::transcript::TranscriptCommitment::Hash(c) = commitment else {
                return Err(Error::Protocol);
            };
            let ranges: Vec<_> = c.idx.iter().collect();
            if c.direction != Direction::Received
                || c.hash.alg != tlsn::hash::HashAlgId::SHA256
                || ranges.len() != 1
            {
                return Err(Error::Protocol);
            }
            commitments.push(Commitment {
                range: ranges[0].clone(),
                digest: c.hash.value.as_bytes().to_vec(),
            });
        }
        Ok((
            Verified {
                verify_ms,
                server_name: host,
                cert_chain_der: Vec::new(),
                time,
                sent: transcript.sent_unsafe().to_vec(),
                received: transcript.received_unsafe().to_vec(),
                sent_mask: transcript.sent_authed().iter().collect(),
                received_mask: transcript.received_authed().iter().collect(),
                commitments,
            },
            name,
            binding,
        ))
    };
    let run = while_session_runs(run, &mut driver, &mut driver_ended).await;
    if run.is_ok() {
        checked(frames.ready.send(()))?;
        checked(frames.peer_ready.await)??;
    }
    handle.close();
    if run.is_err() {
        if !driver_ended {
            driver.abort();
            let _ = driver.await;
        }
        return run.map(|x| x.0);
    }
    let (mut output, name, binding) = run?;
    drop(checked(checked(driver.await)?)?);
    let mut stream = checked(frames.pump.await)??.compat();
    // The upstream verifier does not return the certificate chain in MPC mode.
    // Bind this supplemental chain to the authenticated session's ephemeral key,
    // hostname, time and trust roots instead of trusting peer-supplied metadata.
    let mut length = [0; 4];
    checked(stream.read_exact(&mut length).await)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 65536 {
        return Err(Error::Limit);
    }
    let mut metadata = vec![0; length];
    checked(stream.read_exact(&mut metadata).await)?;
    let metadata: HandshakeData = checked(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(65536)
            .reject_trailing_bytes()
            .deserialize(&metadata),
    )?;
    let CertBinding::V1_2(binding) = binding else {
        return Err(Error::Protocol);
    };
    let CertBinding::V1_2(ref supplied) = metadata.binding else {
        return Err(Error::Protocol);
    };
    if supplied.client_random != binding.client_random
        || supplied.server_random != binding.server_random
    {
        return Err(Error::Protocol);
    }
    let metadata_started = std::time::Instant::now();
    checked(metadata.verify(
        &checked(ServerCertVerifier::new(&roots))?,
        output.time,
        &binding.server_ephemeral_key,
        &name,
    ))?;
    output.verify_ms += metadata_started.elapsed().as_millis() as u64;
    output.cert_chain_der = metadata.certs.into_iter().map(|c| c.0).collect();
    secure.io = stream.into_inner();
    secure.finish().await?;
    Ok(output)
}

struct LimitedIo<S> {
    inner: S,
    read_left: usize,
    write_left: usize,
}
impl<S: AsyncRead + Unpin> AsyncRead for LimitedIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > self.read_left {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::InvalidData.into()));
        }
        self.read_left -= n;
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for LimitedIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if buf.len() > self.write_left {
            return std::task::Poll::Ready(Err(std::io::ErrorKind::InvalidData.into()));
        }
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = result {
            self.write_left -= n;
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Frame the TLSNotary segment separately from the supplemental certificate
// message. A mux may read ahead, so an unframed suffix can be swallowed by its
// internal buffer. A zero-length segment frame gives it a real EOF boundary.
struct SessionFrames {
    pump: tokio::task::JoinHandle<Result<tokio::io::DuplexStream>>,
    ready: tokio::sync::oneshot::Sender<()>,
    peer_ready: tokio::sync::oneshot::Receiver<Result<()>>,
}
fn session_frames(stream: tokio::io::DuplexStream) -> (tokio::io::DuplexStream, SessionFrames) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (io, bridge) = tokio::io::duplex(32768);
    let (ready, mut ready_rx) = tokio::sync::oneshot::channel();
    let (peer_ready_tx, peer_ready) = tokio::sync::oneshot::channel();
    let pump = tokio::spawn(async move {
        let (mut input, mut output) = tokio::io::split(stream);
        let (mut plain_in, mut plain_out) = tokio::io::split(bridge);
        let send = async {
            let mut buffer = vec![0; 16384];
            let mut announced = false;
            loop {
                let n = tokio::select! {
                    result = &mut ready_rx, if !announced => {
                        checked(result)?;
                        checked(output.write_u32(u32::MAX).await)?;
                        checked(output.flush().await)?;
                        announced = true;
                        continue;
                    }
                    result = plain_in.read(&mut buffer) => checked(result)?,
                };
                checked(output.write_u32(n as u32).await)?;
                checked(output.write_all(&buffer[..n]).await)?;
                checked(output.flush().await)?;
                if n == 0 {
                    return Ok::<(), Error>(());
                }
            }
        };
        let receive = async {
            let mut peer_ready_tx = Some(peer_ready_tx);
            let mut buffer = vec![0; 16384];
            loop {
                let n = checked(input.read_u32().await)? as usize;
                if n == u32::MAX as usize {
                    let ready = peer_ready_tx.take().ok_or(Error::Protocol)?;
                    checked(ready.send(Ok(())))?;
                    continue;
                }
                if n > buffer.len() {
                    return Err(Error::Limit);
                }
                if n == 0 {
                    checked(plain_out.shutdown().await)?;
                    return Ok::<(), Error>(());
                }
                checked(input.read_exact(&mut buffer[..n]).await)?;
                checked(plain_out.write_all(&buffer[..n]).await)?;
            }
        };
        tokio::try_join!(send, receive)?;
        Ok(input.unsplit(output))
    });
    (
        io,
        SessionFrames {
            pump,
            ready,
            peer_ready,
        },
    )
}

/// Runs a session operation while the session driver lives. When the peer fails it closes the connection, which
/// ends the driver; an operation still waiting on the session would otherwise wait forever, so it fails instead.
async fn while_session_runs<T, O>(
    run: impl std::future::Future<Output = Result<T>>,
    driver: &mut tokio::task::JoinHandle<O>,
    ended: &mut bool,
) -> Result<T> {
    tokio::pin!(run);
    tokio::select! {
        biased;
        result = &mut run => result,
        _ = &mut *driver => {
            *ended = true;
            Err(Error::Channel)
        }
    }
}

/// Production roots; test callers supply their own explicit root store.
pub fn mozilla_roots() -> RootCertStore {
    RootCertStore::mozilla()
}

/// The production roots plus roots the caller itself chose (a test CA or a root the user imported). The peer never
/// supplies roots: each side passes its own.
pub fn roots_with(extra: Vec<Vec<u8>>) -> RootCertStore {
    let mut roots = mozilla_roots();
    roots
        .roots
        .extend(extra.into_iter().map(tlsn::webpki::CertificateDer));
    roots
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request { host:"example.com".into(),port:443,max_sent:4096,max_recv:1024,mode:"proxy".into(),
        request:b"GET /check?private=x HTTP/1.1\r\nHost: example.com\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n".to_vec() }
    }
    #[test]
    fn request_reveal_excludes_query_and_credentials() {
        let r = request();
        let allowed = permitted_request(&r).unwrap();
        assert!(allowed[0] == (0..10));
        let query = r.request.iter().position(|&b| b == b'?').unwrap();
        assert!(!allowed.iter().any(|r| r.contains(&query)));
        assert!(limits("example.com", 443, 4097, 1024, "proxy").is_err());
        assert!(limits("example.com", 443, 4096, 262145, "proxy").is_err());
        assert!(limits("example.com", 443, 4096, 1024, "unknown").is_err());
    }
    #[test]
    fn rejects_ambiguous_http_headers() {
        for change in [
            "Host: other.example",
            "Host: example.com\r\nHost: example.com",
            "Host: example.com\r\nTransfer-Encoding: chunked",
        ] {
            let mut r = request();
            r.request = String::from_utf8(r.request)
                .unwrap()
                .replace("Host: example.com", change)
                .into_bytes();
            assert!(permitted_request(&r).is_err());
        }
    }
}
