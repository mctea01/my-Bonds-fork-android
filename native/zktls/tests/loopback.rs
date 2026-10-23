use std::{sync::Arc, time::Duration};
use tlsn::webpki::{CertificateDer, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zktls::protocol::{self, Request, Reveal};

async fn loopback(mode: &str, chunked: bool, body_size: usize) -> (u128, usize, usize, u64) {
    let start_time = std::time::Instant::now();
    // Generated per run; no production certificate, private key or response is persisted.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key.into())
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(socket)
            .await
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0; 1];
            tls.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
            assert!(request.len() <= 4096);
        }
        let mut body = vec![b'x'; body_size];
        body[..9].copy_from_slice(b"status=OK");
        let response = if chunked {
            let mut response =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    .to_vec();
            for part in body.chunks(127) {
                response.extend_from_slice(format!("{:X}\r\n", part.len()).as_bytes());
                response.extend_from_slice(part);
                response.extend_from_slice(b"\r\n");
            }
            response.extend_from_slice(b"0\r\n\r\n");
            response
        } else {
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            response
        };
        tls.write_all(&response).await.unwrap();
        tls.shutdown().await.unwrap();
    });
    let roots = RootCertStore {
        roots: vec![CertificateDer(der.to_vec())],
    };
    let noise = snow::Builder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse().unwrap())
        .generate_keypair()
        .unwrap();
    let (a, b) = tokio::io::duplex(65536);
    let prover_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let verifier_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let a = Counted(a, prover_bytes.clone());
    let b = Counted(b, verifier_bytes.clone());
    let max_recv = (body_size + 1024) as u32;
    let request=Request {host:"localhost".into(),port,request:format!("GET /check?secret=synthetic HTTP/1.1\r\nHost: localhost:{port}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").into_bytes(),max_sent:4096,max_recv,mode:mode.into()};
    let prover = protocol::prove(
        a,
        request,
        [7; 32],
        noise.public.try_into().unwrap(),
        roots.clone(),
        |transcript| {
            let start = transcript
                .received
                .windows(9)
                .position(|w| w == b"status=OK")
                .unwrap();
            let host = transcript
                .sent
                .windows(6)
                .position(|w| w == b"Host: ")
                .unwrap();
            let host_end = host
                + transcript.sent[host..]
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .unwrap()
                + 2;
            Ok(Reveal {
                sent: vec![0..10, host..host_end],
                received: vec![start..start + 9],
                commit_sha256: vec![start..start + 9],
            })
        },
    );
    let verifier = protocol::verify(
        b,
        "localhost".into(),
        port,
        4096,
        max_recv,
        mode.into(),
        [7; 32],
        noise.private.try_into().unwrap(),
        roots,
    );
    let (prover, verifier) = tokio::time::timeout(Duration::from_secs(180), async {
        tokio::try_join!(prover, verifier)
    })
    .await
    .unwrap()
    .unwrap();
    assert!(verifier.sent[..10] == prover.sent[..10]);
    for (i, &byte) in verifier.sent.iter().enumerate() {
        if !verifier.sent_mask.iter().any(|range| range.contains(&i)) {
            assert!(byte == 0);
        }
    }
    let query = prover.sent.iter().position(|&b| b == b'?').unwrap();
    assert!(verifier.sent[query] == 0);
    assert!(verifier.commitments.len() == 1);
    assert!(verifier.commitments[0].digest.len() == 32);
    let r = &verifier.received_mask[0];
    assert!(&verifier.received[r.clone()] == b"status=OK");
    assert!(verifier.received[..r.start].iter().all(|&b| b == 0));
    assert!(verifier.received[r.end..].iter().all(|&b| b == 0));
    assert!(!verifier.cert_chain_der.is_empty());
    server.await.unwrap();
    (
        start_time.elapsed().as_millis(),
        prover_bytes.load(std::sync::atomic::Ordering::Relaxed),
        verifier_bytes.load(std::sync::atomic::Ordering::Relaxed),
        verifier.verify_ms,
    )
}

#[tokio::test]
async fn proxy_loopback() {
    loopback("proxy", false, 24).await;
}
#[tokio::test]
async fn proxy_chunked() {
    loopback("proxy", true, 1024).await;
}
#[tokio::test]
async fn mpc_loopback() {
    loopback("mpc", false, 24).await;
}

struct Counted(tokio::io::DuplexStream, Arc<std::sync::atomic::AtomicUsize>);
impl tokio::io::AsyncRead for Counted {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for Counted {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.0).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = result {
            self.1.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn repeated_proxy_sessions() {
    for _ in 0..5 {
        loopback("proxy", false, 24).await;
    }
}

#[tokio::test]
#[ignore = "opt-in desktop benchmark"]
async fn desktop_benchmark() {
    let mode = std::env::var("DIW_TLSN_BENCH_MODE").unwrap();
    assert!(matches!(mode.as_str(), "proxy" | "mpc"));
    let size: usize = std::env::var("DIW_TLSN_BENCH_BYTES")
        .unwrap()
        .parse()
        .unwrap();
    assert!(matches!(size, 1024 | 16384 | 204800));
    for run in ["first", "warm"] {
        let (ms, p, v, verify_ms) = loopback(&mode, false, size).await;
        println!("BENCH mode={mode} body_bytes={size} run={run} elapsed_ms={ms} prover_wire_bytes={p} verifier_wire_bytes={v} verifier_accept_ms={verify_ms}");
    }
}
