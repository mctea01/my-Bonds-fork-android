//! A side that fails must not leave its peer waiting: the peer sees the closed session and fails too.
use std::{sync::Arc, time::Duration};
use tlsn::webpki::{CertificateDer, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zktls::protocol::{self, Request, Reveal};

/// A localhost TLS 1.2 target with a fresh self-signed certificate; returns its port and certificate.
async fn target() -> (u16, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config.clone()));
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() <= 4096 {
                    let mut byte = [0; 1];
                    if tls.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                }
                let _ = tls
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\nConnection: close\r\n\r\nstatus=OKxxxxxxxxxxxxxxx")
                    .await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, der)
}

fn request(port: u16) -> Request {
    Request {
        host: "localhost".into(),
        port,
        request: format!("GET /check?secret=synthetic HTTP/1.1\r\nHost: localhost:{port}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").into_bytes(),
        max_sent: 4096,
        max_recv: 2048,
        mode: "proxy".into(),
    }
}

/// Runs both roles; each must finish (with an error) well before the deadline.
async fn both_fail(
    port: u16,
    prover_roots: RootCertStore,
    verifier_roots: RootCertStore,
    reveal_query: bool,
) {
    let noise = snow::Builder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse().unwrap())
        .generate_keypair()
        .unwrap();
    let (a, b) = tokio::io::duplex(65536);
    let prover = protocol::prove(
        a,
        request(port),
        [7; 32],
        noise.public.try_into().unwrap(),
        prover_roots,
        move |t| {
            let end = if reveal_query { t.sent.len() } else { 10 };
            Ok(Reveal {
                sent: vec![0..end],
                received: vec![],
                commit_sha256: vec![],
            })
        },
    );
    let verifier = protocol::verify(
        b,
        "localhost".into(),
        port,
        4096,
        2048,
        "proxy".into(),
        [7; 32],
        noise.private.try_into().unwrap(),
        verifier_roots,
    );
    let (p, v) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(prover, verifier)
    })
    .await
    .expect("a failed peer left the other side waiting");
    assert!(p.is_err() && v.is_err());
}

fn roots(der: Vec<u8>) -> RootCertStore {
    RootCertStore {
        roots: vec![CertificateDer(der)],
    }
}

#[tokio::test]
async fn verifier_rejecting_the_server_certificate_ends_the_prover() {
    let (port, der) = target().await;
    // The verifier trusts only the Mozilla roots, so the localhost certificate fails on its side.
    both_fail(port, roots(der), protocol::mozilla_roots(), false).await;
}

#[tokio::test]
async fn prover_refusing_to_reveal_the_query_ends_the_verifier() {
    // Both sides trust the target; the prover's reveal covers the private query, so the prover refuses after the
    // TLS session and the verifier, waiting for the proof, must end too.
    let (port, der) = target().await;
    both_fail(port, roots(der.clone()), roots(der), true).await;
}
