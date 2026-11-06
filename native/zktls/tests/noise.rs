use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zktls::noise;

fn keypair() -> snow::Keypair {
    snow::Builder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse().unwrap())
        .generate_keypair()
        .unwrap()
}

#[tokio::test]
async fn authenticated_duplex_and_eof() {
    let key = keypair();
    let (a, b) = tokio::io::duplex(1024);
    let (a, b) = tokio::try_join!(
        noise::connect(a, [7; 32], key.public.try_into().unwrap(), true),
        noise::connect(b, [7; 32], key.private.try_into().unwrap(), false)
    )
    .unwrap();
    let sender = async {
        let mut a = a;
        a.io.write_all(b"synthetic private bytes").await.unwrap();
        a.io.shutdown().await.unwrap();
        let mut response = [0; 2];
        a.io.read_exact(&mut response).await.unwrap();
        assert!(response == *b"OK");
        a.finish().await.unwrap();
    };
    let receiver = async {
        let mut b = b;
        let mut private = Vec::new();
        b.io.read_to_end(&mut private).await.unwrap();
        assert!(private == b"synthetic private bytes");
        b.io.write_all(b"OK").await.unwrap();
        b.finish().await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(sender, receiver);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejects_request_or_key_mismatch() {
    for wrong_key in [false, true] {
        let key = keypair();
        let other = keypair();
        let (a, b) = tokio::io::duplex(1024);
        let public = if wrong_key { other.public } else { key.public };
        let hash = if wrong_key { [7; 32] } else { [8; 32] };
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                noise::connect(a, hash, public.try_into().unwrap(), true),
                noise::connect(b, [7; 32], key.private.try_into().unwrap(), false)
            )
        })
        .await
        .unwrap();
        assert!(result.0.is_err() && result.1.is_err());
    }
}

#[tokio::test]
async fn rejects_modified_transport_frame() {
    let key = keypair();
    let (a, mut forward) = tokio::io::duplex(4096);
    let (mut backward, b) = tokio::io::duplex(4096);
    let relay = tokio::spawn(async move {
        // Forward the two handshake messages unchanged.
        let n = forward.read_u16().await.unwrap();
        let mut data = vec![0; n as usize];
        forward.read_exact(&mut data).await.unwrap();
        backward.write_u16(n).await.unwrap();
        backward.write_all(&data).await.unwrap();
        let n = backward.read_u16().await.unwrap();
        let mut data = vec![0; n as usize];
        backward.read_exact(&mut data).await.unwrap();
        forward.write_u16(n).await.unwrap();
        forward.write_all(&data).await.unwrap();
        let n = forward.read_u16().await.unwrap();
        let mut data = vec![0; n as usize];
        forward.read_exact(&mut data).await.unwrap();
        data[0] ^= 1;
        backward.write_u16(n).await.unwrap();
        backward.write_all(&data).await.unwrap();
    });
    let (mut a, mut b) = tokio::try_join!(
        noise::connect(a, [7; 32], key.public.try_into().unwrap(), true),
        noise::connect(b, [7; 32], key.private.try_into().unwrap(), false)
    )
    .unwrap();
    a.io.write_all(b"synthetic data").await.unwrap();
    let mut data = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), b.io.read(&mut data))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(b.finish().await.is_err());
    relay.await.unwrap();
}
