//! Request-bound Noise NK transport. Wire frames contain ciphertext only.
use crate::{Error, Result};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

const MAX_FRAME: usize = 65_535;
const CHUNK: usize = 16_384;
const MAX_WIRE: usize = 1024 * 1024 * 1024;

pub struct SecureIo {
    pub io: DuplexStream,
    pump: JoinHandle<Result<()>>,
}

impl SecureIo {
    pub async fn finish(mut self) -> Result<()> {
        self.io.shutdown().await.map_err(|_| Error::Channel)?;
        (&mut self.pump).await.map_err(|_| Error::Worker)?
    }
}

impl Drop for SecureIo {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

async fn send_frame<W: AsyncWrite + Unpin>(io: &mut W, data: &[u8]) -> Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| Error::Limit)?;
    io.write_u16(len).await.map_err(|_| Error::Channel)?;
    io.write_all(data).await.map_err(|_| Error::Channel)?;
    io.flush().await.map_err(|_| Error::Channel)
}

async fn receive_frame<R: AsyncRead + Unpin>(io: &mut R) -> Result<Vec<u8>> {
    let len = io.read_u16().await.map_err(|_| Error::Channel)? as usize;
    if len < 16 {
        return Err(Error::Protocol);
    }
    let mut data = vec![0; len];
    io.read_exact(&mut data).await.map_err(|_| Error::Channel)?;
    Ok(data)
}

pub async fn connect<S>(
    mut wire: S,
    request_hash: [u8; 32],
    key: [u8; 32],
    initiator: bool,
) -> Result<SecureIo>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let key = Zeroizing::new(key);
    let builder = snow::Builder::new(
        "Noise_NK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|_| Error::Worker)?,
    )
    .prologue(&request_hash);
    let mut handshake = if initiator {
        builder.remote_public_key(&key[..]).build_initiator()
    } else {
        builder.local_private_key(&key[..]).build_responder()
    }
    .map_err(|_| Error::Input)?;
    let mut buffer = Zeroizing::new(vec![0; MAX_FRAME]);
    if initiator {
        let len = handshake
            .write_message(&[], &mut buffer)
            .map_err(|_| Error::Protocol)?;
        send_frame(&mut wire, &buffer[..len]).await?;
        let message = receive_frame(&mut wire).await?;
        if handshake
            .read_message(&message, &mut buffer)
            .map_err(|_| Error::Protocol)?
            != 0
        {
            return Err(Error::Protocol);
        }
    } else {
        let message = receive_frame(&mut wire).await?;
        if handshake
            .read_message(&message, &mut buffer)
            .map_err(|_| Error::Protocol)?
            != 0
        {
            return Err(Error::Protocol);
        }
        let len = handshake
            .write_message(&[], &mut buffer)
            .map_err(|_| Error::Protocol)?;
        send_frame(&mut wire, &buffer[..len]).await?;
    }
    let transport = Arc::new(Mutex::new(
        handshake
            .into_transport_mode()
            .map_err(|_| Error::Protocol)?,
    ));
    let (io, inner) = tokio::io::duplex(CHUNK * 2);
    let pump = tokio::spawn(async move {
        let (mut read_wire, mut write_wire) = tokio::io::split(wire);
        let (mut read_plain, mut write_plain) = tokio::io::split(inner);
        let sending = async {
            let mut plain = Zeroizing::new(vec![0; CHUNK]);
            let mut encrypted = vec![0; CHUNK + 16];
            let mut total = 0;
            loop {
                let n = read_plain
                    .read(&mut plain)
                    .await
                    .map_err(|_| Error::Channel)?;
                total += n;
                if total > MAX_WIRE {
                    return Err(Error::Limit);
                }
                let len = transport
                    .lock()
                    .map_err(|_| Error::Worker)?
                    .write_message(&plain[..n], &mut encrypted)
                    .map_err(|_| Error::Protocol)?;
                send_frame(&mut write_wire, &encrypted[..len]).await?;
                if n == 0 {
                    return Ok(());
                }
            }
        };
        let receiving = async {
            let mut plain = Zeroizing::new(vec![0; MAX_FRAME]);
            let mut total = 0;
            loop {
                let encrypted = receive_frame(&mut read_wire).await?;
                total += encrypted.len();
                if total > MAX_WIRE {
                    return Err(Error::Limit);
                }
                let len = transport
                    .lock()
                    .map_err(|_| Error::Worker)?
                    .read_message(&encrypted, &mut plain)
                    .map_err(|_| Error::Protocol)?;
                if len == 0 {
                    write_plain.shutdown().await.map_err(|_| Error::Channel)?;
                    return Ok(());
                }
                write_plain
                    .write_all(&plain[..len])
                    .await
                    .map_err(|_| Error::Channel)?;
            }
        };
        tokio::try_join!(sending, receiving)?;
        Ok(())
    });
    Ok(SecureIo { io, pump })
}
