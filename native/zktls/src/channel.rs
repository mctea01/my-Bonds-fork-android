//! Blocking foreign callbacks bridged with bounded buffers and joined workers.
use crate::{Error, Result};
use futures::{channel::mpsc, SinkExt, StreamExt};
use std::{
    cell::Cell,
    sync::{Arc, Once},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// close must be thread safe and unblock any outstanding send/receive call.
pub trait Channel: Send + Sync + 'static {
    fn send(&self, data: Vec<u8>) -> Result<()>;
    fn receive(&self) -> Result<Vec<u8>>;
    fn close(&self);
}
thread_local! { static PRIVATE:Cell<bool>=const {Cell::new(false)}; }
fn protect() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !PRIVATE.try_with(Cell::get).unwrap_or(false) {
                previous(info);
            }
        }));
    });
}

pub fn run<T: Send + 'static, F, Fut>(
    channel: Arc<dyn Channel>,
    cancel: Arc<dyn Fn() -> bool + Send + Sync>,
    operation: F,
) -> Result<T>
where
    F: FnOnce(DuplexStream) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        run_private(channel, cancel, operation)
    })
}

fn run_private<T: Send + 'static, F, Fut>(
    channel: Arc<dyn Channel>,
    cancel: Arc<dyn Fn() -> bool + Send + Sync>,
    operation: F,
) -> Result<T>
where
    F: FnOnce(DuplexStream) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    if cancel() {
        channel.close();
        return Err(Error::Cancelled);
    }
    protect();
    struct Privacy(bool);
    impl Drop for Privacy {
        fn drop(&mut self) {
            PRIVATE.set(self.0);
        }
    }
    let _privacy = Privacy(PRIVATE.replace(true));
    let (mut incoming_tx, mut incoming_rx) = mpsc::channel::<Result<Vec<u8>>>(2);
    let (mut outgoing_tx, mut outgoing_rx) =
        mpsc::channel::<(Vec<u8>, futures::channel::oneshot::Sender<Result<()>>)>(2);
    let reader_channel = Arc::clone(&channel);
    let reader = std::thread::Builder::new()
        .name("diw-zktls-receive".into())
        .spawn(move || {
            PRIVATE.set(true);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                futures::executor::block_on(async {
                    loop {
                        let packet = reader_channel.receive().and_then(|data| {
                            if data.len() > 65537 || data.is_empty() {
                                Err(Error::Channel)
                            } else {
                                Ok(data)
                            }
                        });
                        let failed = packet.is_err();
                        if incoming_tx.send(packet).await.is_err() || failed {
                            break;
                        }
                    }
                });
            }));
            if result.is_err() {
                reader_channel.close();
            }
            result.map_err(|_| Error::Worker)
        })
        .map_err(|_| Error::Worker)?;
    let writer_channel = Arc::clone(&channel);
    let writer = std::thread::Builder::new()
        .name("diw-zktls-send".into())
        .spawn(move || {
            PRIVATE.set(true);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                futures::executor::block_on(async {
                    while let Some((packet, ack)) = outgoing_rx.next().await {
                        let result = writer_channel.send(packet);
                        let failed = result.is_err();
                        let _ = ack.send(result);
                        if failed {
                            return Err(Error::Channel);
                        }
                    }
                    Ok(())
                })
            }))
            .map_err(|_| Error::Worker)
            .and_then(|x| x);
            if result.is_err() {
                writer_channel.close();
            }
            result
        });
    let writer = match writer {
        Ok(worker) => worker,
        Err(_) => {
            channel.close();
            drop(incoming_rx);
            let _ = reader.join();
            return Err(Error::Worker);
        }
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Worker);
    let result = match runtime {
        Ok(runtime) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async {
                let (stream, bridge) = tokio::io::duplex(32768);
                let (mut read, mut write) = tokio::io::split(bridge);
                let receive = async {
                    while let Some(packet) = incoming_rx.next().await {
                        let packet = match packet {
                            Ok(packet) => packet,
                            Err(_) => break,
                        };
                        write.write_all(&packet).await.map_err(|_| Error::Channel)?;
                    }
                    // Propagate transport EOF to Noise, which must authenticate it.
                    // A peer can close immediately after its authenticated EOF;
                    // do not race a successful protocol result with that closure.
                    write.shutdown().await.map_err(|_| Error::Channel)?;
                    std::future::pending::<Result<()>>().await
                };
                let send = async {
                    let mut buffer = vec![0; 16384];
                    loop {
                        let n = read.read(&mut buffer).await.map_err(|_| Error::Channel)?;
                        if n == 0 {
                            return Ok(());
                        }
                        let (ack, done) = futures::channel::oneshot::channel();
                        outgoing_tx
                            .send((buffer[..n].to_vec(), ack))
                            .await
                            .map_err(|_| Error::Channel)?;
                        done.await.map_err(|_| Error::Channel)??;
                    }
                };
                let stop = async {
                    let start = Instant::now();
                    loop {
                        if cancel() {
                            return Error::Cancelled;
                        }
                        if start.elapsed() > Duration::from_secs(600) {
                            return Error::Limit;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                };
                let work = async {
                    // Either side can finish first. Returning requires both the
                    // protocol result and a fully acknowledged outgoing stream.
                    tokio::try_join!(operation(stream), send).map(|(output, _)| output)
                };
                tokio::select! {
                    biased;
                    error=stop=>Err(error),
                    result=work=>result,
                    result=receive=>result.and(Err(Error::Channel)),
                }
            })
        }))
        .unwrap_or(Err(Error::Worker)),
        Err(error) => Err(error),
    };
    channel.close();
    drop(incoming_rx);
    drop(outgoing_tx);
    let read_result = reader.join().map_err(|_| Error::Worker).and_then(|x| x);
    let write_result = writer.join().map_err(|_| Error::Worker).and_then(|x| x);
    if cancel() {
        return Err(Error::Cancelled);
    }
    let output = result?;
    read_result?;
    write_result?;
    Ok(output)
}
