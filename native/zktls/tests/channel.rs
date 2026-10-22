use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zktls::{
    channel::{self, Channel},
    Error, Result,
};

#[derive(Default)]
struct Echo {
    state: Mutex<(Vec<Vec<u8>>, bool)>,
    ready: Condvar,
}
impl Channel for Echo {
    fn send(&self, data: Vec<u8>) -> Result<()> {
        self.state.lock().unwrap().0.push(data);
        self.ready.notify_all();
        Ok(())
    }
    fn receive(&self) -> Result<Vec<u8>> {
        let mut state = self.state.lock().unwrap();
        while state.0.is_empty() && !state.1 {
            state = self.ready.wait(state).unwrap();
        }
        if state.1 {
            Err(Error::Channel)
        } else {
            Ok(state.0.remove(0))
        }
    }
    fn close(&self) {
        self.state.lock().unwrap().1 = true;
        self.ready.notify_all();
    }
}
#[test]
fn bridge_flushes_and_closes() {
    let channel = Arc::new(Echo::default());
    let result = channel::run(channel.clone(), Arc::new(|| false), |mut io| async move {
        io.write_all(&[17; 40_000])
            .await
            .map_err(|_| Error::Channel)?;
        let mut received = vec![0; 40_000];
        io.read_exact(&mut received)
            .await
            .map_err(|_| Error::Channel)?;
        if !received.iter().all(|&b| b == 17) {
            return Err(Error::Protocol);
        }
        Ok(())
    });
    assert!(result.is_ok());
    assert!(channel.state.lock().unwrap().1);
}
#[test]
fn cancellation_unblocks_and_joins_callbacks() {
    let channel = Arc::new(Echo::default());
    let start = Instant::now();
    let result = channel::run(
        channel.clone(),
        Arc::new(move || start.elapsed() > Duration::from_millis(30)),
        |io| async move {
            let _keep_open = io;
            std::future::pending::<Result<()>>().await
        },
    );
    assert!(matches!(result, Err(Error::Cancelled)));
    assert!(channel.state.lock().unwrap().1);
}
#[test]
fn operation_panic_closes_callbacks() {
    let channel = Arc::new(Echo::default());
    let result: Result<()> = channel::run(channel.clone(), Arc::new(|| false), |_io| async {
        panic!("synthetic worker panic");
    });
    assert!(matches!(result, Err(Error::Worker)));
    assert!(channel.state.lock().unwrap().1);
}

#[test]
fn outbound_eof_before_operation_result_is_not_failure() {
    let channel = Arc::new(Echo::default());
    let result = channel::run(channel, Arc::new(|| false), |io| async move {
        drop(io);
        tokio::time::sleep(Duration::from_millis(30)).await;
        Ok(())
    });
    assert!(result.is_ok());
}

struct Paired {
    incoming: Arc<Echo>,
    outgoing: Arc<Echo>,
}
impl Channel for Paired {
    fn send(&self, data: Vec<u8>) -> Result<()> {
        self.outgoing.send(data)
    }
    fn receive(&self) -> Result<Vec<u8>> {
        let mut state = self.incoming.state.lock().unwrap();
        while state.0.is_empty() && !state.1 {
            state = self.incoming.ready.wait(state).unwrap();
        }
        if state.0.is_empty() {
            Err(Error::Channel)
        } else {
            Ok(state.0.remove(0))
        }
    }
    fn close(&self) {
        self.incoming.close();
        self.outgoing.close();
    }
}
#[test]
fn authenticated_channel_eof_is_drained_before_foreign_close() {
    for _ in 0..10 {
        let key = snow::Builder::new("Noise_NK_25519_ChaChaPoly_SHA256".parse().unwrap())
            .generate_keypair()
            .unwrap();
        let left = Arc::new(Echo::default());
        let right = Arc::new(Echo::default());
        let initiator = Arc::new(Paired {
            incoming: left.clone(),
            outgoing: right.clone(),
        });
        let responder = Arc::new(Paired {
            incoming: right,
            outgoing: left,
        });
        let public: [u8; 32] = key.public.try_into().unwrap();
        let private: [u8; 32] = key.private.try_into().unwrap();
        let thread = std::thread::spawn(move || {
            channel::run(initiator, Arc::new(|| false), |wire| async move {
                let mut secure = zktls::noise::connect(wire, [7; 32], public, true).await?;
                secure
                    .io
                    .write_all(&[19; 1024])
                    .await
                    .map_err(|_| Error::Channel)?;
                secure.finish().await
            })
        });
        let result = channel::run(responder, Arc::new(|| false), |wire| async move {
            let mut secure = zktls::noise::connect(wire, [7; 32], private, false).await?;
            let mut data = vec![0; 1024];
            secure
                .io
                .read_exact(&mut data)
                .await
                .map_err(|_| Error::Channel)?;
            if !data.iter().all(|&b| b == 19) {
                return Err(Error::Protocol);
            }
            secure.finish().await
        });
        assert!(result.is_ok());
        assert!(thread.join().unwrap().is_ok());
    }
}
