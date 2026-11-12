//! The thread Barretenberg runs on. Barretenberg keeps its worker pool in a thread-local whose destructor joins the
//! workers. Windows runs that destructor while the calling thread exits, under the loader lock, where the workers
//! can never finish exiting: the thread hangs, and so does everything that needs the loader lock afterwards. So on
//! Windows every call goes to one thread that lives as long as the process; other systems call directly.

/// Runs [work] where Barretenberg may be called and returns its result; a panic in it continues in the caller.
#[cfg(not(windows))]
pub fn call<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    work()
}

#[cfg(windows)]
pub fn call<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
    use std::sync::{mpsc, Mutex, OnceLock};
    type Job = Box<dyn FnOnce() + Send>;
    static QUEUE: OnceLock<Mutex<mpsc::Sender<Job>>> = OnceLock::new();
    let queue = QUEUE.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("diw-bb".into())
            // The stack the callers give their own workers for these calls.
            .stack_size(64 * 1024 * 1024)
            .spawn(move || receiver.into_iter().for_each(|job| job()))
            .expect("bb_thread");
        Mutex::new(sender)
    });
    let (done, result) = mpsc::sync_channel(1);
    let job: Box<dyn FnOnce() + Send + '_> = Box::new(move || {
        let _ = done.send(catch_unwind(AssertUnwindSafe(work)));
    });
    // SAFETY: the job borrows from this frame, which waits below until the job has run or was dropped unrun.
    let job: Job = unsafe { std::mem::transmute(job) };
    queue.lock().unwrap_or_else(|e| e.into_inner()).send(job).expect("bb_thread");
    match result.recv().expect("bb_thread") {
        Ok(value) => value,
        Err(panic) => resume_unwind(panic),
    }
}
