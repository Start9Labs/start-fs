//! Bounded worker pool for offloading blocking backend I/O from the FUSE
//! dispatch thread.
//!
//! fuser's `Session::run` is a single-threaded loop — if the filesystem
//! handler blocks (a stuck CIFS write, a long ext4 journal commit, an
//! unresponsive USB drive), no other FUSE request can be serviced and
//! every rsync worker queues behind the stuck op.
//!
//! The pool decouples receipt of a FUSE request from the work itself:
//! the dispatch thread parses arguments, hands the `Reply*` object to a
//! worker via a channel, then returns to accept the next request. Workers
//! do the disk I/O and call `reply.ok()` / `reply.error()` when done.
//! fuser's `Reply*` types are `Send + 'static` so this is mechanically
//! safe — fuser does not care who replies or when, as long as every
//! request eventually gets exactly one reply.

use std::num::NonZeroUsize;
use std::sync::OnceLock;
use std::thread::JoinHandle;

use crossbeam_channel::{bounded, Receiver, Sender};

type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct WorkerPool {
    tx: Option<Sender<Job>>,
    handles: Vec<JoinHandle<()>>,
}

impl WorkerPool {
    /// Spawn `size` worker threads sharing a `queue`-deep MPMC channel.
    pub fn new(size: NonZeroUsize, queue: usize) -> Self {
        let (tx, rx) = bounded::<Job>(queue);
        let handles = (0..size.get())
            .map(|i| {
                let rx = rx.clone();
                std::thread::Builder::new()
                    .name(format!("backup-fs-worker-{i}"))
                    .spawn(move || worker_loop(rx))
                    .expect("spawn worker")
            })
            .collect();
        Self {
            tx: Some(tx),
            handles,
        }
    }

    /// Submit a job. Blocks if the queue is full — preferable to
    /// unbounded memory growth under a sustained stall. In practice the
    /// queue should not fill: workers outnumber concurrent FUSE clients
    /// by a wide margin.
    pub fn submit<F: FnOnce() + Send + 'static>(&self, f: F) {
        if let Some(tx) = &self.tx {
            // send only returns Err when every receiver has dropped —
            // which means the pool is being torn down. The caller's
            // Reply* won't get fired; that's a protocol leak we cannot
            // avoid during shutdown.
            let _ = tx.send(Box::new(f));
        }
    }
}

impl Drop for WorkerPool {
    fn drop(&mut self) {
        // Close the sender; each worker's recv() then returns Err and
        // exits the loop. Join every worker so any in-flight job
        // completes before the process exits — otherwise outstanding
        // disk writes could be lost on shutdown.
        drop(self.tx.take());
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

fn worker_loop(rx: Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        // A panicking job must not kill the worker — otherwise one bug
        // silently reduces pool capacity for the rest of the session.
        // The request whose job panicked won't get a reply; that's a
        // fuser protocol leak we trade for resilience.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
    }
}

/// Global pool sized once at first access. `BACKUPFS_WORKERS` overrides;
/// default is min(32, 2 * logical CPUs).
pub fn global() -> &'static WorkerPool {
    static POOL: OnceLock<WorkerPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let default = std::thread::available_parallelism()
            .map(|p| p.get().saturating_mul(2).min(32))
            .unwrap_or(8);
        let size = std::env::var("BACKUPFS_WORKERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(default);
        // Queue depth: 4x worker count. Enough headroom for a request
        // burst without starving the dispatch thread under back-pressure.
        let queue = size.saturating_mul(4).max(16);
        WorkerPool::new(NonZeroUsize::new(size).unwrap(), queue)
    })
}
