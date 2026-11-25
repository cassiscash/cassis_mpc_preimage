//! Benchmark: runs both parties in one process over an in-memory stream.
//!
//!     cargo run --release --example local -- <batch size>

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context as TaskContext, Poll},
    time::Instant,
};

use futures::{AsyncRead, AsyncWrite};
use mpc_preimage::{Role, generate_batch, open, random_shares};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Counts the bytes written through an IO stream.
struct Counted<T> {
    inner: T,
    sent: Arc<AtomicU64>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.sent.fetch_add(n as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Runs both parties in one process over an in-memory duplex stream.
#[tokio::main]
async fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .map(|s| s.parse().expect("batch size"))
        .unwrap_or(4);

    let a_shares = random_shares(n);
    let b_shares = random_shares(n);

    let (io_a, io_b) = tokio::io::duplex(1 << 20);
    let (sent_a, sent_b) = (Arc::default(), Arc::default());
    let io_a = Counted {
        inner: io_a.compat(),
        sent: Arc::clone(&sent_a),
    };
    let io_b = Counted {
        inner: io_b.compat(),
        sent: Arc::clone(&sent_b),
    };

    let start = Instant::now();
    let b_task = {
        let b_shares = b_shares.clone();
        tokio::spawn(async move { generate_batch(io_b, Role::B, &b_shares).await })
    };
    let hashes = generate_batch(io_a, Role::A, &a_shares)
        .await
        .expect("party A");
    let hashes_b = b_task.await.unwrap().expect("party B");
    let elapsed = start.elapsed();

    assert_eq!(hashes, hashes_b, "parties disagree on the hashes");

    println!(
        "{n} hashes in {elapsed:.2?} ({:.2?}/hash), A sent {:.1} MB, B sent {:.1} MB",
        elapsed / n as u32,
        sent_a.load(Ordering::Relaxed) as f64 / 1e6,
        sent_b.load(Ordering::Relaxed) as f64 / 1e6,
    );
    for hash in hashes.iter().take(3) {
        println!("  H = {}", hex(hash));
    }

    // Later, both agree to release the first one.
    let preimage = open(&a_shares[0], &b_shares[0], &hashes[0]).expect("shares should open");
    println!("opened #0 preimage: {}", hex(&preimage));
}
