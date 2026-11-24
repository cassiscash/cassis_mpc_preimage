use std::time::Instant;

use mpc_preimage::{Role, generate_batch, open, random_shares};
use polytune::channel::SimpleChannel;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Runs both parties in one process over in-memory channels.
#[tokio::main]
async fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .map(|s| s.parse().expect("batch size"))
        .unwrap_or(4);

    let a_shares = random_shares(n);
    let b_shares = random_shares(n);

    let mut channels = SimpleChannel::channels(2).into_iter();
    let (ch_a, ch_b) = (channels.next().unwrap(), channels.next().unwrap());

    let start = Instant::now();
    let b_task = {
        let b_shares = b_shares.clone();
        tokio::spawn(async move {
            let hashes = generate_batch(&ch_b, Role::B, &b_shares).await;
            (hashes, ch_b.bytes_sent())
        })
    };
    let hashes = generate_batch(&ch_a, Role::A, &a_shares)
        .await
        .expect("party A");
    let (hashes_b, b_sent) = b_task.await.unwrap();
    let hashes_b = hashes_b.expect("party B");
    let elapsed = start.elapsed();

    assert_eq!(hashes, hashes_b, "parties disagree on the hashes");

    println!(
        "{n} hashes in {elapsed:.2?} ({:.2?}/hash), A sent {:.1} MB, B sent {:.1} MB",
        elapsed / n as u32,
        ch_a.bytes_sent() as f64 / 1e6,
        b_sent as f64 / 1e6,
    );
    for hash in hashes.iter().take(3) {
        println!("  H = {}", hex(hash));
    }

    // Later, both agree to release the first one.
    let preimage = open(&a_shares[0], &b_shares[0], &hashes[0]).expect("shares should open");
    println!("opened #0 preimage: {}", hex(&preimage));
}
