//! One party of the 2PC, talking to the other party over iroh.
//!
//! Terminal 1 (party A):
//!
//!     cargo run --release --example iroh_peer -- listen
//!
//! Terminal 2 (party B), with the endpoint id that A prints:
//!
//!     cargo run --release --example iroh_peer -- connect <endpoint id>
//!
//! Both generate 10 hashes together, then reveal their shares to each other
//! and check the preimages.

use std::time::{Duration, Instant};

use iroh::{Endpoint, EndpointId, endpoint::presets};
use mpc_preimage::{
    Error, Progress, Role, Share, generate_batch_with_progress, open, random_shares,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

const ALPN: &[u8] = b"mpc-preimage/0";
const BATCH_SIZE: usize = 10;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn report(role: Role, progress: Progress<'_>) {
    match progress {
        Progress::Handshake { batch_size } => {
            println!("handshake: we are party {role:?}, batch of {batch_size} hashes")
        }
        Progress::RunStarted { run, garbler } if garbler == role => {
            println!("run {run}: we garble SHA256(r_A ^ r_B), the peer evaluates")
        }
        Progress::RunStarted { run, .. } => {
            println!("run {run}: the peer garbles SHA256(r_A ^ r_B), we evaluate")
        }
        Progress::InputLabelsTransferred { bits } => {
            println!("  oblivious transfer: evaluator got the labels for its {bits} share bits")
        }
        Progress::Garbled { index, bytes } => {
            println!("  garbled circuit #{index}, sent {} KB", bytes / 1000)
        }
        Progress::Evaluated { index, hash } => {
            println!("  evaluated circuit #{index}: {}", hex(hash))
        }
        Progress::Checking => {
            println!("check: comparing both runs' output labels in a SPAKE2 equality test")
        }
        Progress::Verified => {
            println!("check passed: both runs used the same shares and the honest circuit")
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let (endpoint, conn, role) = match args[..] {
        ["listen"] => {
            let endpoint = Endpoint::builder(presets::N0)
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await?;
            endpoint.online().await;
            println!("we are party A, waiting for party B. In another terminal run:");
            println!(
                "  cargo run --release --example iroh_peer -- connect {}",
                endpoint.id()
            );
            let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
            let conn = incoming.await?;
            (endpoint, conn, Role::A)
        }
        ["connect", id] => {
            let id: EndpointId = id.parse()?;
            let endpoint = Endpoint::bind(presets::N0).await?;
            println!("we are party B, connecting to {id}");
            let conn = endpoint.connect(id, ALPN).await?;
            (endpoint, conn, Role::B)
        }
        _ => {
            eprintln!("usage: iroh_peer listen | iroh_peer connect <endpoint id>");
            std::process::exit(2);
        }
    };
    println!("connected to {}\n", conn.remote_id());

    let shares = random_shares(BATCH_SIZE);
    println!("our {BATCH_SIZE} random shares (secret until the reveal):");
    for (i, share) in shares.iter().enumerate() {
        println!("  #{i}: {}", hex(share));
    }
    println!();

    // B opens the stream and A accepts it. The handshake is the first thing
    // B sends, which is what makes the stream show up on A's side.
    let (send, recv) = match role {
        Role::A => conn.accept_bi().await?,
        Role::B => conn.open_bi().await?,
    };
    let io = tokio::io::join(recv, send).compat();

    let start = Instant::now();
    let hashes =
        generate_batch_with_progress(io, role, &shares, |progress| report(role, progress)).await?;
    println!(
        "\ngenerated {BATCH_SIZE} hashes in {:.2?}:",
        start.elapsed()
    );
    for (i, hash) in hashes.iter().enumerate() {
        println!("  #{i}: {}", hex(hash));
    }

    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("\nnow revealing the preimages\n");

    // A fresh stream for the reveal: each side sends its shares to the other.
    let (mut send, mut recv) = match role {
        Role::A => conn.accept_bi().await?,
        Role::B => conn.open_bi().await?,
    };
    send.write_all(shares.as_flattened()).await?;
    send.finish()?;
    let mut peer_shares: Vec<Share> = vec![[0; 32]; BATCH_SIZE];
    recv.read_exact(peer_shares.as_flattened_mut()).await?;
    // Wait until the peer has received our shares too.
    send.stopped().await?;

    for (i, hash) in hashes.iter().enumerate() {
        let (r_a, r_b) = match role {
            Role::A => (&shares[i], &peer_shares[i]),
            Role::B => (&peer_shares[i], &shares[i]),
        };
        let preimage: Vec<u8> = r_a.iter().zip(r_b).map(|(a, b)| a ^ b).collect();
        let ok = open(r_a, r_b, hash).is_some();
        println!("#{i}: hash     {}", hex(hash));
        println!(
            "    preimage {}  {}",
            hex(&preimage),
            if ok {
                "ok: SHA256(preimage) = hash"
            } else {
                "MISMATCH"
            }
        );
    }

    match role {
        Role::A => {
            conn.closed().await;
        }
        Role::B => conn.close(0u32.into(), b"done"),
    }
    endpoint.close().await;
    Ok(())
}
