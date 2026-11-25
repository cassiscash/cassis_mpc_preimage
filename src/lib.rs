//! Two-party generation of SHA-256 hashes whose 32-byte preimage nobody knows.
//!
//! The preimage is `x = r_A ^ r_B`, where each party picks its own random
//! 32-byte share. Both parties jointly compute `H = SHA256(r_A ^ r_B)` with
//! garbled circuits (mpz half-gates) using dual execution:
//!
//! 1. A garbles and B evaluates; B decodes `v1`.
//! 2. B garbles and A evaluates; A decodes `v2`.
//! 3. Each party encodes the value it decoded in the labels of the circuit it
//!    garbled, and the parties check in a secure equality test that this
//!    matches the labels the other party actually evaluated. That holds only
//!    if `v1 == v2` and both circuits were honest.
//!
//! A malicious party can't make the honest party accept a wrong hash. It can
//! learn at most one bit about the honest party's shares per batch (whether
//! the check passed), and in that case the honest party sees the batch abort.
//!
//! Many hashes are produced in one batch, so they can be pregenerated and
//! consumed later. To release a preimage, both parties reveal their shares and
//! anyone can check them with [`open`].
//!
//! Each program runs one party. It brings its own transport: any reliable,
//! ordered byte stream to the other party (TCP, TLS, a QUIC stream, ...) passed
//! to [`generate_batch`]. The transport should authenticate the peer.

mod circuit;
mod equality;
mod execution;

use futures::{AsyncRead, AsyncWrite};
use mpz_circuits::Circuit;
use mpz_common::Context;
use mpz_garble_core::{Delta, Mac};
use mpz_ot::{
    chou_orlandi,
    cot::{DerandCOTReceiver, DerandCOTSender},
    kos::{self, ReceiverConfig, SenderConfig},
};
use rand::RngExt;
use serio::{SinkExt, stream::IoStreamExt};
use sha2::{Digest, Sha256};

pub const SHARE_LEN: usize = 32;

/// Sent in the handshake; peers with a different version refuse to run.
const PROTOCOL_VERSION: u32 = 1;

pub type Share = [u8; SHARE_LEN];
pub type Hash = [u8; 32];
pub type Preimage = [u8; SHARE_LEN];
pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Role {
    /// Garbles first.
    A,
    /// Garbles second.
    B,
}

impl Role {
    fn other(self) -> Self {
        match self {
            Role::A => Role::B,
            Role::B => Role::A,
        }
    }
}

pub fn random_shares(n: usize) -> Vec<Share> {
    let mut rng = rand::rng();
    (0..n).map(|_| rng.random()).collect()
}

/// A step of [`generate_batch_with_progress`], reported as it happens.
#[derive(Debug)]
#[non_exhaustive]
pub enum Progress<'a> {
    /// Both peers agreed on the protocol version, their roles and the batch
    /// size.
    Handshake { batch_size: usize },
    /// One of the two runs started. In run 1, A garbles and B evaluates; in
    /// run 2 it's the other way around.
    RunStarted { run: u8, garbler: Role },
    /// Oblivious transfer gave the evaluator the input labels for the bits of
    /// its shares, without the garbler learning those bits.
    InputLabelsTransferred { bits: usize },
    /// We garbled circuit `index` and sent it.
    Garbled { index: usize, bytes: usize },
    /// We evaluated circuit `index` and decoded its hash.
    Evaluated { index: usize, hash: &'a Hash },
    /// The secure equality test is about to compare the output labels of both
    /// runs.
    Checking,
    /// The check passed: both runs computed the same, correct hashes.
    Verified,
}

/// Runs this party's side of the dual-execution 2PC for a batch of shares,
/// talking to the other party over `io`.
///
/// Both parties must use the same batch size and opposite roles; hash `i`
/// belongs to share `i` on both sides. Returns an error, and no hashes, if the
/// other party cheated or the connection failed. Throw away the shares of a
/// failed batch and don't retry with them.
pub async fn generate_batch<T>(io: T, role: Role, shares: &[Share]) -> Result<Vec<Hash>, Error>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    generate_batch_with_progress(io, role, shares, |_| {}).await
}

/// [`generate_batch`], calling `progress` after each step.
pub async fn generate_batch_with_progress<T>(
    io: T,
    role: Role,
    shares: &[Share],
    mut progress: impl FnMut(Progress<'_>) + Send,
) -> Result<Vec<Hash>, Error>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    let mut ctx = Context::new_single_threaded(io);
    let circuit = circuit::sha256_xor();
    dual_execution(
        &mut ctx,
        role,
        shares,
        (shares, &circuit),
        &circuit,
        &mut progress,
    )
    .await
}

/// Checks that the peer runs the same protocol version, plays the other role
/// and uses the same batch size.
async fn handshake(ctx: &mut Context, role: Role, batch_size: usize) -> Result<(), Error> {
    ctx.io_mut()
        .send((PROTOCOL_VERSION, role, batch_size as u64))
        .await?;
    let (version, peer_role, peer_size): (u32, Role, u64) = ctx.io_mut().expect_next().await?;
    if version != PROTOCOL_VERSION {
        return Err(format!("handshake: peer runs protocol version {version}").into());
    }
    if peer_role != role.other() {
        return Err(format!("handshake: both parties chose role {role:?}").into());
    }
    if peer_size != batch_size as u64 {
        return Err(format!("handshake: batch size {batch_size}, but peer has {peer_size}").into());
    }
    Ok(())
}

/// `garbling` is what this party garbles with. Only tests that simulate a
/// cheater pass something other than `(shares, circuit)`.
async fn dual_execution(
    ctx: &mut Context,
    role: Role,
    shares: &[Share],
    garbling: (&[Share], &Circuit),
    circuit: &Circuit,
    progress: &mut (dyn FnMut(Progress<'_>) + Send),
) -> Result<Vec<Hash>, Error> {
    handshake(ctx, role, shares.len()).await?;
    progress(Progress::Handshake {
        batch_size: shares.len(),
    });

    let (garble_shares, garble_circuit) = garbling;
    let delta = Delta::random(&mut rand::rng());
    let mut cot_sender = DerandCOTSender::new(kos::Sender::new(
        SenderConfig::default(),
        delta.into_inner(),
        chou_orlandi::Receiver::new(),
    ));
    let mut cot_receiver = DerandCOTReceiver::new(kos::Receiver::new(
        ReceiverConfig::default(),
        chou_orlandi::Sender::new(),
    ));

    let (keys, (macs, hashes)) = match role {
        Role::A => {
            progress(Progress::RunStarted {
                run: 1,
                garbler: Role::A,
            });
            let keys = execution::garble(
                ctx,
                &mut cot_sender,
                delta,
                garble_shares,
                garble_circuit,
                progress,
            )
            .await?;
            progress(Progress::RunStarted {
                run: 2,
                garbler: Role::B,
            });
            let eval =
                execution::evaluate(ctx, &mut cot_receiver, shares, circuit, progress).await?;
            (keys, eval)
        }
        Role::B => {
            progress(Progress::RunStarted {
                run: 1,
                garbler: Role::A,
            });
            let eval =
                execution::evaluate(ctx, &mut cot_receiver, shares, circuit, progress).await?;
            progress(Progress::RunStarted {
                run: 2,
                garbler: Role::B,
            });
            let keys = execution::garble(
                ctx,
                &mut cot_sender,
                delta,
                garble_shares,
                garble_circuit,
                progress,
            )
            .await?;
            (keys, eval)
        }
    };

    // The hashes we decoded from the other party's circuit, as labels of the
    // circuit we garbled. If everyone was honest, these are exactly the labels
    // the other party got from evaluating our circuit.
    let expected: Vec<Mac> = keys
        .iter()
        .zip(&hashes)
        .flat_map(|(keys, hash)| keys.iter().zip(bytes_to_bits(hash)))
        .map(|(key, bit)| key.auth(bit, &delta))
        .collect();
    let evaluated: Vec<Mac> = macs.into_iter().flatten().collect();

    // Both sides hash the run-1 labels, then the run-2 labels.
    let (run1, run2) = match role {
        Role::A => (&expected, &evaluated),
        Role::B => (&evaluated, &expected),
    };
    let check = run1
        .iter()
        .chain(run2)
        .fold(Sha256::new(), |h, mac| h.chain_update(mac.as_bytes()))
        .finalize();

    progress(Progress::Checking);
    if !equality::equal(ctx, role, &check.into()).await? {
        return Err("dual-execution check failed: the other party cheated".into());
    }
    progress(Progress::Verified);

    Ok(hashes)
}

/// Combines both revealed shares and checks them against the agreed hash.
pub fn open(r_a: &Share, r_b: &Share, hash: &Hash) -> Option<Preimage> {
    let preimage: Preimage = std::array::from_fn(|i| r_a[i] ^ r_b[i]);
    (Sha256::digest(preimage).as_slice() == hash).then_some(preimage)
}

/// MSB-first bits of `bytes`, matching the circuit's wire order.
pub(crate) fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect()
}

pub(crate) fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|byte| byte.iter().fold(0u8, |acc, &bit| (acc << 1) | bit as u8))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

    fn streams() -> (
        Compat<tokio::io::DuplexStream>,
        Compat<tokio::io::DuplexStream>,
    ) {
        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        (io_a.compat(), io_b.compat())
    }

    fn contexts() -> (Context, Context) {
        let (io_a, io_b) = streams();
        (
            Context::new_single_threaded(io_a),
            Context::new_single_threaded(io_b),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_party_batch_opens() {
        let n = 3;
        let a_shares = random_shares(n);
        let b_shares = random_shares(n);
        let (io_a, io_b) = streams();

        let (hashes_a, hashes_b) = tokio::join!(
            generate_batch(io_a, Role::A, &a_shares),
            generate_batch(io_b, Role::B, &b_shares),
        );
        let (hashes_a, hashes_b) = (hashes_a.unwrap(), hashes_b.unwrap());

        assert_eq!(hashes_a, hashes_b);
        for i in 0..n {
            assert!(open(&a_shares[i], &b_shares[i], &hashes_a[i]).is_some());
            assert!(open(&a_shares[i], &b_shares[(i + 1) % n], &hashes_a[i]).is_none());
        }
    }

    fn assert_check_failed(result: Result<Vec<Hash>, Error>) {
        let err = result.expect_err("cheating must be rejected");
        assert!(err.to_string().contains("check failed"), "{err}");
    }

    /// Runs a batch where A garbles with `cheat`, and returns both results.
    async fn run_with_cheating_a(
        cheat: (&[Share], &Circuit),
        a_shares: &[Share],
        b_shares: &[Share],
    ) -> (Result<Vec<Hash>, Error>, Result<Vec<Hash>, Error>) {
        let (io_a, io_b) = streams();
        let mut ctx_a = Context::new_single_threaded(io_a);
        let honest = circuit::sha256_xor();
        let mut no_progress = |_: Progress<'_>| {};
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            tokio::join!(
                dual_execution(
                    &mut ctx_a,
                    Role::A,
                    a_shares,
                    cheat,
                    &honest,
                    &mut no_progress
                ),
                generate_batch(io_b, Role::B, b_shares),
            )
        })
        .await
        .expect("protocol should not hang")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cheating_circuit_is_detected() {
        let (a_shares, b_shares) = (random_shares(2), random_shares(2));
        let evil = circuit::sha256_of_a();

        let (a, b) = run_with_cheating_a((&a_shares, &evil), &a_shares, &b_shares).await;
        assert_check_failed(a);
        assert_check_failed(b);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn inconsistent_inputs_are_detected() {
        let (a_shares, b_shares) = (random_shares(2), random_shares(2));
        let other_shares = random_shares(2);
        let honest = circuit::sha256_xor();

        let (a, b) = run_with_cheating_a((&other_shares, &honest), &a_shares, &b_shares).await;
        assert_check_failed(a);
        assert_check_failed(b);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_rejects_mismatches() {
        for (role_b, n_b) in [(Role::A, 2), (Role::B, 3)] {
            let (io_a, io_b) = streams();
            let (a_shares, b_shares) = (random_shares(2), random_shares(n_b));
            let (a, b) = tokio::join!(
                generate_batch(io_a, Role::A, &a_shares),
                generate_batch(io_b, role_b, &b_shares),
            );
            for result in [a, b] {
                let err = result.expect_err("mismatch must be rejected");
                assert!(err.to_string().starts_with("handshake"), "{err}");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn equality_test() {
        for (a, b, expected) in [([7u8; 32], [7u8; 32], true), ([7u8; 32], [8u8; 32], false)] {
            let (mut ctx_a, mut ctx_b) = contexts();
            let (eq_a, eq_b) = tokio::join!(
                equality::equal(&mut ctx_a, Role::A, &a),
                equality::equal(&mut ctx_b, Role::B, &b),
            );
            assert_eq!(eq_a.unwrap(), expected);
            assert_eq!(eq_b.unwrap(), expected);
        }
    }
}
