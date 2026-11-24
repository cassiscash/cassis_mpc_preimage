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

mod circuit;
mod equality;
mod execution;

use mpz_circuits::Circuit;
use mpz_common::Context;
use mpz_garble_core::{Delta, Mac};
use mpz_ot::{
    chou_orlandi,
    cot::{DerandCOTReceiver, DerandCOTSender},
    kos::{self, ReceiverConfig, SenderConfig},
};
use rand::RngExt;
use sha2::{Digest, Sha256};

pub const SHARE_LEN: usize = 32;

pub type Share = [u8; SHARE_LEN];
pub type Hash = [u8; 32];
pub type Preimage = [u8; SHARE_LEN];
pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// Runs the dual-execution 2PC for a batch of shares. Both parties must call
/// this with batches of the same length; hash `i` belongs to share `i` on
/// both sides. Returns an error, and no hashes, if the check fails.
pub async fn generate_batch(
    ctx: &mut Context,
    role: Role,
    shares: &[Share],
) -> Result<Vec<Hash>, Error> {
    let circuit = circuit::sha256_xor();
    dual_execution(ctx, role, shares, (shares, &circuit), &circuit).await
}

/// `garbling` is what this party garbles with. Only tests that simulate a
/// cheater pass something other than `(shares, circuit)`.
async fn dual_execution(
    ctx: &mut Context,
    role: Role,
    shares: &[Share],
    garbling: (&[Share], &Circuit),
    circuit: &Circuit,
) -> Result<Vec<Hash>, Error> {
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
            let keys =
                execution::garble(ctx, &mut cot_sender, delta, garble_shares, garble_circuit)
                    .await?;
            let eval = execution::evaluate(ctx, &mut cot_receiver, shares, circuit).await?;
            (keys, eval)
        }
        Role::B => {
            let eval = execution::evaluate(ctx, &mut cot_receiver, shares, circuit).await?;
            let keys =
                execution::garble(ctx, &mut cot_sender, delta, garble_shares, garble_circuit)
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

    if !equality::equal(ctx, role, &check.into()).await? {
        return Err("dual-execution check failed: the other party cheated".into());
    }

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
    use tokio_util::compat::TokioAsyncReadCompatExt;

    fn contexts() -> (Context, Context) {
        let (io_a, io_b) = tokio::io::duplex(1 << 20);
        (
            Context::new_single_threaded(io_a.compat()),
            Context::new_single_threaded(io_b.compat()),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_party_batch_opens() {
        let n = 3;
        let a_shares = random_shares(n);
        let b_shares = random_shares(n);
        let (mut ctx_a, mut ctx_b) = contexts();

        let (hashes_a, hashes_b) = tokio::join!(
            generate_batch(&mut ctx_a, Role::A, &a_shares),
            generate_batch(&mut ctx_b, Role::B, &b_shares),
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
        let (mut ctx_a, mut ctx_b) = contexts();
        let honest = circuit::sha256_xor();
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            tokio::join!(
                dual_execution(&mut ctx_a, Role::A, a_shares, cheat, &honest),
                generate_batch(&mut ctx_b, Role::B, b_shares),
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
