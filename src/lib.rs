//! Two-party generation of SHA-256 hashes whose 32-byte preimage nobody knows.
//!
//! The preimage is `x = r_A ^ r_B`, where each party picks its own random
//! 32-byte share. Both parties jointly evaluate `H = SHA256(r_A ^ r_B)` inside
//! a maliciously secure garbled-circuit protocol (polytune, WRK17), so neither
//! learns anything about the other's share beyond `H`.
//!
//! Many hashes are produced in one batch, so they can be pregenerated and
//! consumed later. To release a preimage, both parties reveal their shares and
//! anyone can check them with [`open`].

pub mod circuit;

use polytune::channel::Channel;
use polytune::garble_lang::register_circuit::Circuit as RegisterCircuit;
use rand::Rng;
use sha2::{Digest, Sha256};

pub use polytune::Error;

pub const SHARE_LEN: usize = 32;

pub type Share = [u8; SHARE_LEN];
pub type Hash = [u8; 32];
pub type Preimage = [u8; SHARE_LEN];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Party 0, also the garbled-circuit evaluator.
    A,
    /// Party 1.
    B,
}

impl Role {
    fn index(self) -> usize {
        match self {
            Role::A => 0,
            Role::B => 1,
        }
    }
}

pub fn random_shares(n: usize) -> Vec<Share> {
    let mut rng = rand::rng();
    (0..n)
        .map(|_| {
            let mut share = [0u8; SHARE_LEN];
            rng.fill_bytes(&mut share);
            share
        })
        .collect()
}

/// Runs the 2PC for a batch of shares. Both parties must call this with
/// batches of the same length; hash `i` belongs to share `i` on both sides.
pub async fn generate_batch(
    channel: &impl Channel,
    role: Role,
    shares: &[Share],
) -> Result<Vec<Hash>, Error> {
    let circuit: RegisterCircuit = circuit::sha256_batch(shares.len()).into();
    let inputs: Vec<bool> = shares.iter().flat_map(|s| bytes_to_bits(s)).collect();

    let out = polytune::mpc(channel, &circuit, &inputs, 0, role.index(), &[0, 1], None).await?;

    Ok(out
        .as_chunks::<256>()
        .0
        .iter()
        .map(|bits| bits_to_bytes(bits).try_into().expect("256 bits"))
        .collect())
}

/// Combines both revealed shares and checks them against the agreed hash.
pub fn open(r_a: &Share, r_b: &Share, hash: &Hash) -> Option<Preimage> {
    let preimage: Preimage = std::array::from_fn(|i| r_a[i] ^ r_b[i]);
    (Sha256::digest(preimage).as_slice() == hash).then_some(preimage)
}

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
    use polytune::channel::SimpleChannel;

    #[tokio::test(flavor = "multi_thread")]
    async fn two_party_batch_opens() {
        let n = 2;
        let a_shares = random_shares(n);
        let b_shares = random_shares(n);

        let mut channels = SimpleChannel::channels(2).into_iter();
        let (ch_a, ch_b) = (channels.next().unwrap(), channels.next().unwrap());

        let b_task = {
            let b_shares = b_shares.clone();
            tokio::spawn(async move { generate_batch(&ch_b, Role::B, &b_shares).await })
        };
        let hashes_a = generate_batch(&ch_a, Role::A, &a_shares).await.unwrap();
        let hashes_b = b_task.await.unwrap().unwrap();

        assert_eq!(hashes_a, hashes_b);
        for i in 0..n {
            assert!(open(&a_shares[i], &b_shares[i], &hashes_a[i]).is_some());
            assert!(open(&a_shares[i], &b_shares[(i + 1) % n], &hashes_a[i]).is_none());
        }
    }
}
