//! Equality test that is secure against a malicious peer.
//!
//! Both parties commit to their check value, then reveal and compare it. The
//! commitment forces an active attacker to pick its value before it sees the
//! honest party's, so it gets exactly one guess at making the checks match.
//!
//! Unlike a PAKE, this reveals the compared value. That is fine for the
//! dual-execution check: it is a hash over fresh garbled labels and holds no
//! low-entropy secret. Reusing this for a secret value would need a PAKE.

use mpz_common::Context;
use rand::RngExt;
use serio::{SinkExt, stream::IoStreamExt};
use sha2::{Digest, Sha256};

use crate::{Error, Role};

const DOMAIN: &[u8] = b"mpc_preimage equality";

fn commitment(role: Role, nonce: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    Sha256::new()
        .chain_update(DOMAIN)
        .chain_update([role as u8])
        .chain_update(nonce)
        .chain_update(value)
        .finalize()
        .into()
}

pub(crate) async fn equal(ctx: &mut Context, role: Role, value: &[u8; 32]) -> Result<bool, Error> {
    let nonce: [u8; 32] = rand::rng().random();
    ctx.io_mut().send(commitment(role, &nonce, value)).await?;

    let their_commit: [u8; 32] = ctx.io_mut().expect_next().await?;

    ctx.io_mut().send((nonce, *value)).await?;
    let (their_nonce, their_value): ([u8; 32], [u8; 32]) = ctx.io_mut().expect_next().await?;

    Ok(their_value == *value
        && commitment(role.other(), &their_nonce, &their_value) == their_commit)
}
