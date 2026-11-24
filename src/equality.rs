//! Equality test that is secure against a malicious peer.
//!
//! Both parties run SPAKE2 with their check value as the password and then
//! confirm the derived key. A PAKE gives an active attacker exactly one
//! online guess, so the peer learns only whether the two values are equal,
//! never anything else about the honest party's value.

use mpz_common::Context;
use serio::{SinkExt, stream::IoStreamExt};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::{Error, Role};

pub(crate) async fn equal(ctx: &mut Context, role: Role, value: &[u8; 32]) -> Result<bool, Error> {
    let (spake, msg) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(value),
        &Identity::new(b"mpc_preimage dual execution"),
    );
    ctx.io_mut().send(msg).await?;
    let theirs: Vec<u8> = ctx.io_mut().expect_next().await?;
    let key = spake
        .finish(&theirs)
        .map_err(|e| format!("spake2: {e:?}"))?;

    let confirmation = |role: Role| -> Vec<u8> {
        Sha256::new()
            .chain_update(b"confirm")
            .chain_update([role as u8])
            .chain_update(&key)
            .finalize()
            .to_vec()
    };
    ctx.io_mut().send(confirmation(role)).await?;
    let theirs: Vec<u8> = ctx.io_mut().expect_next().await?;

    Ok(theirs == confirmation(role.other()))
}
