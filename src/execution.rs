//! One semi-honest garbled-circuit execution of `SHA256(r_G ^ r_E)` for a
//! batch of shares, exposing the output labels for the dual-execution check.

use mpz_circuits::Circuit;
use mpz_common::{Context, Flush, future::Output};
use mpz_core::Block;
use mpz_garble_core::{Delta, EncryptedGateBatch, Evaluator, Garbler, Key, Mac};
use mpz_ot::cot::{COTReceiver, COTSender};
use rand::RngExt;
use serio::{SinkExt, stream::IoStreamExt};

use crate::{Error, Hash, Progress, Share, bits_to_bytes, bytes_to_bits, circuit::SHARE_BITS};

/// Garbler's message for one hash: labels for its own share, the garbled
/// gates, and the decoding bits of the output wires.
type GarbledHash = (Vec<Mac>, Vec<EncryptedGateBatch>, Vec<bool>);

/// Garbles one circuit per share. Returns the zero-labels ("keys") of each
/// circuit's output wires; the evaluator ends up with the active ones.
pub(crate) async fn garble<C>(
    ctx: &mut Context,
    cot: &mut C,
    delta: Delta,
    shares: &[Share],
    circuit: &Circuit,
    progress: &mut (dyn FnMut(Progress<'_>) + Send),
) -> Result<Vec<Vec<Key>>, Error>
where
    C: COTSender<Block> + Flush + Send,
    <C as Flush>::Error: std::error::Error + Send + Sync + 'static,
{
    let n = shares.len();
    let (own_keys, ev_keys): (Vec<Key>, Vec<Key>) = {
        let mut rng = rand::rng();
        (
            (0..n * SHARE_BITS).map(|_| rng.random()).collect(),
            (0..n * SHARE_BITS).map(|_| rng.random()).collect(),
        )
    };

    // The evaluator obtains the labels for its share by correlated OT.
    cot.alloc(n * SHARE_BITS)?;
    cot.flush(ctx).await?;
    let mut sent = cot.queue_send_cot(Key::as_blocks(&ev_keys))?;
    cot.flush(ctx).await?;
    sent.try_recv()?.ok_or("COT was not sent after flush")?;
    progress(Progress::InputLabelsTransferred {
        bits: n * SHARE_BITS,
    });

    let mut gb = Garbler::default();
    let mut outputs = Vec::with_capacity(n);
    for (i, share) in shares.iter().enumerate() {
        let own = &own_keys[i * SHARE_BITS..(i + 1) * SHARE_BITS];
        let ev = &ev_keys[i * SHARE_BITS..(i + 1) * SHARE_BITS];

        let own_macs: Vec<Mac> = own
            .iter()
            .zip(bytes_to_bits(share))
            .map(|(key, bit)| key.auth(bit, &delta))
            .collect();

        let inputs: Vec<Key> = own.iter().chain(ev).copied().collect();
        let mut gates = gb.generate_batched(circuit, delta, &inputs)?;
        let batches: Vec<EncryptedGateBatch> = gates.by_ref().collect();
        let keys = gates.finish()?.outputs;
        let decoding: Vec<bool> = keys.iter().map(Key::pointer).collect();

        let bytes = batches.len() * size_of::<EncryptedGateBatch>();
        let msg: GarbledHash = (own_macs, batches, decoding);
        ctx.io_mut().send(msg).await?;
        progress(Progress::Garbled { index: i, bytes });
        outputs.push(keys);
    }

    Ok(outputs)
}

/// Evaluates the garbler's circuits. Returns the active output labels of
/// each circuit and the decoded hashes.
pub(crate) async fn evaluate<C>(
    ctx: &mut Context,
    cot: &mut C,
    shares: &[Share],
    circuit: &Circuit,
    progress: &mut (dyn FnMut(Progress<'_>) + Send),
) -> Result<(Vec<Vec<Mac>>, Vec<Hash>), Error>
where
    C: COTReceiver<bool, Block> + Flush + Send,
    <C as Flush>::Error: std::error::Error + Send + Sync + 'static,
{
    let n = shares.len();
    let choices: Vec<bool> = shares.iter().flat_map(|s| bytes_to_bits(s)).collect();

    cot.alloc(n * SHARE_BITS)?;
    cot.flush(ctx).await?;
    let mut received = cot.queue_recv_cot(&choices)?;
    cot.flush(ctx).await?;
    let own_macs = Mac::from_blocks(
        received
            .try_recv()?
            .ok_or("COT output was not ready after flush")?
            .msgs,
    );
    progress(Progress::InputLabelsTransferred {
        bits: n * SHARE_BITS,
    });

    let mut ev = Evaluator::default();
    let mut macs = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    for i in 0..n {
        let (gb_macs, batches, decoding): GarbledHash = ctx.io_mut().expect_next().await?;
        if gb_macs.len() != SHARE_BITS || decoding.len() != circuit.outputs().len() {
            return Err("garbler sent a malformed circuit".into());
        }

        let inputs: Vec<Mac> = gb_macs
            .into_iter()
            .chain(
                own_macs[i * SHARE_BITS..(i + 1) * SHARE_BITS]
                    .iter()
                    .copied(),
            )
            .collect();
        let mut consumer = ev.evaluate_batched(circuit, &inputs)?;
        for batch in batches {
            if !consumer.wants_gates() {
                return Err("garbler sent too many gates".into());
            }
            consumer.next(batch);
        }
        let out = consumer.finish()?.outputs;

        let bits: Vec<bool> = out
            .iter()
            .zip(&decoding)
            .map(|(mac, d)| mac.pointer() ^ d)
            .collect();
        let hash: Hash = bits_to_bytes(&bits).try_into().expect("256 output bits");
        progress(Progress::Evaluated {
            index: i,
            hash: &hash,
        });
        hashes.push(hash);
        macs.push(out);
    }

    Ok((macs, hashes))
}
