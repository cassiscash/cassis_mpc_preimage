//! Boolean circuit for `SHA256(a ^ b)` over two 32-byte inputs.
//!
//! The builder folds constants, so the fixed padding words, the IV and the
//! round constants don't turn into garbled gates.

use mpz_circuits::{Circuit, CircuitBuilder, Feed, Node};

use crate::SHARE_LEN;

pub(crate) const SHARE_BITS: usize = SHARE_LEN * 8;

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[derive(Clone, Copy)]
enum Bit {
    Const(bool),
    Wire(Node<Feed>),
}

/// A 32-bit word, least significant bit first.
type Word = [Bit; 32];

struct Builder(CircuitBuilder);

impl Builder {
    fn not(&mut self, a: Bit) -> Bit {
        match a {
            Bit::Const(x) => Bit::Const(!x),
            Bit::Wire(a) => Bit::Wire(self.0.add_inv_gate(a)),
        }
    }

    fn xor(&mut self, a: Bit, b: Bit) -> Bit {
        match (a, b) {
            (Bit::Const(x), Bit::Const(y)) => Bit::Const(x ^ y),
            (Bit::Const(false), w) | (w, Bit::Const(false)) => w,
            (Bit::Const(true), w) | (w, Bit::Const(true)) => self.not(w),
            (Bit::Wire(a), Bit::Wire(b)) if a == b => Bit::Const(false),
            (Bit::Wire(a), Bit::Wire(b)) => Bit::Wire(self.0.add_xor_gate(a, b)),
        }
    }

    fn and(&mut self, a: Bit, b: Bit) -> Bit {
        match (a, b) {
            (Bit::Const(x), Bit::Const(y)) => Bit::Const(x & y),
            (Bit::Const(false), _) | (_, Bit::Const(false)) => Bit::Const(false),
            (Bit::Const(true), w) | (w, Bit::Const(true)) => w,
            (Bit::Wire(a), Bit::Wire(b)) if a == b => Bit::Wire(a),
            (Bit::Wire(a), Bit::Wire(b)) => Bit::Wire(self.0.add_and_gate(a, b)),
        }
    }

    fn xor_word(&mut self, a: &Word, b: &Word) -> Word {
        std::array::from_fn(|i| self.xor(a[i], b[i]))
    }

    /// Ripple-carry adder mod 2^32, one AND per bit.
    fn add(&mut self, a: &Word, b: &Word) -> Word {
        let mut out = [Bit::Const(false); 32];
        let mut carry = Bit::Const(false);
        for i in 0..32 {
            let a_c = self.xor(a[i], carry);
            let b_c = self.xor(b[i], carry);
            out[i] = self.xor(a_c, b[i]);
            if i < 31 {
                let t = self.and(a_c, b_c);
                carry = self.xor(t, carry);
            }
        }
        out
    }

    fn add_all(&mut self, words: &[&Word]) -> Word {
        let mut acc = *words[0];
        for w in &words[1..] {
            acc = self.add(&acc, w);
        }
        acc
    }

    /// `g ^ (e & (f ^ g))`
    fn ch(&mut self, e: &Word, f: &Word, g: &Word) -> Word {
        std::array::from_fn(|i| {
            let fg = self.xor(f[i], g[i]);
            let t = self.and(e[i], fg);
            self.xor(g[i], t)
        })
    }

    /// `b ^ ((a ^ b) & (b ^ c))`
    fn maj(&mut self, a: &Word, b: &Word, c: &Word) -> Word {
        std::array::from_fn(|i| {
            let ab = self.xor(a[i], b[i]);
            let bc = self.xor(b[i], c[i]);
            let t = self.and(ab, bc);
            self.xor(b[i], t)
        })
    }

    fn sigma(&mut self, w: &Word, rotations: [usize; 3], shift: bool) -> Word {
        let [r0, r1, r2] = rotations;
        let x = rotr(w, r0);
        let y = rotr(w, r1);
        let z = if shift { shr(w, r2) } else { rotr(w, r2) };
        let xy = self.xor_word(&x, &y);
        self.xor_word(&xy, &z)
    }

    /// One SHA-256 compression of `block` starting from `IV`.
    fn sha256_block(&mut self, block: &[Word; 16]) -> [Word; 8] {
        let mut w = [[Bit::Const(false); 32]; 64];
        w[..16].copy_from_slice(block);
        for t in 16..64 {
            let s0 = self.sigma(&w[t - 15], [7, 18, 3], true);
            let s1 = self.sigma(&w[t - 2], [17, 19, 10], true);
            w[t] = self.add_all(&[&w[t - 16], &s0, &w[t - 7], &s1]);
        }

        let iv = IV.map(const_word);
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = iv;
        for t in 0..64 {
            let s1 = self.sigma(&e, [6, 11, 25], false);
            let ch = self.ch(&e, &f, &g);
            let k = const_word(K[t]);
            let t1 = self.add_all(&[&h, &s1, &ch, &k, &w[t]]);
            let s0 = self.sigma(&a, [2, 13, 22], false);
            let maj = self.maj(&a, &b, &c);
            let t2 = self.add(&s0, &maj);
            h = g;
            g = f;
            f = e;
            e = self.add(&d, &t1);
            d = c;
            c = b;
            b = a;
            a = self.add(&t1, &t2);
        }

        let state = [a, b, c, d, e, f, g, h];
        std::array::from_fn(|i| self.add(&iv[i], &state[i]))
    }
}

fn const_word(x: u32) -> Word {
    std::array::from_fn(|i| Bit::Const((x >> i) & 1 == 1))
}

fn rotr(w: &Word, n: usize) -> Word {
    std::array::from_fn(|i| w[(i + n) % 32])
}

fn shr(w: &Word, n: usize) -> Word {
    std::array::from_fn(|i| {
        if i + n < 32 {
            w[i + n]
        } else {
            Bit::Const(false)
        }
    })
}

/// Circuit computing `SHA256(a ^ b)`.
///
/// Inputs are the 256 bits of `a`, then the 256 bits of `b`, each MSB-first.
/// The output is the 256-bit hash, MSB-first.
pub(crate) fn sha256_xor() -> Circuit {
    build(|b, x, y| b.xor(x, y))
}

/// A cheating garbler's circuit: `SHA256(a)`, ignoring `b`, so the garbler
/// would know the preimage. It has the same AND gates as [`sha256_xor`].
#[cfg(test)]
pub(crate) fn sha256_of_a() -> Circuit {
    build(|_, x, _| x)
}

fn build(mix: impl Fn(&mut Builder, Bit, Bit) -> Bit) -> Circuit {
    let mut b = Builder(CircuitBuilder::new());
    let a_in: Vec<_> = (0..SHARE_BITS).map(|_| b.0.add_input()).collect();
    let b_in: Vec<_> = (0..SHARE_BITS).map(|_| b.0.add_input()).collect();

    // 32-byte message, then 0x80, zeros, and the bit length (256).
    let mut block = [[Bit::Const(false); 32]; 16];
    for pos in 0..SHARE_BITS {
        // MSB-first input bits into LSB-first words.
        block[pos / 32][31 - pos % 32] = mix(&mut b, Bit::Wire(a_in[pos]), Bit::Wire(b_in[pos]));
    }
    block[8] = const_word(0x8000_0000);
    block[15] = const_word(SHARE_BITS as u32);

    for word in b.sha256_block(&block) {
        for bit in word.into_iter().rev() {
            let Bit::Wire(node) = bit else {
                unreachable!("every hash bit depends on the inputs")
            };
            b.0.add_output(node);
        }
    }

    b.0.build().expect("sha256 circuit is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bits_to_bytes, bytes_to_bits};
    use sha2::{Digest, Sha256};

    #[test]
    fn plaintext_eval_matches_sha256() {
        let circuit = sha256_xor();
        let a = [0x11u8; 32];
        let b: [u8; 32] = std::array::from_fn(|i| i as u8);

        let inputs: Vec<bool> = bytes_to_bits(&a)
            .into_iter()
            .chain(bytes_to_bits(&b))
            .collect();
        let out = circuit.evaluate(inputs).unwrap();

        let x: Vec<u8> = a.iter().zip(&b).map(|(a, b)| a ^ b).collect();
        assert_eq!(bits_to_bytes(&out), Sha256::digest(&x).as_slice());
    }
}
