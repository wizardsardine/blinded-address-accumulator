//! Deterministic shuffle of the derivation index range.
//!
//! Tree position must not correlate with derivation index: if it did, a sender
//! holding a proof could infer how many addresses the recipient had used before
//! that one, and in what order. This module produces a permutation of
//! `0..n` that is a pure function of the descriptor, so any wallet holding
//! the descriptor reproduces the same tree, while a sender (who holds neither
//! the descriptor nor the shuffle key) cannot compute it.
//!
//! Fisher-Yates over an HMAC counter stream. The alternatives were considered
//! and rejected:
//!
//! - Affine / LCG / LFSR: constant state, but linear. Payments happen in
//!   roughly ascending derivation order, so a counterparty can guess that two
//!   observed positions come from near-consecutive indices, solve for the
//!   coefficients, and then invert every position they ever see.
//! - Open-addressed insertion (linear or double hashing): the resulting
//!   permutation depends on insertion order, so displacement correlates with
//!   derivation index, and the correlation strengthens as the table fills.
//! - Keyed PRP (swap-or-not, Feistel): O(1) state, no array. Correct and
//!   strictly better at large `n`, but at `n <= 256` the array costs 256 bytes
//!   and the PRP costs a primitive that must be pinned exactly in the spec.
//!
//! Fisher-Yates is uniform over all permutations, which is a one-line claim a
//! reviewer can check, and needs no auxiliary occupancy bitmap.

use crate::crypto::{Crypto, HmacEngine, Sha256Engine};

pub const SHUFFLE_TAG: &[u8] = "BIPXXX_SHUFFLE".as_bytes();

/// Largest supported range. A `u8` holds `0..=255`, so 256 entries is the
/// exact ceiling. Going beyond this is not a parameter change: the stream must
/// be read in wider units and the rejection bound below changes with it.
pub const MAX_RANGE: usize = 256;

/// Derive the shuffle key from the wallet policy id, the keychain, and the
/// tree start.
///
/// Domain-separated so this key has a single purpose. Binding the policy id,
/// the keychain, and the tree start gives each tree its own permutation: two
/// trees never share one, even across keychains at equal starts or across
/// policies over the same keys, so proofs cannot be linked across trees by
/// tree position.
pub fn shuffle_key<C: Crypto>(policy_id: &[u8; 32], keychain: u32, start_index: u32) -> [u8; 32] {
    let mut engine = C::Sha256Engine::new_tagged(SHUFFLE_TAG);
    engine.input(policy_id);
    engine.input(&keychain.to_be_bytes());
    engine.input(&start_index.to_be_bytes());
    engine.hash()
}

/// Deterministic byte stream: HMAC(key, SHUFFLE_TAG || u32be(counter)).
///
/// Pseudorandom, not random. Nothing here touches an entropy source. Every
/// byte is a pure function of the key.
struct ShuffleStream<C: Crypto> {
    key: [u8; 32],
    block: [u8; 64],
    counter: u32,
    offset: usize,
    _crypto: std::marker::PhantomData<C>,
}

impl<C: Crypto> ShuffleStream<C> {
    fn new(key: [u8; 32]) -> Self {
        let mut s = Self {
            key,
            block: [0u8; 64],
            counter: 0,
            offset: 64,
            _crypto: std::marker::PhantomData,
        };
        s.refill();
        s
    }

    fn refill(&mut self) {
        let mut engine = C::HmacEngine::new(&self.key);
        engine.input(SHUFFLE_TAG);
        engine.input(&self.counter.to_be_bytes());
        self.block = engine.hash();
        self.counter += 1;
        self.offset = 0;
    }

    fn next_byte(&mut self) -> u8 {
        if self.offset == self.block.len() {
            self.refill();
        }
        let b = self.block[self.offset];
        self.offset += 1;
        b
    }
}

/// Fisher-Yates, descending, with rejection sampling.
///
/// Returns `order` where `order[position] = derivation_index_offset`.
///
/// Four details below are load-bearing for cross-implementation
/// reproducibility. Each is a point where two correct-looking implementations
/// diverge, and the failure is silent: a different root, no error, discovered
/// only when a proof fails to verify.
///
/// 1. The loop runs DESCENDING, `i` from `n-1` down to `1`. Ascending is an
///    equally valid shuffle and yields a DIFFERENT permutation from the same
///    stream.
/// 2. A rejected draw CONSUMES a stream byte. It is not retried against the
///    same position with the same byte. Implementations that disagree here
///    desynchronise at the first rejection.
/// 3. The bound is `b <= i`, inclusive. `j == i` is a valid no-op swap, and
///    excluding it biases the result.
/// 4. Draws use rejection, never modulo. `b % (i + 1)` biases toward low
///    indices, which is a privacy defect rather than a cosmetic one: it makes
///    some index/position pairings likelier than others.
pub fn shuffle_order<C: Crypto>(key: [u8; 32]) -> Vec<u8> {
    let mut order: Vec<u8> = (0..MAX_RANGE).map(|i| i as u8).collect();
    let mut stream = ShuffleStream::<C>::new(key);

    for i in (1..MAX_RANGE).rev() {
        // uniform over 0..=i
        let j = loop {
            let b = stream.next_byte() as usize;
            if b <= i {
                break b;
            }
        };
        order.swap(i, j);
    }

    order
}

/// Invert the permutation: `inv[derivation_index] = position`.
///
/// The coordinator needs this direction to answer "serve a proof for the
/// address at derivation index 5". The signing device never needs it. It
/// walks positions in order and discards as it goes.
pub fn invert(order: &[u8]) -> Vec<u8> {
    let mut inv = vec![0u8; order.len()];
    for (pos, &idx) in order.iter().enumerate() {
        inv[idx as usize] = pos as u8;
    }
    inv
}
