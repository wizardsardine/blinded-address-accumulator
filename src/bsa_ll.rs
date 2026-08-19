use crate::{
    crypto::{HmacEngine, Sha256Engine},
    tree::{TreeSink, collapse},
};

pub const LEAF_TAG: &[u8] = "BIPXXX_LEAF".as_bytes();
pub const PAD_TAG: &[u8] = "BIPXXX_PAD".as_bytes();
pub const BRANCH_TAG: &[u8] = "BIPXXX_BRANCH".as_bytes();
pub const ROOT_TAG: &[u8] = "BIPXXX_ROOT".as_bytes();
pub const NONCE_TAG: &[u8] = "BIPXXX_NONCE".as_bytes();

pub fn leaf_nonce(
    chaincode: &[u8; 32],
    keys_digest: &[u8; 32],
    keychain: u32,
    index: u32,
) -> ([u8; 32] /* chaincode */, [u8; 32] /* nonce */) {
    let mut engine = HmacEngine::new(chaincode);
    engine.input(keys_digest);
    engine.input(&keychain.to_be_bytes());
    engine.input(&index.to_be_bytes());
    let hmac = engine.hash();
    let chaincode = hmac[..32].try_into().expect("64 bytes");
    let nonce = hmac[32..].try_into().expect("64 bytes");
    (chaincode, nonce)
}

pub fn leaf_hash(script: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    let mut engine = Sha256Engine::new_tagged(LEAF_TAG);
    engine.input(script);
    engine.input(nonce);
    engine.hash()
}

pub fn branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut engine = Sha256Engine::new_tagged(BRANCH_TAG);
    engine.input(left);
    engine.input(right);
    engine.hash()
}

pub fn leaf_bucket(
    mut chaincode: [u8; 32],
    keys_digest: &[u8; 32],
    keychain: u32,
    start_index: u32,
    size: u8,
    derivator: impl Fn(u32) -> Vec<u8>,
    sink: &mut impl TreeSink,
) -> ([u8; 32] /* chaincode */, [u8; 32] /* root */) {
    let n = size as usize;
    assert!(n.is_power_of_two() && n >= 2);
    let leaves_count = n * n;
    assert!(start_index as usize % leaves_count == 0);

    let mut leaves: Vec<(
        [u8; 32], /* leaf hash */
        u32,      /* derivation index */
    )> = Vec::with_capacity(leaves_count);
    for index in start_index..start_index + leaves_count as u32 {
        let (cc, nonce) = leaf_nonce(&chaincode, keys_digest, keychain, index);
        chaincode = cc;
        leaves.push((leaf_hash(&derivator(index), &nonce), index));
    }

    // sort across the whole n*n block, THEN chunk, this is what
    // decorrelates chunk membership from derivation index
    leaves.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    for (leaf_position, (leaf_hash, derivation_index)) in leaves.iter().enumerate() {
        sink.leaf(
            start_index + leaf_position as u32,
            *derivation_index,
            leaf_hash,
        );
    }

    let mut roots: Vec<[u8; 32]> = leaves
        .chunks(n)
        .enumerate()
        .map(|(c, chunk)| {
            let mut nodes: Vec<[u8; 32]> = chunk.iter().map(|(h, _)| *h).collect();
            collapse(&mut nodes, 0, start_index + (c * n) as u32, sink)
        })
        .collect();

    let chunk_level = size.trailing_zeros() as u8;
    (
        chaincode,
        collapse(&mut roots, chunk_level, start_index / n as u32, sink),
    )
}
