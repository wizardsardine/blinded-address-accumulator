pub mod crypto;
pub mod descriptor;
pub mod shuffle;
pub mod tree;

use crate::{
    crypto::{Crypto, HmacEngine, Sha256Engine},
    shuffle::{MAX_RANGE, shuffle_key, shuffle_order},
    tree::{TreeBuilder, collapse},
};

pub const LEAF_TAG: &[u8] = "BIPXXX_LEAF".as_bytes();
pub const BRANCH_TAG: &[u8] = "BIPXXX_BRANCH".as_bytes();
pub const ROOT_TAG: &[u8] = "BIPXXX_ROOT".as_bytes();
pub const NONCE_TAG: &[u8] = "BIPXXX_NONCE".as_bytes();
pub const POLICY_TAG: &[u8] = "BIPXXX_POLICY".as_bytes();

pub fn leaf_nonce<C: Crypto>(
    chaincode: &[u8; 32],
    keys_digest: &[u8; 32],
    keychain: u32,
    index: u32,
) -> ([u8; 32] /* chaincode */, [u8; 32] /* nonce */) {
    let mut engine = C::HmacEngine::new(chaincode);
    engine.input(NONCE_TAG);
    engine.input(keys_digest);
    engine.input(&keychain.to_be_bytes());
    engine.input(&index.to_be_bytes());
    let hmac = engine.hash();
    let chaincode = hmac[..32].try_into().expect("64 bytes");
    let nonce = hmac[32..].try_into().expect("64 bytes");
    (chaincode, nonce)
}

pub fn leaf_hash<C: Crypto>(script: &[u8], nonce: &[u8; 32]) -> [u8; 32] {
    let mut engine = C::Sha256Engine::new_tagged(LEAF_TAG);
    engine.input(script);
    engine.input(nonce);
    engine.hash()
}

pub fn branch_hash<C: Crypto>(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut engine = C::Sha256Engine::new_tagged(BRANCH_TAG);
    engine.input(left);
    engine.input(right);
    engine.hash()
}

pub fn policy_hash<C: Crypto>(policy_id: &[u8; 32], keychain: u32, start_index: u32) -> [u8; 32] {
    let mut engine = C::Sha256Engine::new_tagged(POLICY_TAG);
    engine.input(policy_id);
    engine.input(&keychain.to_be_bytes());
    engine.input(&start_index.to_be_bytes());
    engine.hash()
}

pub fn root_hash<C: Crypto>(root: &[u8; 32]) -> [u8; 32] {
    let mut engine = C::Sha256Engine::new_tagged(ROOT_TAG);
    engine.input(root);
    engine.hash()
}

pub fn generate_tree<C: Crypto, T: TreeBuilder>(
    policy_id: [u8; 32],
    keys_digest: &[u8; 32],
    keychain: u32,
    start_index: u32,
    derivator: impl Fn(u32) -> Vec<u8>,
    mut tree: T,
) -> T::Tree {
    assert!(start_index <= u32::MAX - (MAX_RANGE as u32 - 1));

    let mut chaincode = policy_hash::<C>(&policy_id, keychain, start_index);
    let mut leaves = vec![[0u8; 32]; MAX_RANGE];
    let mut nonces = vec![[0u8; 32]; MAX_RANGE];
    for offset in 0..MAX_RANGE {
        let index = start_index + offset as u32;
        let (cc, nonce) = leaf_nonce::<C>(&chaincode, keys_digest, keychain, index);
        chaincode = cc;
        nonces[offset] = nonce;
        leaves[offset] = leaf_hash::<C>(&derivator(index), &nonce);
    }

    let mut nodes: Vec<[u8; 32]> =
        shuffle_order::<C>(shuffle_key::<C>(&policy_id, keychain, start_index))
            .iter()
            .enumerate()
            .map(|(pos, offset)| {
                let index = start_index + *offset as u32;
                let hash = leaves[*offset as usize];
                tree.leaf(pos as u32, index, &hash, &nonces[*offset as usize]);
                hash
            })
            .collect();

    let root = root_hash::<C>(&collapse::<C>(&mut nodes, &mut tree));
    tree.finish(root)
}
