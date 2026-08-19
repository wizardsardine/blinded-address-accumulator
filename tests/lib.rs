use std::{collections::BTreeSet, fmt, str::FromStr, str::Utf8Error};

use blinded_secret_accumulator::{
    crypto::{Crypto, HmacEngine, Sha256Engine},
    descriptor::{DescriptorImpl, XpubImpl},
    final_tree,
    shuffle::{MAX_RANGE, invert, shuffle_order},
    tree::{HEIGHT, Leaf, Node, ProofTreeBuilder, TreeBuilder, sibling_position, verify_proof},
};
use miniscript::bitcoin::{
    self, bip32,
    hashes::{Hash, HashEngine, Hmac, HmacEngine as BitcoinHmacEngine, sha256, sha512},
};
use miniscript::{Descriptor, DescriptorPublicKey, ForEachKey};

struct TestCrypto;

impl Crypto for TestCrypto {
    type HmacEngine = TestHmacEngine;
    type Sha256Engine = TestSha256Engine;
}

struct TestHmacEngine {
    key: Vec<u8>,
    data: Vec<u8>,
}

impl HmacEngine for TestHmacEngine {
    fn new(data: &[u8]) -> Self {
        Self {
            key: data.to_vec(),
            data: Vec::new(),
        }
    }

    fn input(&mut self, input: &[u8]) {
        self.data.extend_from_slice(input);
    }

    fn hash(&self) -> [u8; 64] {
        let mut engine = BitcoinHmacEngine::<sha512::Hash>::new(&self.key);
        engine.input(&self.data);
        Hmac::from_engine(engine).to_byte_array()
    }
}

struct TestSha256Engine(Vec<u8>);

impl Sha256Engine for TestSha256Engine {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn new_tagged(tag: &[u8]) -> Self {
        let tag_hash = sha256::Hash::hash(tag).to_byte_array();
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&tag_hash);
        data.extend_from_slice(&tag_hash);
        Self(data)
    }

    fn input(&mut self, input: &[u8]) {
        self.0.extend_from_slice(input);
    }

    fn hash(&self) -> [u8; 32] {
        sha256::Hash::hash(&self.0).to_byte_array()
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct TestXpub(bitcoin::bip32::Xpub);

impl XpubImpl for TestXpub {
    fn public_key(&self) -> [u8; 33] {
        self.0.public_key.serialize()
    }

    fn chain_code(&self) -> [u8; 32] {
        *self.0.chain_code.as_bytes()
    }
}

struct ByteDescriptor {
    xpubs: Vec<TestXpub>,
    bytes: Vec<u8>,
}

struct TestDescriptor(Descriptor<DescriptorPublicKey>);

impl fmt::Display for ByteDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            std::str::from_utf8(&self.bytes).map_err(|_| fmt::Error)?
        )
    }
}

impl FromStr for ByteDescriptor {
    type Err = Utf8Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        std::str::from_utf8(s.as_bytes())?;
        Ok(Self {
            xpubs: Vec::new(),
            bytes: s.as_bytes().to_vec(),
        })
    }
}

impl DescriptorImpl for ByteDescriptor {
    type Xpub = TestXpub;

    fn xpubs(&self) -> Vec<Self::Xpub> {
        self.xpubs.clone()
    }

    fn recv_script_at(&self, index: u32) -> Vec<u8> {
        index.to_be_bytes().to_vec()
    }

    fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl fmt::Display for TestDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for TestDescriptor {
    type Err = miniscript::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Descriptor::from_str(s).map(Self)
    }
}

impl DescriptorImpl for TestDescriptor {
    type Xpub = TestXpub;

    fn xpubs(&self) -> Vec<Self::Xpub> {
        let mut xpubs = Vec::new();
        self.0.for_each_key(|key| {
            match key {
                DescriptorPublicKey::XPub(xpub) => xpubs.push(TestXpub(xpub.xkey)),
                DescriptorPublicKey::MultiXPub(xpub) => xpubs.push(TestXpub(xpub.xkey)),
                DescriptorPublicKey::Single(_) => {}
            }
            true
        });
        xpubs
    }

    fn recv_script_at(&self, index: u32) -> Vec<u8> {
        self.0
            .at_derivation_index(index)
            .expect("valid derivation index")
            .script_pubkey()
            .to_bytes()
    }

    fn bytes(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
}

fn xpub(secret: u8, chain_code: [u8; 32]) -> TestXpub {
    use bitcoin::{NetworkKind, secp256k1};

    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&[secret; 32]).expect("secret key");
    TestXpub(bip32::Xpub {
        network: NetworkKind::Test,
        depth: 0,
        parent_fingerprint: bip32::Fingerprint::default(),
        child_number: bip32::ChildNumber::Normal { index: 0 },
        public_key: secp256k1::PublicKey::from_secret_key(&secp, &secret_key),
        chain_code: chain_code.into(),
    })
}

fn key() -> [u8; 32] {
    [0x42u8; 32]
}

fn hash(level: usize, pos: usize) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0] = level as u8;
    hash[1] = pos as u8;
    hash
}

fn liana_descriptor() -> TestDescriptor {
    let primary = xpub(1, [2u8; 32]);
    let recovery = xpub(2, [3u8; 32]);
    let descriptor = format!(
        "wsh(or_d(pk({}/0/*),and_v(v:pk({}/0/*),older(144))))",
        primary.0, recovery.0
    );

    TestDescriptor::from_str(&descriptor).expect("descriptor")
}

#[test]
fn policy_id_hashes_descriptor_bytes() {
    let descriptor = ByteDescriptor {
        xpubs: Vec::new(),
        bytes: b"descriptor".to_vec(),
    };
    let mut engine = TestSha256Engine::new();
    engine.input(b"descriptor");

    assert_eq!(descriptor.policy_id::<TestCrypto>(), engine.hash());
}

#[test]
fn test_descriptor_parses_and_displays() {
    let descriptor = ByteDescriptor::from_str("descriptor").expect("descriptor");

    assert_eq!(descriptor.to_string(), "descriptor");
}

#[test]
fn keys_digest_sorts_bitcoin_xpubs() {
    let a = xpub(1, [2u8; 32]);
    let b = xpub(2, [1u8; 32]);
    let descriptor = ByteDescriptor {
        xpubs: vec![b.clone(), a.clone()],
        bytes: Vec::new(),
    };
    let mut engine = TestSha256Engine::new();
    for xpub in BTreeSet::from([a, b]) {
        engine.input(&xpub.chain_code());
        engine.input(&xpub.public_key());
    }

    assert_eq!(descriptor.keys_digest::<TestCrypto>(), engine.hash());
}

#[test]
fn shuffle_is_deterministic() {
    assert_eq!(
        shuffle_order::<TestCrypto>(key()),
        shuffle_order::<TestCrypto>(key())
    );
}

#[test]
fn shuffle_is_a_permutation() {
    let order = shuffle_order::<TestCrypto>(key());
    assert_eq!(order.len(), MAX_RANGE);
    let mut sorted = order.clone();
    sorted.sort_unstable();
    let expected: Vec<u8> = (0..MAX_RANGE).map(|i| i as u8).collect();
    assert_eq!(sorted, expected);
}

#[test]
fn invert_roundtrips() {
    let order = shuffle_order::<TestCrypto>(key());
    let inv = invert(&order);
    for (pos, &idx) in order.iter().enumerate() {
        assert_eq!(inv[idx as usize] as usize, pos);
    }
}

#[test]
fn shuffle_is_key_dependent() {
    let a = shuffle_order::<TestCrypto>([0x01u8; 32]);
    let b = shuffle_order::<TestCrypto>([0x02u8; 32]);
    assert_ne!(a, b);
}

#[test]
fn proof_tree_returns_proof_for_absolute_index() {
    let start_index = 512;
    let mut builder = ProofTreeBuilder::new(start_index);

    for local_pos in 0..MAX_RANGE {
        let offset = MAX_RANGE - 1 - local_pos;
        let index = start_index + offset as u32;
        builder.leaf(
            start_index + local_pos as u32,
            index,
            &hash(0, local_pos),
            &[offset as u8; 32],
        );
    }

    for level in 1..=HEIGHT {
        for local_pos in 0..MAX_RANGE >> level {
            builder.node(
                level as u8,
                Node {
                    position: (start_index >> level) + local_pos as u32,
                    hash: hash(level, local_pos),
                },
            );
        }
    }

    let tree = builder.finish([9u8; 32]);
    let proof = tree.proof_of(start_index + 111).expect("proof");

    assert_eq!(proof.nonce, [111u8; 32]);
    assert_eq!(proof.position, start_index + 144);
    for level in 0..HEIGHT {
        let sibling_pos = sibling_position(proof.position, level as u8);
        let local_pos = sibling_pos - (start_index >> level);
        assert_eq!(
            proof.siblings.expect("siblings")[level],
            hash(level, local_pos as usize)
        );
    }
}

#[test]
fn proof_tree_returns_none_outside_tree() {
    let start_index = 512;
    let mut builder = ProofTreeBuilder::new(start_index);

    for offset in 0..MAX_RANGE {
        builder.leaf(
            start_index + offset as u32,
            start_index + offset as u32,
            &hash(0, offset),
            &[offset as u8; 32],
        );
    }

    let tree = builder.finish([9u8; 32]);

    assert_eq!(tree.proof_of(start_index - 1), None);
    assert_eq!(tree.proof_of(start_index + MAX_RANGE as u32), None);
}

#[test]
fn verify_proof_without_siblings_fails() {
    let leaf = Leaf {
        nonce: [1u8; 32],
        position: 0,
        siblings: None,
    };

    assert!(!verify_proof::<TestCrypto>(&[], &leaf, &[2u8; 32]));
}

#[test]
fn final_tree_verifies_all_proofs() {
    let start_index = 512;
    let descriptor = liana_descriptor();
    let keys_digest = descriptor.keys_digest::<TestCrypto>();
    let (_, tree) = final_tree::<TestCrypto, _>(
        [1u8; 32],
        &keys_digest,
        0,
        start_index,
        |index| descriptor.recv_script_at(index),
        ProofTreeBuilder::new(start_index),
    );

    for offset in 0..MAX_RANGE {
        let index = start_index + offset as u32;
        let leaf = tree.proof_of(index).expect("proof");

        assert!(leaf.siblings.is_some());
        assert!(verify_proof::<TestCrypto>(
            &descriptor.recv_script_at(index),
            &leaf,
            &tree.root
        ));
    }
}
