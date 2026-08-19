use crate::{branch_hash, crypto::Crypto, leaf_hash, root_hash};

use crate::shuffle::MAX_RANGE;

pub const HEIGHT: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Leaf {
    pub nonce: [u8; 32],
    pub position: u32,
    pub siblings: Option<[[u8; 32]; HEIGHT]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node {
    pub position: u32,
    pub hash: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub struct Tree {
    pub root: [u8; 32],
    pub start_index: u32,
    leaves: Vec<Leaf>,
    levels: Vec<Vec<Node>>,
}

impl Tree {
    pub fn proof_of(&self, index: u32) -> Option<Leaf> {
        let offset = index.checked_sub(self.start_index)? as usize;
        if offset >= MAX_RANGE {
            return None;
        }

        let mut proof = self.leaves[offset];
        let mut siblings = [[0u8; 32]; HEIGHT];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            let pos = sibling_position(proof.position, level as u8);
            let start = self.start_index >> level;
            *sibling = self.levels[level][(pos - start) as usize].hash;
        }

        proof.siblings = Some(siblings);
        Some(proof)
    }
}

pub fn sibling_position(leaf_position: u32, depth: u8) -> u32 {
    (leaf_position >> depth) ^ 1
}

pub fn verify_proof<C: Crypto>(script: &[u8], leaf: &Leaf, root: &[u8; 32]) -> bool {
    let Some(siblings) = leaf.siblings else {
        return false;
    };

    let mut hash = leaf_hash::<C>(script, &leaf.nonce);
    for (depth, sibling) in siblings.iter().enumerate() {
        let pos = leaf.position >> depth;
        let sibling_pos = sibling_position(leaf.position, depth as u8);
        hash = if pos < sibling_pos {
            branch_hash::<C>(&hash, sibling)
        } else {
            branch_hash::<C>(sibling, &hash)
        };
    }

    root_hash::<C>(&hash) == *root
}

pub trait TreeBuilder {
    type Tree;

    /// Level 0. `pos` is the global tree position; `index` is the derivation
    /// index that produced it. The keyed shuffle means these do not correlate.
    fn leaf(&mut self, pos: u32, index: u32, hash: &[u8; 32], nonce: &[u8; 32]);

    /// Level 1 and above, increasing upward.
    fn node(&mut self, level: u8, node: Node);

    fn finish(self, root: [u8; 32]) -> Self::Tree;
}

/// Signer side: records nothing. Monomorphises away entirely.
pub struct NullTreeBuilder;
impl TreeBuilder for NullTreeBuilder {
    type Tree = [u8; 32];

    fn leaf(&mut self, _: u32, _: u32, _: &[u8; 32], _: &[u8; 32]) {}
    fn node(&mut self, _: u8, _: Node) {}
    fn finish(self, root: [u8; 32]) -> Self::Tree {
        root
    }
}

pub struct ProofTreeBuilder {
    start_index: u32,
    leaves: Vec<Option<Leaf>>,
    levels: Vec<Vec<Node>>,
}

impl ProofTreeBuilder {
    pub fn new(start_index: u32) -> Self {
        let levels = (0..=HEIGHT)
            .map(|level| {
                vec![
                    Node {
                        position: 0,
                        hash: [0u8; 32],
                    };
                    MAX_RANGE >> level
                ]
            })
            .collect();
        Self {
            start_index,
            leaves: vec![None; MAX_RANGE],
            levels,
        }
    }
}

impl TreeBuilder for ProofTreeBuilder {
    type Tree = Tree;

    fn leaf(&mut self, pos: u32, index: u32, hash: &[u8; 32], nonce: &[u8; 32]) {
        let offset = index
            .checked_sub(self.start_index)
            .expect("leaf index below tree start") as usize;
        assert!(offset < MAX_RANGE);
        assert!(self.leaves[offset].is_none());

        let local_pos = pos
            .checked_sub(self.start_index)
            .expect("leaf position below tree start") as usize;
        self.levels[0][local_pos] = Node {
            position: pos,
            hash: *hash,
        };
        self.leaves[offset] = Some(Leaf {
            position: pos,
            nonce: *nonce,
            siblings: None,
        });
    }

    fn node(&mut self, level: u8, node: Node) {
        let level = level as usize;
        let level_start = self.start_index >> level;
        let local_pos = node
            .position
            .checked_sub(level_start)
            .expect("node position below tree start") as usize;
        self.levels[level][local_pos] = node;
    }

    fn finish(self, root: [u8; 32]) -> Self::Tree {
        let leaves = self
            .leaves
            .into_iter()
            .map(|leaf| leaf.expect("missing leaf"))
            .collect();
        Tree {
            root,
            start_index: self.start_index,
            leaves,
            levels: self.levels,
        }
    }
}

/// Collapse a power-of-two slice bottom-up, emitting every level it computes.
/// The input level is NOT emitted. The caller is responsible for that, since
/// only the caller knows whether those nodes are leaves or subroots.
pub fn collapse<C: Crypto>(
    nodes: &mut Vec<[u8; 32]>,
    base_level: u8,
    base_pos: u32,
    tree: &mut impl TreeBuilder,
) -> [u8; 32] {
    assert!(nodes.len().is_power_of_two());

    let mut level = base_level;
    let mut pos = base_pos;

    while nodes.len() > 1 {
        for i in 0..nodes.len() / 2 {
            nodes[i] = branch_hash::<C>(&nodes[2 * i], &nodes[2 * i + 1]);
        }
        nodes.truncate(nodes.len() / 2);
        level += 1;
        pos /= 2;
        for (i, h) in nodes.iter().enumerate() {
            tree.node(
                level,
                Node {
                    position: pos + i as u32,
                    hash: *h,
                },
            );
        }
    }
    nodes[0]
}
