use crate::bsa_ll::branch_hash;

pub trait TreeSink {
    /// Level 0. `pos` is the global tree position; `index` is the derivation
    /// index that produced it. Sorting means these do not correlate.
    fn leaf(&mut self, pos: u32, index: u32, hash: &[u8; 32]);

    /// Level 1 and above, increasing upward.
    fn node(&mut self, level: u8, pos: u32, hash: &[u8; 32]);
}

/// Signer side: records nothing. Monomorphises away entirely.
pub struct NullSink;
impl TreeSink for NullSink {
    fn leaf(&mut self, _: u32, _: u32, _: &[u8; 32]) {}
    fn node(&mut self, _: u8, _: u32, _: &[u8; 32]) {}
}

/// Collapse a power-of-two slice bottom-up, emitting every level it computes.
/// The input level is NOT emitted — the caller is responsible for that, since
/// only the caller knows whether those nodes are leaves or subroots.
pub fn collapse(
    nodes: &mut Vec<[u8; 32]>,
    base_level: u8,
    base_pos: u32,
    sink: &mut impl TreeSink,
) -> [u8; 32] {
    assert!(nodes.len().is_power_of_two());

    let mut level = base_level;
    let mut pos = base_pos;

    while nodes.len() > 1 {
        for i in 0..nodes.len() / 2 {
            nodes[i] = branch_hash(&nodes[2 * i], &nodes[2 * i + 1]);
        }
        nodes.truncate(nodes.len() / 2);
        level += 1;
        pos /= 2;
        for (i, h) in nodes.iter().enumerate() {
            sink.node(level, pos + i as u32, h);
        }
    }
    nodes[0]
}
