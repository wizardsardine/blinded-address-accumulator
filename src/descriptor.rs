use std::{collections::BTreeSet, fmt::Display, str::FromStr};

use crate::crypto::{HmacEngine, PublicKey, Sha256Engine};

#[derive(Ord, PartialOrd, Eq, PartialEq)]
pub struct XPub {
    pub public_key: PublicKey,
    pub chain_code: [u8; 32],
}

pub struct Descriptor {
    key_digest: [u8; 32],
}

impl Display for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NOTE: we need the descriptor string to be non malleable, like enforcing
        // ' as hardening indicator and enforcing fingerprint
        todo!()
    }
}

impl FromStr for Descriptor {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl Descriptor {
    pub fn xpubs(&self) -> Vec<XPub> {
        // TODO: return xpubs in descriptor order
        todo!()
    }
    pub fn recv_script_at(&self, index: u32) -> Vec<u8> {
        todo!()
    }

    pub fn policy_id(&self) -> [u8; 32] {
        let mut engine = Sha256Engine::new();
        engine.input(self.to_string().as_bytes());
        engine.hash()
    }

    pub fn compute_keys_digest(&self) -> [u8; 32] {
        let xpubs: BTreeSet<XPub> = self.xpubs().into_iter().collect();
        let mut engine = Sha256Engine::new();
        for xpub in xpubs {
            engine.input(&xpub.chain_code);
            engine.input(&xpub.public_key.raw());
        }
        engine.hash()
    }

    pub fn keys_digest(&self) -> &[u8; 32] {
        &self.key_digest
    }
}
