use std::{collections::BTreeSet, fmt::Display, str::FromStr};

use crate::crypto::{Crypto, Sha256Engine};

pub trait XpubImpl: Ord {
    fn public_key(&self) -> [u8; 33];
    fn chain_code(&self) -> [u8; 32];
}

pub trait DescriptorImpl: Display + FromStr {
    type Xpub: XpubImpl;

    fn xpubs(&self) -> Vec<Self::Xpub>;
    fn recv_script_at(&self, index: u32) -> Vec<u8>;
    fn bytes(&self) -> Vec<u8>;

    fn policy_id<C: Crypto>(&self) -> [u8; 32] {
        let mut engine = C::Sha256Engine::new();
        engine.input(&self.bytes());
        engine.hash()
    }

    fn keys_digest<C: Crypto>(&self) -> [u8; 32] {
        let xpubs: BTreeSet<Self::Xpub> = self.xpubs().into_iter().collect();
        let mut engine = C::Sha256Engine::new();
        for xpub in xpubs {
            engine.input(&xpub.chain_code());
            engine.input(&xpub.public_key());
        }
        engine.hash()
    }
}
