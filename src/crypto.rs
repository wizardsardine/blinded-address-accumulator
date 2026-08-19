pub trait Crypto {
    type HmacEngine: HmacEngine;
    type Sha256Engine: Sha256Engine;
}

pub trait HmacEngine {
    fn new(data: &[u8]) -> Self;
    fn input(&mut self, input: &[u8]);
    fn hash(&self) -> [u8; 64];
}

pub trait Sha256Engine {
    fn new() -> Self;
    fn new_tagged(tag: &[u8]) -> Self;
    fn input(&mut self, input: &[u8]);
    fn hash(&self) -> [u8; 32];
}

pub trait PublicKey: Ord {
    fn raw(&self) -> [u8; 33];
}

pub trait SecretKey {
    type PublicKey: PublicKey;

    fn add_tweak(&self, tweak: &[u8; 32]) -> Self;
    fn public_key(&self) -> Self::PublicKey;
    fn raw(&self) -> [u8; 32];
}
