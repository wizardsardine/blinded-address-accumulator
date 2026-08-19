pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn new(raw: &[u8; 32]) -> Self {
        todo!()
    }

    pub fn add_tweak(&self, tweak: &[u8; 32]) -> Self {
        todo!()
    }

    pub fn public_key(&self) -> PublicKey {
        todo!()
    }

    pub fn raw(&self) -> [u8; 32] {
        todo!()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey([u8; 33]);

impl PublicKey {
    pub fn add_exp_tweak(&self, tweak: &[u8; 32]) -> Self {
        todo!()
    }

    pub fn raw(&self) -> [u8; 33] {
        todo!()
    }
}

pub struct HmacEngine(Vec<u8>);

impl HmacEngine {
    pub fn new(data: &[u8]) -> Self {
        todo!()
    }
    pub fn input(&mut self, input: &[u8]) {
        todo!()
    }
    pub fn hash(&self) -> [u8; 64] {
        todo!()
    }
}

pub struct Sha256Engine(Vec<u8>);

impl Sha256Engine {
    pub fn new() -> Self {
        todo!()
    }
    pub fn new_tagged(tag: &[u8]) -> Self {
        todo!()
    }
    pub fn input(&mut self, input: &[u8]) {
        todo!()
    }
    pub fn hash(&self) -> [u8; 32] {
        todo!()
    }
}

pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    todo!()
}
