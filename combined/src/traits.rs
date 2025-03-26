#[cfg(test)]
use sha2::{Digest, Sha256};

pub trait Hasher: Default {
    fn update(&mut self, bytes: &[u8]);
    fn finalize(&self) -> [u8; 32];
}

#[cfg(test)]
impl Hasher for Sha256 {
    fn update(&mut self, bytes: &[u8]) {
        <Sha256 as Digest>::update(self, bytes);
    }

    fn finalize(&self) -> [u8; 32] {
        <Sha256 as Digest>::finalize(self.clone()).into()
    }
}
