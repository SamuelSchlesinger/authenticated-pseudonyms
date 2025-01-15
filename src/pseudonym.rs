// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bls12_381::{Bls12, G1Affine, G1Projective, G2Affine, Scalar};
use pairing::group::ff::Field;
use pairing::group::{Group, GroupEncoding};
use pairing::Engine;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use subtle::{Choice, ConstantTimeEq, CtOption};

use std::ops::Neg;

const GLOBAL_LABEL: &[u8] = b"SOCIAL_LOGIN";
const SEPARATOR: &[u8] = b"\n";

/// Parameters for the protocol.
#[derive(Clone, Debug)]
pub struct Params {
    h: G1Affine,
}

impl Params {
    pub fn default() -> Self {
        let mut rng = ChaCha20Rng::from_seed(*blake3::hash(b"a very special string").as_bytes());
        Params {
            h: G1Projective::random(&mut rng).into(),
        }
    }
}

struct FiatShamir {
    hasher: blake3::Hasher,
}

impl FiatShamir {
    fn new(nonce: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(GLOBAL_LABEL);
        hasher.update(SEPARATOR);
        hasher.update(G1Affine::label());
        hasher.update(SEPARATOR);
        hasher.update(nonce);
        hasher.update(SEPARATOR);
        FiatShamir { hasher }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.hasher.update(SEPARATOR);
    }

    fn rng(&self) -> impl CryptoRngCore {
        ChaCha20Rng::from_seed(*self.hasher.finalize().as_bytes())
    }
}

trait HasLabel {
    fn label() -> &'static [u8];
}

impl HasLabel for G1Affine {
    fn label() -> &'static [u8] {
        b"BLS12_381"
    }
}

/// The private key of the issuer.
#[derive(Debug, Clone)]
pub struct IssuerPrivateKey {
    x: Scalar,
}

/// The public key of the issuer.
#[derive(Debug, Clone)]
pub struct IssuerPublicKey {
    w: G2Affine,
}

impl IssuerPrivateKey {
    /// Generate random private key for the issuer.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        IssuerPrivateKey {
            x: Scalar::random(&mut rng),
        }
    }

    /// Computes the public key of the issuer given the private one.
    pub fn public(&self) -> IssuerPublicKey {
        IssuerPublicKey {
            w: (G2Affine::generator() * self.x).into(),
        }
    }
}

/// A credential which the client holds privately.
#[derive(Debug, Clone)]
pub struct Credential {
    a: G1Affine,
    e: Scalar,
    k: Scalar,
}

impl Credential {
    /// Mint a brand new, random credential.
    pub fn mint(
        params: &Params,
        issuer_private_key: &IssuerPrivateKey,
        mut rng: impl CryptoRngCore,
    ) -> CtOption<Credential> {
        let k = Scalar::random(&mut rng);
        let e = Scalar::random(&mut rng);
        let a =
            (e + issuer_private_key.x).invert().map(|i| (G1Affine::generator() + params.h * k) * i);
        a.map(|a| Credential { a: a.into(), e, k })
    }

    /// Recover the credential with the given VRF key.
    pub fn recover(
        params: &Params,
        issuer_private_key: &IssuerPrivateKey,
        k: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> CtOption<Credential> {
        let e = Scalar::random(&mut rng);
        let a =
            (e + issuer_private_key.x).invert().map(|i| (G1Affine::generator() + params.h * k) * i);
        a.map(|a| Credential { a: a.into(), e, k })
    }

    /// Verify the validity of the given credential.
    pub fn verify(&self, params: &Params, issuer_public_key: &IssuerPublicKey) -> Choice {
        Bls12::pairing(&self.a, &issuer_public_key.w).ct_eq(&Bls12::pairing(
            &G1Affine::from(&self.a * self.e.neg() + G1Affine::generator() + params.h * self.k),
            &G2Affine::generator(),
        ))
    }

    pub fn vrf_key(&self) -> &Scalar {
        &self.k
    }
}

/// A local pseudonym derived for a particular context.
#[derive(Debug, Clone)]
pub struct Pseudonym {
    relying_party_id: Scalar,
    a_prime: G1Affine,
    b_bar: G1Affine,
    a_bar: G1Affine,
    y: G1Affine,
    gamma: Scalar,
    z_e: Scalar,
    z_r2: Scalar,
    z_r3: Scalar,
    z_k: Scalar,
}

impl Credential {
    /// Compute a pseudonym for the given context.
    pub fn pseudonym_for(
        &self,
        params: &Params,
        relying_party_id: Scalar,
        nonce: &[u8],
        mut rng: impl CryptoRngCore,
    ) -> CtOption<Pseudonym> {
        let mut fiat_shamir = FiatShamir::new(nonce);

        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let e_prime = Scalar::random(&mut rng);
        let r2_prime = Scalar::random(&mut rng);
        let r3_prime = Scalar::random(&mut rng);
        let k_prime = Scalar::random(&mut rng);

        let b = G1Affine::generator() + params.h * self.k;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let a_bar = a_prime * self.e.neg() + b_bar * r2;
        let r3 = r1.invert();

        fiat_shamir.update(a_prime.to_bytes().as_ref());
        fiat_shamir.update(b_bar.to_bytes().as_ref());
        fiat_shamir.update(a_bar.to_bytes().as_ref());

        let a1 = a_prime * e_prime + b_bar * r2_prime;
        let a2 = b_bar * r3_prime + params.h * k_prime;

        fiat_shamir.update(a1.to_bytes().as_ref());
        fiat_shamir.update(a2.to_bytes().as_ref());

        let y = G1Affine::generator() * (self.k + relying_party_id).invert().unwrap();

        fiat_shamir.update(y.to_bytes().as_ref());

        let y1 = y * k_prime.neg();

        fiat_shamir.update(y1.to_bytes().as_ref());

        let gamma = Scalar::random(fiat_shamir.rng());

        let z_e = gamma.neg() * self.e + e_prime;
        let z_r2 = gamma * r2 + r2_prime;
        let z_r3 = r3.map(|r3| gamma * r3 + r3_prime);
        let z_k = gamma.neg() * self.k + k_prime;

        z_r3.map(|z_r3| Pseudonym {
            relying_party_id,
            a_prime: a_prime.into(),
            b_bar: b_bar.into(),
            a_bar: a_bar.into(),
            y: y.into(),
            gamma,
            z_e,
            z_r2,
            z_r3,
            z_k,
        })
    }
}

impl Pseudonym {
    /// Verify the pseudonym's correctness.
    pub fn verify(&self, params: &Params, issuer_public_key: &IssuerPublicKey, nonce: &[u8]) -> Choice {
        let mut choice = Choice::from(1);

        choice &= !self.a_prime.ct_eq(&G1Affine::identity());
        choice &= Bls12::pairing(&self.a_prime, &issuer_public_key.w)
            .ct_eq(&Bls12::pairing(&self.a_bar, &G2Affine::generator()));

        let mut fiat_shamir = FiatShamir::new(nonce);

        fiat_shamir.update(self.a_prime.to_bytes().as_ref());
        fiat_shamir.update(self.b_bar.to_bytes().as_ref());
        fiat_shamir.update(self.a_bar.to_bytes().as_ref());

        let a1 = self.a_prime * self.z_e + self.b_bar * self.z_r2 + self.a_bar * self.gamma.neg();
        let a2 =
            self.b_bar * self.z_r3 + params.h * self.z_k + G1Affine::generator() * self.gamma.neg();

        fiat_shamir.update(a1.to_bytes().as_ref());
        fiat_shamir.update(a2.to_bytes().as_ref());

        fiat_shamir.update(self.y.to_bytes().as_ref());

        let y1 = self.y * self.z_k.neg()
            + (G1Affine::generator() - self.y * self.relying_party_id) * self.gamma.neg();

        fiat_shamir.update(y1.to_bytes().as_ref());

        let gamma = Scalar::random(fiat_shamir.rng());

        choice &= gamma.ct_eq(&self.gamma);

        choice
    }

    /// Return which relying party this pseudonym is meant for.
    pub fn relying_party_id(&self) -> &Scalar {
        &self.relying_party_id
    }

    /// Return the pseudonym ID which can be compared to other pseudonym IDs.
    pub fn pseudonym_id(&self) -> &G1Affine {
        &self.y
    }
}

#[test]
fn test() {
    for _ in 0..10 {
        use rand_core::OsRng;
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let cred1 = Credential::mint(&params, &issuer_private_key, OsRng).unwrap();
        assert!(bool::from(
            cred1.verify(&params, &issuer_private_key.public())
        ));
        let relying_party_id = Scalar::random(OsRng);
        let pseudonym1 = cred1.pseudonym_for(&params, relying_party_id, b"nonce", OsRng).unwrap();
        assert!(bool::from(
            pseudonym1.verify(&params, &issuer_private_key.public(), b"nonce")
        ));
        assert_eq!(pseudonym1.relying_party_id(), &relying_party_id);
        let vrf_key = cred1.vrf_key().clone();
        let cred2 = Credential::recover(&params, &issuer_private_key, vrf_key, OsRng).unwrap();
        assert!(bool::from(
            cred2.verify(&params, &issuer_private_key.public())
        ));
        let pseudonym2 = cred2.pseudonym_for(&params, relying_party_id, b"nonce2", OsRng).unwrap();
        assert!(bool::from(
            pseudonym2.verify(&params, &issuer_private_key.public(), b"nonce2")
        ));
        assert_eq!(pseudonym1.pseudonym_id(), pseudonym2.pseudonym_id());
    }
}
