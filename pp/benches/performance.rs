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

use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::Scalar as RScalar;
use num::BigUint;
use sha2::Digest;
use private_proofs_crypto::traits::{RngCore, CryptoRngCore, ChaCha20Rng, RandomBitsExt};

pub struct Sha256(sha2::Sha256);

impl Default for Sha256 {
    fn default() -> Self {
        Sha256(Default::default())
    }
}

impl digest::Digest for Sha256 {
    type OutputSize = digest::consts::U32;

    fn new() -> Self {
        Self::default()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        <sha2::Sha256 as Digest>::update(&mut self.0, data);
    }

    fn finalize(self) -> digest::Output<Self> {
        <sha2::Sha256 as Digest>::finalize(self.0).into()
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn finalize_into(self, out: &mut digest::Output<Self>) {
        let result = <sha2::Sha256 as Digest>::finalize(self.0);
        out.copy_from_slice(&result);
    }

    fn finalize_reset(&mut self) -> digest::Output<Self> {
        let result = <sha2::Sha256 as Digest>::finalize_reset(&mut self.0);
        result.into()
    }

    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        let result = <sha2::Sha256 as Digest>::finalize_reset(&mut self.0);
        out.copy_from_slice(&result);
    }

    fn digest(data: impl AsRef<[u8]>) -> digest::Output<Self> {
        <sha2::Sha256 as Digest>::digest(data).into()
    }
}

fn chacha_rng() -> ChaCha20Rng {
    // Create a seed using a fixed value for testing
    let seed = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    ChaCha20Rng::from_seed(seed)
}

fn criterion_benchmark(c: &mut Criterion) {
    private_benchmark(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

fn private_benchmark(c: &mut Criterion) {
    use private_proofs_crypto::*;
    let mut rng = chacha_rng();
    let issuer_private_key = IssuerPrivateKey::random(&mut rng);
    let client_private_key = ClientPrivateKey::random(&mut rng);
    let issuer_public_key = issuer_private_key.public();
    let params: Params<Sha256> = Params::default();
    c.bench_function("private::issuance", {
        let issuer_private_key = issuer_private_key.clone();
        let client_private_key = client_private_key.clone();
        let issuer_public_key = issuer_public_key.clone();
        let params: Params<Sha256> = Params::default();
        move |b| {
            let setup = || {
                let mut rng = chacha_rng();
                let bound = rng.gen_biguint(30);
                let bound: BigUint = bound % BigUint::from(MAX_RANGE_PROOF_BOUND);
                let message = rng.gen_biguint(30);
                let message: BigUint = message % &bound;
                (
                    rng,
                    bigint_to_rscalar(&message).unwrap(),
                    bigint_to_rscalar(&bound).unwrap(),
                )
            };
            let routine = |(mut rng, message, _bound)| {
                let req = client_private_key.credential_request(&params, &mut rng);
                let resp = req
                    .respond(
                        &issuer_private_key,
                        &issuer_public_key,
                        &params,
                        message,
                        &mut rng,
                    )
                    .unwrap();
                let cred = client_private_key
                    .create_credential(&params, &req, &resp, &issuer_public_key)
                    .unwrap();
            };
            b.iter_batched(setup, routine, criterion::BatchSize::SmallInput);
        }
    });
    c.bench_function("private::proof", {
        let issuer_private_key = issuer_private_key.clone();
        let client_private_key = client_private_key.clone();
        let issuer_public_key = issuer_public_key.clone();
        let params: Params<Sha256> = Params::default();
        move |b| {
            let setup = || {
                use rand_core::RngCore;
                let mut rng = chacha_rng();
                let bound: u64 = rng.next_u64();
                let bound: u64 = bound % MAX_RANGE_PROOF_BOUND;
                let message: u64 = rng.next_u64();
                let message: u64 = message % &bound;
                let req = client_private_key.credential_request(&params, &mut rng);
                let resp = req
                    .respond(
                        &issuer_private_key,
                        &issuer_public_key,
                        &params,
                        RScalar::from(message),
                        &mut rng,
                    )
                    .unwrap();
                let cred = client_private_key
                    .create_credential(&params, &req, &resp, &issuer_public_key)
                    .unwrap();
                (rng, bound, cred)
            };
            let routine = |(mut rng, bound, cred): (ChaCha20Rng, u64, Credential)| {
                let epoch = 5;
                let rate_limit_exponent = 15;
                let i = 35;
                cred.prove(&params, bound, epoch, &mut rng, rate_limit_exponent, i)
                    .unwrap();
            };
            b.iter_batched(setup, routine, criterion::BatchSize::SmallInput);
        }
    });
    c.bench_function("private::verify", {
        let issuer_private_key = issuer_private_key.clone();
        let client_private_key = client_private_key.clone();
        let issuer_public_key = issuer_public_key.clone();
        let params: Params<Sha256> = Params::default();
        move |b| {
            let setup = || {
                use rand_core::RngCore;
                let mut rng = chacha_rng();
                let bound: u64 = rng.next_u64();
                let bound: u64 = bound % MAX_RANGE_PROOF_BOUND;
                let message: u64 = rng.next_u64();
                let message: u64 = message % &bound;
                let req = client_private_key.credential_request(&params, &mut rng);
                let resp = req
                    .respond(
                        &issuer_private_key,
                        &issuer_public_key,
                        &params,
                        RScalar::from(message),
                        &mut rng,
                    )
                    .unwrap();
                let cred = client_private_key
                    .create_credential(&params, &req, &resp, &issuer_public_key)
                    .unwrap();
                let epoch = 5;
                let rate_limit_exponent = 15;
                let i = 35;
                let proof = cred
                    .prove(&params, bound, epoch, &mut rng, rate_limit_exponent, i)
                    .unwrap();
                (rng, bound, proof)
            };
            let routine = |(mut rng, bound, pf): (ChaCha20Rng, u64, Proof)| {
                let _ = pf.verify(&params, &issuer_private_key);
            };
            b.iter_batched(setup, routine, criterion::BatchSize::SmallInput);
        }
    });
}

fn rscalar_to_bigint(s: &RScalar) -> BigUint {
    BigUint::from_bytes_le(s.as_bytes())
}

fn bigint_to_rscalar(b: &BigUint) -> Option<RScalar> {
    use std::ops::Neg;
    let q = rscalar_to_bigint(&(RScalar::ONE.neg())) + BigUint::from(1u64);
    if b >= &q {
        return None;
    }
    let b_bs = b.to_bytes_le();
    let mut s_bs = [0u8; 32];
    for i in 0..32 {
        if i >= b_bs.len() {
            break;
        }
        s_bs[i] = b_bs[i];
    }

    Some(RScalar::from_bytes_mod_order(s_bs))
}
