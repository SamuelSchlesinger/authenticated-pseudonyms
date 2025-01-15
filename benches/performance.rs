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

use bls12_381::Scalar as BLSScalar;
use criterion::{criterion_group, criterion_main, Criterion};
use curve25519_dalek::Scalar as RScalar;
use num::{bigint::RandomBits, BigUint};
use rand::distributions::Distribution;
use rand::thread_rng;
use rand::Fill;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn chacha_rng() -> ChaCha20Rng {
    let mut rng = thread_rng();
    let mut seed = [0u8; 32];
    seed.try_fill(&mut rng).unwrap();
    ChaCha20Rng::from_seed(seed)
}

fn criterion_benchmark(c: &mut Criterion) {
    public_benchmark(c);
    private_benchmark(c);
}

fn public_benchmark(c: &mut Criterion) {
    use authenticated_pseudonyms::public::*;
    let mut rng = chacha_rng();
    let issuer_private_key = IssuerPrivateKey::random(&mut rng);
    let client_private_key = ClientPrivateKey::random(&mut rng);
    let issuer_public_key = issuer_private_key.public();
    let params: Params = Params::default();
    c.bench_function("public::issuance", {
        let issuer_private_key = issuer_private_key.clone();
        let client_private_key = client_private_key.clone();
        let issuer_public_key = issuer_public_key.clone();
        let params = params.clone();
        move |b| {
            let setup = || {
                let mut rng = chacha_rng();
                let bound: BigUint = RandomBits::new(30).sample(&mut rng);
                let bound: BigUint = bound % BigUint::from(MAX_RANGE_PROOF_BOUND);
                let message: BigUint = RandomBits::new(30).sample(&mut rng);
                let message: BigUint = message % &bound;
                (
                    rng,
                    bigint_to_blsscalar(&message).unwrap(),
                    bigint_to_blsscalar(&bound).unwrap(),
                )
            };
            let routine = |(mut rng, message, _bound)| {
                let req = client_private_key.credential_request(&params, &mut rng);
                let resp = req
                    .respond(&issuer_private_key, &params, message, &mut rng)
                    .unwrap();
                let cred = client_private_key
                    .create_credential(&params, &req, &resp, &issuer_public_key)
                    .unwrap();
            };
            b.iter_batched(setup, routine, criterion::BatchSize::SmallInput);
        }
    });
    c.bench_function("public::proof", {
        let issuer_private_key = issuer_private_key.clone();
        let client_private_key = client_private_key.clone();
        let issuer_public_key = issuer_public_key.clone();
        let params = params.clone();
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
                        &params,
                        BLSScalar::from(message),
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
    c.bench_function("public::verify", {
        let issuer_private_key = issuer_private_key.clone();
        let client_private_key = client_private_key.clone();
        let issuer_public_key = issuer_public_key.clone();
        let params = params.clone();
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
                        &params,
                        BLSScalar::from(message),
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
                let _ = pf.verify(&params, &issuer_public_key);
            };
            b.iter_batched(setup, routine, criterion::BatchSize::SmallInput);
        }
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

fn private_benchmark(c: &mut Criterion) {
    use authenticated_pseudonyms::private::*;
    let mut rng = chacha_rng();
    let issuer_private_key = IssuerPrivateKey::random(&mut rng);
    let client_private_key = ClientPrivateKey::random(&mut rng);
    let issuer_public_key = issuer_private_key.public();
    let params: Params = Params::default();
    c.bench_function("private::issuance", {
        let issuer_private_key = issuer_private_key.clone();
        let client_private_key = client_private_key.clone();
        let issuer_public_key = issuer_public_key.clone();
        let params = params.clone();
        move |b| {
            let setup = || {
                let mut rng = chacha_rng();
                let bound: BigUint = RandomBits::new(30).sample(&mut rng);
                let bound: BigUint = bound % BigUint::from(MAX_RANGE_PROOF_BOUND);
                let message: BigUint = RandomBits::new(30).sample(&mut rng);
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
        let params = params.clone();
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
        let params = params.clone();
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

fn blsscalar_to_bigint(scalar: &BLSScalar) -> BigUint {
    BigUint::from_bytes_le(&scalar.to_bytes())
}

fn bigint_to_blsscalar(b: &BigUint) -> Option<BLSScalar> {
    let q = blsscalar_to_bigint(&(BLSScalar::zero() - BLSScalar::one())) + BigUint::from(1u64);
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
    Some(BLSScalar::from_bytes(&s_bs).unwrap())
}
