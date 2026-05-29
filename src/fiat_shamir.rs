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

//! Shared Fiat-Shamir challenge-derivation primitives.
//!
//! These helpers operate purely on the *finalized* SHA-256 transcript digest.
//! They deliberately do NOT touch how the transcript itself is constructed
//! (domain-separation labels, separators, field ordering), which differs
//! between modules and which defines the exact bytes that are hashed. Each
//! module keeps its own `FiatShamir::new`/`update` so that no transcript byte
//! changes; only the (byte-identical across modules) step of turning the final
//! digest into a challenge is shared here.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};

/// Seed a ChaCha20 RNG from a finalized 32-byte transcript digest.
///
/// The returned RNG is used to sample challenge scalars via `Scalar::random`.
/// Equivalent to the previous per-module `FiatShamir::rng` implementations.
pub(crate) fn rng_from_digest(hash_result: [u8; 32]) -> impl CryptoRngCore {
    ChaCha20Rng::from_seed(hash_result)
}

/// Reduce a finalized 32-byte transcript digest (interpreted little-endian)
/// modulo the challenge bound `c`.
///
/// Used by the range-proof modules to derive the Fiat-Shamir challenge as an
/// integer in `[0, c)`. Equivalent to the previous per-module
/// `FiatShamir::rph` implementations.
#[cfg(any(feature = "public_range", feature = "private_range"))]
pub(crate) fn reduce_digest_mod(hash_result: [u8; 32], c: u128) -> num::BigUint {
    num::BigUint::from_bytes_le(&hash_result) % num::BigUint::from(c)
}
