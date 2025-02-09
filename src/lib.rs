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

//! # Authenticated Pseudonyms
//!
//! Often, one wants to communicate authentication without identity. In these circumstances,
//! one can authenticate a pseudonym scoped by a label for each different context in which one
//! needs to authenticate unlinkably.

#[cfg(any(feature = "private_range", feature = "public_range"))]
pub(crate) mod math;

/// Rate limited range proofs, which can be used for proofs of various types of ages.
#[cfg(any(feature = "private_range", feature = "public_range"))]
pub mod age {
    /// Authenticated pseudonyms where the relying party must be the issuer. This is useful in internal
    /// authentication systems within a single entity.
    #[cfg(feature = "private_range")]
    pub mod private;

    /// Authenticated pseudonyms where the relying party can be anyone. This is useful for interlocking
    /// systems of authentication, where one party may give permission to access the resources of
    /// another.
    #[cfg(feature = "public_range")]
    pub mod public;
}

/// Local pseudonyms, linkable by the issuer but not by relying parties alone.
#[cfg(feature = "pseudonym")]
pub mod pseudonym;

/// Local pseudonyms, fully unlinkable.
#[cfg(feature = "unlinkable_pseudonym")]
pub mod unlinkable_pseudonym;
