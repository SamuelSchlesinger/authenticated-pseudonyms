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

use num::{BigInt, BigUint};

/// An RNG core trait similar to rand_core's RngCore, but implemented within our library
pub trait RngCore {
    /// Fill the given buffer with random bytes
    fn fill_bytes(&mut self, dest: &mut [u8]);
    
    /// Try to fill the given buffer with random bytes
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
    
    /// Generate a random u32
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }
    
    /// Generate a random u64
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}

/// A simple error type for our RNG operations
#[derive(Debug)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RNG error")
    }
}

impl std::error::Error for Error {}

/// A trait for cryptographically secure random number generators
pub trait CryptoRngCore: RngCore {}

/// Extension trait for RngCore to provide methods for generating random BigInt values
pub trait RandomBigIntExt: RngCore {
    /// Generate a random BigInt with the specified number of bits
    fn gen_bigint(&mut self, bits: u64) -> BigInt {
        use num::bigint::Sign;
        
        if bits == 0 {
            return BigInt::from(0u64);
        }
        
        let num_bytes = ((bits + 7) / 8) as usize;
        let mut bytes = vec![0u8; num_bytes];
        self.fill_bytes(&mut bytes);
        
        // Set the most significant bit
        let extra_bits = bits % 8;
        if extra_bits != 0 {
            bytes[0] &= 0xFF >> (8 - extra_bits);
        }
        
        // Ensure the highest bit is set
        if bits > 0 {
            let highest_byte_index = if extra_bits == 0 { 0 } else { 0 };
            let highest_bit_mask = if extra_bits == 0 { 0x80 } else { 1 << (extra_bits - 1) };
            bytes[highest_byte_index] |= highest_bit_mask;
        }
        
        BigInt::from_bytes_le(Sign::Plus, &bytes)
    }
    
    /// Generate a random BigUint with the specified number of bits
    fn gen_biguint(&mut self, bits: u64) -> BigUint {
        BigUint::from_bytes_le(&self.gen_bigint(bits).to_bytes_le().1)
    }
}

// Implement RandomBigIntExt for anything that implements RngCore
impl<R: RngCore + ?Sized> RandomBigIntExt for R {}

/// A ChaCha20 RNG implementation that's compatible with our custom traits
pub struct ChaCha20Rng {
    state: [u32; 16],
    buffer: [u8; 64],
    buffer_index: usize,
}

impl ChaCha20Rng {
    /// Create a new ChaCha20Rng from a 32-byte seed
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut state = [0u32; 16];
        
        // "expand 32-byte k" in little-endian
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Add seed to state
        for i in 0..8 {
            state[i + 4] = u32::from_le_bytes([
                seed[i * 4],
                seed[i * 4 + 1],
                seed[i * 4 + 2],
                seed[i * 4 + 3],
            ]);
        }
        
        // Set counter to 0
        state[12] = 0;
        state[13] = 0;
        
        // Add nonce (set to 0)
        state[14] = 0;
        state[15] = 0;
        
        let mut rng = Self {
            state,
            buffer: [0u8; 64],
            buffer_index: 64, // Start with empty buffer
        };
        
        // Generate initial buffer
        rng.refill_buffer();
        
        rng
    }
    
    fn refill_buffer(&mut self) {
        let mut state = self.state;
        
        // ChaCha20 block function to fill the buffer
        for _ in 0..10 {
            // Column round
            self.quarter_round(0, 4, 8, 12, &mut state);
            self.quarter_round(1, 5, 9, 13, &mut state);
            self.quarter_round(2, 6, 10, 14, &mut state);
            self.quarter_round(3, 7, 11, 15, &mut state);
            
            // Diagonal round
            self.quarter_round(0, 5, 10, 15, &mut state);
            self.quarter_round(1, 6, 11, 12, &mut state);
            self.quarter_round(2, 7, 8, 13, &mut state);
            self.quarter_round(3, 4, 9, 14, &mut state);
        }
        
        // Add the original state to the result
        for i in 0..16 {
            state[i] = state[i].wrapping_add(self.state[i]);
        }
        
        // Convert state to bytes
        for i in 0..16 {
            let bytes = state[i].to_le_bytes();
            for j in 0..4 {
                self.buffer[i * 4 + j] = bytes[j];
            }
        }
        
        // Update counter
        let counter = u64::from(self.state[13]) << 32 | u64::from(self.state[12]);
        let new_counter = counter.wrapping_add(1);
        self.state[12] = new_counter as u32;
        self.state[13] = (new_counter >> 32) as u32;
        
        self.buffer_index = 0;
    }
    
    fn quarter_round(&self, a: usize, b: usize, c: usize, d: usize, state: &mut [u32; 16]) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = state[d] ^ state[a];
        state[d] = state[d].rotate_left(16);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = state[b] ^ state[c];
        state[b] = state[b].rotate_left(12);
        
        state[a] = state[a].wrapping_add(state[b]);
        state[d] = state[d] ^ state[a];
        state[d] = state[d].rotate_left(8);
        
        state[c] = state[c].wrapping_add(state[d]);
        state[b] = state[b] ^ state[c];
        state[b] = state[b].rotate_left(7);
    }
}

impl RngCore for ChaCha20Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut remaining = dest;
        
        while !remaining.is_empty() {
            // If the buffer is empty, refill it
            if self.buffer_index >= 64 {
                self.refill_buffer();
            }
            
            // Copy bytes from buffer to destination
            let available = 64 - self.buffer_index;
            let to_copy = std::cmp::min(available, remaining.len());
            
            remaining[..to_copy].copy_from_slice(&self.buffer[self.buffer_index..self.buffer_index + to_copy]);
            
            self.buffer_index += to_copy;
            remaining = &mut remaining[to_copy..];
        }
    }
}

impl CryptoRngCore for ChaCha20Rng {}

// An adapter to make our RngCore types work with curve25519-dalek
pub struct CurveRng<R: CryptoRngCore>(pub R);

impl CurveRng<ChaCha20Rng> {
    pub fn new(seed: [u8; 32]) -> Self {
        CurveRng(ChaCha20Rng::from_seed(seed))
    }
}

// We can't directly implement curve25519_dalek's RngCore trait since we don't have access to it
// Instead, we'll just provide a simple wrapper that implements our own RngCore trait
impl<R: CryptoRngCore> RngCore for CurveRng<R> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl<R: CryptoRngCore> CryptoRngCore for CurveRng<R> {}