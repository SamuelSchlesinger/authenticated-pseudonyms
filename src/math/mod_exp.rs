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

use num::BigInt;

/// Efficient modular exponentiation algorithm.
pub fn mod_exp(x: BigInt, y: BigInt, p: BigInt) -> BigInt {
    if p == BigInt::from(1) {
        return BigInt::from(0);
    }
    let mut result = BigInt::from(1);
    let mut base = ((x % &p) + &p) % &p;
    let mut exponent = y;
    while exponent > BigInt::from(0) {
        if &exponent % 2 == BigInt::from(1) {
            result = (result * &base) % &p;
        }
        exponent = exponent >> 1;
        base = (&base * &base) % &p;
    }
    result
}

#[test]
fn test_mod_exp() {
    assert_eq!(
        mod_exp(BigInt::from(5), BigInt::from(2), BigInt::from(25)),
        BigInt::from(0)
    );
    assert_eq!(
        mod_exp(BigInt::from(2), BigInt::from(8), BigInt::from(10)),
        BigInt::from(6)
    );
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_positive_bigint()(n: u64) -> BigInt {
            BigInt::from(n + 1)
        }
    }

    prop_compose! {
        fn arb_nonneg_bigint()(n: u64) -> BigInt {
            BigInt::from(n)
        }
    }

    prop_compose! {
        fn arb_small_positive()(n in 1u32..100) -> BigInt {
            BigInt::from(n)
        }
    }

    #[test]
    fn test_mod_exp_mod_one() {
        let result = mod_exp(BigInt::from(42), BigInt::from(100), BigInt::from(1));
        assert_eq!(result, BigInt::from(0));
    }

    proptest! {
        #[test]
        fn test_mod_exp_identity_prop(x in arb_nonneg_bigint(), p in arb_positive_bigint()) {
            let result = mod_exp(x.clone(), BigInt::from(0), p.clone());
            if p == BigInt::from(1) {
                prop_assert_eq!(result, BigInt::from(0));
            } else {
                prop_assert_eq!(result, BigInt::from(1));
            }
        }

        #[test]
        fn test_mod_exp_one_exponent(x in arb_nonneg_bigint(), p in arb_positive_bigint()) {
            let result = mod_exp(x.clone(), BigInt::from(1), p.clone());
            prop_assert_eq!(result, x % p);
        }

        #[test]
        fn test_mod_exp_zero_base(y in arb_nonneg_bigint(), p in arb_positive_bigint()) {
            if y == BigInt::from(0) && p != BigInt::from(1) {
                let result = mod_exp(BigInt::from(0), y, p);
                prop_assert_eq!(result, BigInt::from(1));
            } else if y > BigInt::from(0) {
                let result = mod_exp(BigInt::from(0), y, p);
                prop_assert_eq!(result, BigInt::from(0));
            }
        }

        #[test]
        fn test_mod_exp_small_cases(x in 0u32..10, y in 0u32..10, p in 1u32..20) {
            let x_big = BigInt::from(x);
            let y_big = BigInt::from(y);
            let p_big = BigInt::from(p);
            
            let result = mod_exp(x_big.clone(), y_big.clone(), p_big.clone());
            
            let mut expected = BigInt::from(1);
            for _ in 0..y {
                expected = (expected * &x_big) % &p_big;
            }
            
            if p == 1 {
                // Everything mod 1 is 0
                prop_assert_eq!(result, BigInt::from(0));
            } else {
                prop_assert_eq!(result, expected);
            }
        }

        #[test]
        fn test_mod_exp_power_rule(x in arb_small_positive(), a in 0u32..10, b in 0u32..10, p in arb_small_positive()) {
            let a_big = BigInt::from(a);
            let b_big = BigInt::from(b);
            
            let result1 = mod_exp(x.clone(), &a_big + &b_big, p.clone());
            let result2 = (mod_exp(x.clone(), a_big, p.clone()) * mod_exp(x, b_big, p.clone())) % &p;
            
            prop_assert_eq!(result1, result2);
        }

        #[test]
        fn test_mod_exp_fermats_little_theorem(a in 1u32..100) {
            let primes = vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31];
            for p in primes {
                if a % p != 0 {
                    let a_big = BigInt::from(a);
                    let p_big = BigInt::from(p);
                    let result = mod_exp(a_big, p_big.clone() - 1, p_big);
                    prop_assert_eq!(result, BigInt::from(1));
                }
            }
        }

        #[test]
        fn test_mod_exp_negative_handling(x: i64, y in arb_nonneg_bigint(), p in arb_positive_bigint()) {
            let x_big = BigInt::from(x);
            let x_mod = ((x_big.clone() % &p) + &p) % &p;
            let result = mod_exp(x_big, y.clone(), p.clone());
            let expected = mod_exp(x_mod, y, p);
            prop_assert_eq!(result, expected);
        }

        #[test]
        fn test_mod_exp_large_exponent(x in 1u32..10, p in 2u32..100) {
            let x_big = BigInt::from(x);
            let p_big = BigInt::from(p);
            let large_exp = BigInt::from(1000u32);
            
            let result = mod_exp(x_big, large_exp, p_big.clone());
            prop_assert!(result >= BigInt::from(0));
            prop_assert!(result < p_big);
        }

        #[test]
        fn test_mod_exp_commutativity_of_mod(x in arb_small_positive(), y in arb_small_positive(), p in arb_small_positive()) {
            let result1 = mod_exp(x.clone() % &p, y.clone(), p.clone());
            let result2 = mod_exp(x, y, p);
            prop_assert_eq!(result1, result2);
        }
    }
}
