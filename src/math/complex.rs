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

use num::{rational::Ratio, BigInt};
use std::ops::{Add, Div, Mul, Sub};

/// Rational complex numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complex {
    pub a: Ratio<BigInt>,
    pub b: Ratio<BigInt>,
}

impl Complex {
    /// Returns zero.
    pub fn zero() -> Complex {
        Complex {
            a: Ratio::from(BigInt::from(0)),
            b: Ratio::from(BigInt::from(0)),
        }
    }

    /// The greatest common divisor of Gaussian integers.
    pub fn gcd(mut self, mut other: Self) -> Self {
        while other != Complex::zero() {
            let (_q, r) = self.divide_with_remainder(&other);
            self = other;
            other = r;
        }
        self
    }

    /// Given a, b, find q, r such that a = q * b + r.
    pub fn divide_with_remainder(&self, other: &Self) -> (Self, Self) {
        if other == &Complex::zero() {
            panic!("oooh why oh why");
        }
        let exact_quotient = self / other;
        let mut quotient = exact_quotient.clone();
        quotient.a = quotient.a.clone().round();
        quotient.b = quotient.b.clone().round();

        (
            quotient.clone(),
            other
                * &Complex {
                    a: exact_quotient.a - quotient.a,
                    b: exact_quotient.b - quotient.b,
                },
        )
    }
}

impl Add for &Complex {
    type Output = Complex;

    fn add(self, other: Self) -> Complex {
        Complex {
            a: &self.a + &other.a,
            b: &self.b + &other.b,
        }
    }
}

impl Mul for &Complex {
    type Output = Complex;

    fn mul(self, other: Self) -> Complex {
        Complex {
            a: &self.a * &other.a - &self.b * &other.b,
            b: &self.a * &other.b + &self.b * &other.a,
        }
    }
}

impl Sub for &Complex {
    type Output = Complex;

    fn sub(self, other: Self) -> Complex {
        Complex {
            a: &self.a - &other.a,
            b: &self.b - &other.b,
        }
    }
}

impl Div for &Complex {
    type Output = Complex;

    fn div(self, other: Self) -> Complex {
        Complex {
            a: (&self.a * &other.a + &self.b * &other.b)
                / (&other.a * &other.a + &other.b * &other.b),
            b: (&self.b * &other.a - &self.a * &other.b)
                / (&other.a * &other.a + &other.b * &other.b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config;

    prop_compose! {
        fn arb_bigint()(n: i64) -> BigInt {
            BigInt::from(n)
        }
    }

    prop_compose! {
        fn arb_ratio()(num: i64, den in 1i64..=1000) -> Ratio<BigInt> {
            Ratio::new(BigInt::from(num), BigInt::from(den))
        }
    }

    prop_compose! {
        fn arb_complex()(a in arb_ratio(), b in arb_ratio()) -> Complex {
            Complex { a, b }
        }
    }

    prop_compose! {
        fn arb_nonzero_complex()(a in arb_ratio(), b in arb_ratio()) -> Complex {
            let c = Complex { a, b };
            if c == Complex::zero() {
                Complex {
                    a: Ratio::from(BigInt::from(1)),
                    b: Ratio::from(BigInt::from(0)),
                }
            } else {
                c
            }
        }
    }

    proptest! {
        #![proptest_config(Config::with_cases(32))]
        
        #[test]
        fn test_add_commutative(a in arb_complex(), b in arb_complex()) {
            prop_assert_eq!(&a + &b, &b + &a);
        }

        #[test]
        fn test_add_associative(a in arb_complex(), b in arb_complex(), c in arb_complex()) {
            prop_assert_eq!(&(&a + &b) + &c, &a + &(&b + &c));
        }

        #[test]
        fn test_add_identity(a in arb_complex()) {
            let zero = Complex::zero();
            prop_assert_eq!(&a + &zero, a.clone());
            prop_assert_eq!(&zero + &a, a);
        }

        #[test]
        fn test_mul_commutative(a in arb_complex(), b in arb_complex()) {
            prop_assert_eq!(&a * &b, &b * &a);
        }

        #[test]
        fn test_mul_associative(a in arb_complex(), b in arb_complex(), c in arb_complex()) {
            prop_assert_eq!(&(&a * &b) * &c, &a * &(&b * &c));
        }

        #[test]
        fn test_mul_identity(a in arb_complex()) {
            let one = Complex {
                a: Ratio::from(BigInt::from(1)),
                b: Ratio::from(BigInt::from(0)),
            };
            prop_assert_eq!(&a * &one, a.clone());
            prop_assert_eq!(&one * &a, a);
        }

        #[test]
        fn test_distributive(a in arb_complex(), b in arb_complex(), c in arb_complex()) {
            prop_assert_eq!(&a * &(&b + &c), &(&a * &b) + &(&a * &c));
        }

        #[test]
        fn test_sub_inverse_add(a in arb_complex(), b in arb_complex()) {
            prop_assert_eq!(&(&a + &b) - &b, a);
        }

        #[test]
        fn test_div_inverse_mul(a in arb_complex(), b in arb_nonzero_complex()) {
            let result = &(&a * &b) / &b;
            let epsilon = Ratio::from(BigInt::from(1)) / Ratio::from(BigInt::from(1000000));
            let diff_a = if result.a > a.a { result.a - &a.a } else { &a.a - result.a };
            let diff_b = if result.b > a.b { result.b - &a.b } else { &a.b - result.b };
            prop_assert!(diff_a < epsilon);
            prop_assert!(diff_b < epsilon);
        }

        #[test]
        fn test_gcd_divides_both(a in arb_complex(), b in arb_complex()) {
            if a == Complex::zero() && b == Complex::zero() {
                return Ok(());
            }
            let gcd = a.clone().gcd(b.clone());
            if gcd != Complex::zero() {
                let (_q1, r1) = a.divide_with_remainder(&gcd);
                let (_q2, r2) = b.divide_with_remainder(&gcd);
                prop_assert_eq!(r1, Complex::zero());
                prop_assert_eq!(r2, Complex::zero());
            }
        }

        #[test]
        fn test_divide_with_remainder_property(a in arb_complex(), b in arb_nonzero_complex()) {
            let (q, r) = a.divide_with_remainder(&b);
            let reconstructed = &(&q * &b) + &r;
            let epsilon = Ratio::from(BigInt::from(1)) / Ratio::from(BigInt::from(1000));
            let diff_a = if reconstructed.a > a.a { reconstructed.a - &a.a } else { &a.a - reconstructed.a };
            let diff_b = if reconstructed.b > a.b { reconstructed.b - &a.b } else { &a.b - reconstructed.b };
            prop_assert!(diff_a < epsilon);
            prop_assert!(diff_b < epsilon);
        }

        #[test]
        fn test_zero_properties(a in arb_complex()) {
            let zero = Complex::zero();
            prop_assert_eq!(&a + &zero, a.clone());
            prop_assert_eq!(&a * &zero, zero.clone());
            prop_assert_eq!(&a - &a, zero);
        }
    }
}
