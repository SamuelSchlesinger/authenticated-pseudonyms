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

use num::{rational::Ratio, traits::Euclid, BigInt};
use std::ops::{Add, Mul, Neg, Sub};

#[cfg(test)]
use proptest::prelude::*;

/// Rational quaternions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Quaternion {
    pub a: Ratio<BigInt>,
    pub b: Ratio<BigInt>,
    pub c: Ratio<BigInt>,
    pub d: Ratio<BigInt>,
}

impl Quaternion {
    /// Returns the zero quaternion.
    pub fn zero() -> Quaternion {
        Quaternion {
            a: Ratio::from(BigInt::from(0)),
            b: Ratio::from(BigInt::from(0)),
            c: Ratio::from(BigInt::from(0)),
            d: Ratio::from(BigInt::from(0)),
        }
    }
}

#[test]
fn test_division() {
    let a = Quaternion {
        a: BigInt::from(1).into(),
        b: BigInt::from(2).into(),
        c: BigInt::from(3).into(),
        d: BigInt::from(4).into(),
    };
    assert!(a.is_hurwitz());
    let one_half = Ratio::new_raw(BigInt::from(1), BigInt::from(2));
    let b = Quaternion {
        a: Ratio::from(BigInt::from(5)) + &one_half,
        b: Ratio::from(BigInt::from(6)) + &one_half,
        c: Ratio::from(BigInt::from(7)) + &one_half,
        d: Ratio::from(BigInt::from(8)) + &one_half,
    };
    assert!(b.is_hurwitz());
    let (q, r) = a.divide_with_remainder(&b);
    assert!(q.is_hurwitz());
    assert!(r.is_hurwitz());
    assert_eq!(&(&q * &b) + &r, a);
    let (q, r) = b.divide_with_remainder(&a);
    assert!(q.is_hurwitz());
    assert!(r.is_hurwitz());
    assert_eq!(&(&q * &a) + &r, b);
}

#[test]
fn test_gcrd() {
    let a = Quaternion {
        a: BigInt::from(1).into(),
        b: BigInt::from(2).into(),
        c: BigInt::from(3).into(),
        d: BigInt::from(4).into(),
    };
    assert!(a.is_hurwitz());
    let one_half = Ratio::new_raw(BigInt::from(1), BigInt::from(2));
    let b = Quaternion {
        a: Ratio::from(BigInt::from(5)) + &one_half,
        b: Ratio::from(BigInt::from(6)) + &one_half,
        c: Ratio::from(BigInt::from(7)) + &one_half,
        d: Ratio::from(BigInt::from(8)) + &one_half,
    };
    assert_eq!(
        a.clone().divide_with_remainder(&a.gcrd(b)).1,
        Quaternion::zero()
    );
}

impl Quaternion {
    /// Multiply by self e times.
    pub fn pow(&self, mut e: usize) -> Quaternion {
        let mut result = Quaternion {
            a: BigInt::from(1).into(),
            b: BigInt::from(0).into(),
            c: BigInt::from(0).into(),
            d: BigInt::from(0).into(),
        };
        while e != 0 {
            result = &result * &self;
            e -= 1;
        }
        result
    }

    /// Conjugates the given Quaternion by flipping the sign of the b, c, d coordinates.
    pub fn conjugate(&self) -> Self {
        Self {
            a: self.a.clone(),
            b: self.b.clone().neg(),
            c: self.c.clone().neg(),
            d: self.d.clone().neg(),
        }
    }

    /// Map each coordinate with the same function, useful for scaling for Lagrange Decomposition.
    pub fn scale(mut self, mut f: impl FnMut(Ratio<BigInt>) -> Ratio<BigInt>) -> Quaternion {
        self.a = f(self.a);
        self.b = f(self.b);
        self.c = f(self.c);
        self.d = f(self.d);
        self
    }

    /// Normalize a Hurwitz quaternion with half-integer coordinates into one with integer ones by
    /// multiplying by a particular unit.
    pub fn normalize_hurwitz(&self) -> Quaternion {
        assert!(self.is_hurwitz());
        if self.a.is_integer() {
            return self.clone();
        }
        let c = self.conjugate().scale(|x| x * BigInt::from(2));
        let f = |x: BigInt| {
            if x.clone().rem_euclid(&BigInt::from(4)) == BigInt::from(3) {
                Ratio::from(BigInt::from(-1))
            } else if x.clone().rem_euclid(&BigInt::from(4)) == BigInt::from(1) {
                Ratio::from(BigInt::from(1))
            } else {
                panic!("should be impossible");
            }
        };
        let e = Quaternion {
            a: f(c.a.to_integer()),
            b: f(c.b.to_integer()),
            c: f(c.c.to_integer()),
            d: f(c.d.to_integer()),
        }
        .scale(|x| x / BigInt::from(2));

        self * &e
    }

    /// Hurwitz quaternions have either fully integer coefficients or fully half-integer
    /// coefficients.
    pub fn is_hurwitz(&self) -> bool {
        let one_half = Ratio::new_raw(BigInt::from(1), BigInt::from(2));
        ((&self.a + &one_half).is_integer()
            && (&self.b + &one_half).is_integer()
            && (&self.c + &one_half).is_integer()
            && (&self.d + &one_half).is_integer())
            || (self.a.is_integer()
                && self.b.is_integer()
                && self.c.is_integer()
                && self.d.is_integer())
    }

    /// Snap to the nearest Hurwitz by rounding.
    pub fn nearest_hurwitz(&self) -> Quaternion {
        // either all going to snap to the nearest half integer or all going to snap to the nearest
        // integer
        let integer_candidate = Quaternion {
            a: self.a.round(),
            b: self.b.round(),
            c: self.c.round(),
            d: self.d.round(),
        };
        let one_half: Ratio<BigInt> = Ratio::new_raw(BigInt::from(1), BigInt::from(2));
        let half_integer_candidate = Quaternion {
            a: (&self.a + &one_half).round() - &one_half,
            b: (&self.b + &one_half).round() - &one_half,
            c: (&self.c + &one_half).round() - &one_half,
            d: (&self.d + &one_half).round() - &one_half,
        };
        let v_i = self - &integer_candidate;
        let v_h = self - &half_integer_candidate;
        if v_i.norm() < v_h.norm() {
            integer_candidate
        } else {
            half_integer_candidate
        }
    }

    /// The norm is defined by multiplying by the conjugate
    /// and is equal to the dot product of the quaternions thought of as vectors.
    pub fn norm(&self) -> Ratio<BigInt> {
        &self.a * &self.a + &self.b * &self.b + &self.c * &self.c + &self.d * &self.d
    }

    /// Greatest common right divisor between a and b is (one of) the largest c such that c divides a and b.
    pub fn gcrd(mut self, mut other: Self) -> Self {
        while other != Quaternion::zero() {
            let (_q, r) = self.divide_with_remainder(&other);
            self = other;
            other = r;
            assert!(self.is_hurwitz());
            assert!(other.is_hurwitz());
        }
        self
    }

    /// Here, exact, rational quaternion inverse is computed by dividing the conjugate by the norm.
    /// We then multiply by the inverse for exact division, then round for the quotient and subtract to get the remainder. The quotient is in the left hand of the tuple and the remainder in the right.
    pub fn divide_with_remainder(&self, other: &Self) -> (Self, Self) {
        if other == &Quaternion::zero() {
            panic!("whhhhyyyy u do this");
        }
        let mut quotient = self * &other.conjugate();
        let norm = other.norm();
        // divide by norm and round to nearest half integer
        quotient.a /= &norm;
        quotient.b /= &norm;
        quotient.c /= &norm;
        quotient.d /= &norm;
        quotient = quotient.nearest_hurwitz();
        assert!(quotient.clone().is_hurwitz());
        (quotient.clone(), self - &(&quotient * &other))
    }
}

// TODO(samschlesinger) implement Div for Quaternion and factor out division from above

impl Add for &Quaternion {
    type Output = Quaternion;

    fn add(self, rhs: Self) -> Quaternion {
        Quaternion {
            a: &self.a + &rhs.a,
            b: &self.b + &rhs.b,
            c: &self.c + &rhs.c,
            d: &self.d + &rhs.d,
        }
    }
}

impl Sub for &Quaternion {
    type Output = Quaternion;

    fn sub(self, rhs: Self) -> Quaternion {
        Quaternion {
            a: &self.a - &rhs.a,
            b: &self.b - &rhs.b,
            c: &self.c - &rhs.c,
            d: &self.d - &rhs.d,
        }
    }
}

impl Mul for &Quaternion {
    type Output = Quaternion;

    fn mul(self, rhs: &Quaternion) -> Quaternion {
        Quaternion {
            a: &self.a * &rhs.a - &self.b * &rhs.b - &self.c * &rhs.c - &self.d * &rhs.d,
            b: &self.b * &rhs.a + &self.a * &rhs.b + &self.c * &rhs.d - &self.d * &rhs.c,
            c: &self.a * &rhs.c + &self.c * &rhs.a + &self.d * &rhs.b - &self.b * &rhs.d,
            d: &self.a * &rhs.d + &self.d * &rhs.a + &self.b * &rhs.c - &self.c * &rhs.b,
        }
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::test_runner::Config;

    prop_compose! {
        fn arb_ratio()(num: i64, den in 1i64..=100) -> Ratio<BigInt> {
            Ratio::new(BigInt::from(num), BigInt::from(den))
        }
    }

    prop_compose! {
        fn arb_quaternion()(a in arb_ratio(), b in arb_ratio(), c in arb_ratio(), d in arb_ratio()) -> Quaternion {
            Quaternion { a, b, c, d }
        }
    }

    prop_compose! {
        fn arb_nonzero_quaternion()(a in arb_ratio(), b in arb_ratio(), c in arb_ratio(), d in arb_ratio()) -> Quaternion {
            let q = Quaternion { a, b, c, d };
            if q == Quaternion::zero() {
                Quaternion {
                    a: Ratio::from(BigInt::from(1)),
                    b: Ratio::from(BigInt::from(0)),
                    c: Ratio::from(BigInt::from(0)),
                    d: Ratio::from(BigInt::from(0)),
                }
            } else {
                q
            }
        }
    }

    prop_compose! {
        fn arb_hurwitz_integer()(a: i32, b: i32, c: i32, d: i32) -> Quaternion {
            Quaternion {
                a: Ratio::from(BigInt::from(a)),
                b: Ratio::from(BigInt::from(b)),
                c: Ratio::from(BigInt::from(c)),
                d: Ratio::from(BigInt::from(d)),
            }
        }
    }

    prop_compose! {
        fn arb_hurwitz_half_integer()(a: i32, b: i32, c: i32, d: i32) -> Quaternion {
            let one_half = Ratio::new(BigInt::from(1), BigInt::from(2));
            Quaternion {
                a: Ratio::from(BigInt::from(a)) + &one_half,
                b: Ratio::from(BigInt::from(b)) + &one_half,
                c: Ratio::from(BigInt::from(c)) + &one_half,
                d: Ratio::from(BigInt::from(d)) + &one_half,
            }
        }
    }

    prop_compose! {
        fn arb_hurwitz()(use_half_integer: bool, a: i32, b: i32, c: i32, d: i32) -> Quaternion {
            if use_half_integer {
                let one_half = Ratio::new(BigInt::from(1), BigInt::from(2));
                Quaternion {
                    a: Ratio::from(BigInt::from(a)) + &one_half,
                    b: Ratio::from(BigInt::from(b)) + &one_half,
                    c: Ratio::from(BigInt::from(c)) + &one_half,
                    d: Ratio::from(BigInt::from(d)) + &one_half,
                }
            } else {
                Quaternion {
                    a: Ratio::from(BigInt::from(a)),
                    b: Ratio::from(BigInt::from(b)),
                    c: Ratio::from(BigInt::from(c)),
                    d: Ratio::from(BigInt::from(d)),
                }
            }
        }
    }

    prop_compose! {
        fn arb_nonzero_hurwitz()(q in arb_hurwitz()) -> Quaternion {
            if q == Quaternion::zero() {
                Quaternion {
                    a: Ratio::from(BigInt::from(1)),
                    b: Ratio::from(BigInt::from(0)),
                    c: Ratio::from(BigInt::from(0)),
                    d: Ratio::from(BigInt::from(0)),
                }
            } else {
                q
            }
        }
    }

    proptest! {
        #![proptest_config(Config::with_cases(32))]
        
        #[test]
        fn test_add_commutative(a in arb_quaternion(), b in arb_quaternion()) {
            prop_assert_eq!(&a + &b, &b + &a);
        }

        #[test]
        fn test_add_associative(a in arb_quaternion(), b in arb_quaternion(), c in arb_quaternion()) {
            prop_assert_eq!(&(&a + &b) + &c, &a + &(&b + &c));
        }

        #[test]
        fn test_add_identity(a in arb_quaternion()) {
            let zero = Quaternion::zero();
            prop_assert_eq!(&a + &zero, a.clone());
            prop_assert_eq!(&zero + &a, a);
        }

        #[test]
        fn test_sub_inverse_add(a in arb_quaternion(), b in arb_quaternion()) {
            prop_assert_eq!(&(&a + &b) - &b, a);
        }

        #[test]
        fn test_mul_associative(a in arb_quaternion(), b in arb_quaternion(), c in arb_quaternion()) {
            prop_assert_eq!(&(&a * &b) * &c, &a * &(&b * &c));
        }

        #[test]
        fn test_mul_identity(a in arb_quaternion()) {
            let one = Quaternion {
                a: Ratio::from(BigInt::from(1)),
                b: Ratio::from(BigInt::from(0)),
                c: Ratio::from(BigInt::from(0)),
                d: Ratio::from(BigInt::from(0)),
            };
            prop_assert_eq!(&a * &one, a.clone());
            prop_assert_eq!(&one * &a, a);
        }

        #[test]
        fn test_distributive_left(a in arb_quaternion(), b in arb_quaternion(), c in arb_quaternion()) {
            prop_assert_eq!(&a * &(&b + &c), &(&a * &b) + &(&a * &c));
        }

        #[test]
        fn test_distributive_right(a in arb_quaternion(), b in arb_quaternion(), c in arb_quaternion()) {
            prop_assert_eq!(&(&a + &b) * &c, &(&a * &c) + &(&b * &c));
        }

        #[test]
        fn test_conjugate_involution(a in arb_quaternion()) {
            prop_assert_eq!(a.conjugate().conjugate(), a);
        }

        #[test]
        fn test_conjugate_norm(a in arb_quaternion()) {
            let conj_a = a.conjugate();
            let norm_via_conj = (&a * &conj_a).a.clone();
            let norm_direct = a.norm();
            prop_assert_eq!(norm_via_conj, norm_direct);
        }

        #[test]
        fn test_norm_multiplicative(a in arb_quaternion(), b in arb_quaternion()) {
            let norm_product = (&a * &b).norm();
            let product_norms = a.norm() * b.norm();
            let epsilon = Ratio::from(BigInt::from(1)) / Ratio::from(BigInt::from(1000000));
            let diff = if norm_product > product_norms { norm_product - product_norms } else { product_norms - norm_product };
            prop_assert!(diff < epsilon);
        }

        #[test]
        fn test_pow_correctness(a in arb_quaternion(), n in 0usize..10) {
            let mut expected = Quaternion {
                a: Ratio::from(BigInt::from(1)),
                b: Ratio::from(BigInt::from(0)),
                c: Ratio::from(BigInt::from(0)),
                d: Ratio::from(BigInt::from(0)),
            };
            for _ in 0..n {
                expected = &expected * &a;
            }
            prop_assert_eq!(a.pow(n), expected);
        }

        #[test]
        fn test_is_hurwitz_invariant(q in arb_hurwitz()) {
            prop_assert!(q.is_hurwitz());
        }

        #[test]
        fn test_hurwitz_closed_under_add(a in arb_hurwitz(), b in arb_hurwitz()) {
            prop_assert!((&a + &b).is_hurwitz());
        }

        #[test]
        fn test_hurwitz_closed_under_sub(a in arb_hurwitz(), b in arb_hurwitz()) {
            prop_assert!((&a - &b).is_hurwitz());
        }

        #[test]
        fn test_hurwitz_closed_under_mul(a in arb_hurwitz(), b in arb_hurwitz()) {
            prop_assert!((&a * &b).is_hurwitz());
        }

        #[test]
        fn test_normalize_hurwitz_preserves_hurwitz(q in arb_hurwitz()) {
            let normalized = q.normalize_hurwitz();
            prop_assert!(normalized.is_hurwitz());
            prop_assert!(normalized.a.is_integer());
            prop_assert!(normalized.b.is_integer());
            prop_assert!(normalized.c.is_integer());
            prop_assert!(normalized.d.is_integer());
        }

        #[test]
        fn test_nearest_hurwitz_is_hurwitz(q in arb_quaternion()) {
            let nearest = q.nearest_hurwitz();
            prop_assert!(nearest.is_hurwitz());
        }

        #[test]
        fn test_divide_with_remainder_hurwitz(a in arb_hurwitz(), b in arb_nonzero_hurwitz()) {
            let (q, r) = a.divide_with_remainder(&b);
            prop_assert!(q.is_hurwitz());
            prop_assert!(r.is_hurwitz());
            prop_assert_eq!(&(&q * &b) + &r, a);
        }

        #[test]
        fn test_gcrd_divides_both(a in arb_hurwitz(), b in arb_hurwitz()) {
            if a == Quaternion::zero() && b == Quaternion::zero() {
                return Ok(());
            }
            let gcd = a.clone().gcrd(b.clone());
            if gcd != Quaternion::zero() {
                let (_, r1) = a.divide_with_remainder(&gcd);
                let (_, r2) = b.divide_with_remainder(&gcd);
                prop_assert_eq!(r1, Quaternion::zero());
                prop_assert_eq!(r2, Quaternion::zero());
            }
        }

        #[test]
        fn test_scale_linearity(q in arb_quaternion(), k: i32) {
            let k_ratio = Ratio::from(BigInt::from(k));
            let q_clone = q.clone();
            let scaled = q.scale(|x| x * &k_ratio);
            prop_assert_eq!(scaled.a, &q_clone.a * &k_ratio);
            prop_assert_eq!(scaled.b, &q_clone.b * &k_ratio);
            prop_assert_eq!(scaled.c, &q_clone.c * &k_ratio);
            prop_assert_eq!(scaled.d, &q_clone.d * &k_ratio);
        }
    }
}
