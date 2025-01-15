use num::{rational::Ratio, traits::Euclid, BigInt};
use std::ops::{Add, Mul, Neg, Sub};

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
