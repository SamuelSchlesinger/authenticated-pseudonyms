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
