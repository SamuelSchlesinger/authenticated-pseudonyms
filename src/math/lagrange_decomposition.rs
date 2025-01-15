use crate::math::{complex::Complex, mod_exp::mod_exp, quaternion::Quaternion};
use num::{bigint::RandomBits, rational::Ratio, BigInt};
use rand::distributions::Distribution;
use rand::Rng;

/// Decomposes the given number into a, b, c, d such that a^2 + b^2 + c^2 + d^2 = delta.
/// Works on numbers up to about a million billion or so.
pub fn decompose(mut rng: impl Rng, mut delta: BigInt) -> (BigInt, BigInt, BigInt, BigInt) {
    if delta <= BigInt::from(20) {
        let first_byte = if delta > BigInt::from(0) {
            delta.to_u32_digits().1[0]
        } else {
            0
        };
        let f = |(i, j, k, l)| {
            (
                BigInt::from(i),
                BigInt::from(j),
                BigInt::from(k),
                BigInt::from(l),
            )
        };
        return f(match first_byte {
            0 => (0, 0, 0, 0),
            1 => (1, 0, 0, 0),
            2 => (1, 1, 0, 0),
            3 => (1, 1, 1, 0),
            4 => (2, 0, 0, 0),
            5 => (2, 1, 0, 0),
            6 => (2, 1, 1, 0),
            7 => (2, 1, 1, 1),
            8 => (2, 2, 0, 0),
            9 => (3, 0, 0, 0),
            10 => (3, 1, 0, 0),
            11 => (3, 1, 1, 0),
            12 => (3, 1, 1, 1),
            13 => (3, 2, 0, 0),
            14 => (3, 2, 1, 0),
            15 => (3, 2, 1, 1),
            16 => (4, 0, 0, 0),
            17 => (4, 1, 0, 0),
            18 => (4, 1, 1, 0),
            19 => (4, 1, 1, 1),
            20 => (4, 2, 0, 0),
            _ => panic!("impossible"),
        });
    }
    if &delta % 2 == BigInt::from(0) {
        let mut e = 0;
        while &delta % 2 == BigInt::from(0) {
            e += 1;
            delta /= 2;
        }
        let factor = Quaternion {
            a: Ratio::from(BigInt::from(1)),
            b: Ratio::from(BigInt::from(1)),
            c: Ratio::from(BigInt::from(0)),
            d: Ratio::from(BigInt::from(0)),
        }
        .pow(e);
        let (y1, y2, y3, y4) = decompose(rng, delta);
        let q = &factor
            * &Quaternion {
                a: Ratio::from(BigInt::from(y1)),
                b: Ratio::from(BigInt::from(y2)),
                c: Ratio::from(BigInt::from(y3)),
                d: Ratio::from(BigInt::from(y4)),
            };
        return (
            q.a.to_integer(),
            q.b.to_integer(),
            q.c.to_integer(),
            q.d.to_integer(),
        );
    }
    assert!(&delta % BigInt::from(2) == BigInt::from(1) && &delta > &BigInt::from(20));
    let log2_delta = delta.clone().into_parts().1.bits().into();
    // currently, this can handle numbers up to around a million billion. if we want to go higher,
    // need to add primes here.
    let primes = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
    ];
    let m = {
        let mut r = BigInt::from(1);
        for p in primes {
            let p = BigInt::from(p);
            if p < log2_delta {
                r *= p;
            }
        }
        r
    };

    let k_limit = delta.pow(5);
    let m_delta_product: BigInt = &m * &delta;
    loop {
        let k_candidate: BigInt = RandomBits::new(321).sample(&mut rng);
        let k = &k_candidate % &k_limit;
        if &k % 2 == BigInt::from(0) {
            // we need an odd k
            continue;
        }
        let p: BigInt = &m_delta_product * &k - 1;
        let u_candidate: BigInt = RandomBits::new(500).sample(&mut rng);
        let u: BigInt = u_candidate % (&p - 1) + BigInt::from(1);
        let s = mod_exp(u, (&p - 1) / 4, p.clone());

        if (&s * &s) % &p != &p - BigInt::from(1) {
            continue;
        }

        let c = Complex {
            a: Ratio::from(s.clone()),
            b: Ratio::from(BigInt::from(1)),
        };
        let r = c.gcd(Complex {
            a: Ratio::from(p),
            b: Ratio::from(BigInt::from(0)),
        });
        let a = r.a;
        let b = r.b;

        let q = Quaternion {
            a,
            b,
            c: Ratio::from(BigInt::from(1)),
            d: Ratio::from(BigInt::from(0)),
        };

        let d = Quaternion {
            a: Ratio::from(delta.clone()),
            b: Ratio::from(BigInt::from(0)),
            c: Ratio::from(BigInt::from(0)),
            d: Ratio::from(BigInt::from(0)),
        };

        let r = q.gcrd(d).normalize_hurwitz();

        return (
            r.a.to_integer(),
            r.b.to_integer(),
            r.c.to_integer(),
            r.d.to_integer(),
        );
    }
}

#[test]
fn test_decomposition() {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    for i in 0..=100u64 {
        let (y1, y2, y3, y4) = decompose(&mut rng, BigInt::from(i));
        assert_eq!(
            &y1 * &y1 + &y2 * &y2 + &y3 * &y3 + &y4 * &y4,
            BigInt::from(i)
        );
    }
    for _i in 0..10u64 {
        let n = rng.next_u64() % 1000000;
        let (y1, y2, y3, y4) = decompose(&mut rng, BigInt::from(n));
        assert_eq!(
            &y1 * &y1 + &y2 * &y2 + &y3 * &y3 + &y4 * &y4,
            BigInt::from(n)
        );
    }
}
