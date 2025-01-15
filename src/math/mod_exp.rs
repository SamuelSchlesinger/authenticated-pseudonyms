use num::BigInt;

/// Efficient modular exponentiation algorithm.
pub fn mod_exp(x: BigInt, y: BigInt, p: BigInt) -> BigInt {
    if p == BigInt::from(1) {
        return BigInt::from(0);
    }
    let mut result = BigInt::from(1);
    let mut base = x % &p;
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
