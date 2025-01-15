use curve25519_dalek::{RistrettoPoint, Scalar};
use group::ff::Field;
use group::{Group, GroupEncoding};
use num::{bigint::RandomBits, BigInt, BigUint};
use rand::distributions::Distribution;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};

use std::ops::Neg;

pub(crate) mod math;

type G = RistrettoPoint;

const GLOBAL_LABEL: &[u8] = b"ZKAGE_CREDENTIALS";
const CLIENT_ISSUANCE_LABEL: &[u8] = b"CLIENT_ISSUANCE";
const SERVER_ISSUANCE_LABEL: &[u8] = b"SERVER_ISSUANCE";
const ZKAGE_PROOF_LABEL: &[u8] = b"ZKAGE_PROOF";
const SEPARATOR: &[u8] = b"\n";

/// This value is smaller than it could be for performance reasons.
const MAX_RATE_LIMIT_EXPONENT: u32 = 20;

/// This value can be derived from Theorem 1 in the whitepaper.
const MAX_RANGE_PROOF_BOUND: u64 = 2u64.pow(36) / 3;

/// TODO describe security parameter
const C: u128 = 2u128.pow(80);

/// TODO describe security parameter
const L: u128 = 2u128.pow(30);

struct FiatShamir {
    hasher: blake3::Hasher,
}

impl FiatShamir {
    fn new(label: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(GLOBAL_LABEL);
        hasher.update(SEPARATOR);
        hasher.update(label);
        hasher.update(SEPARATOR);
        hasher.update(G::label());
        hasher.update(SEPARATOR);
        FiatShamir { hasher }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.hasher.update(SEPARATOR);
    }

    fn rng(&self) -> impl CryptoRngCore {
        ChaCha20Rng::from_seed(*self.hasher.finalize().as_bytes())
    }

    fn rph(&self) -> BigUint {
        BigUint::from_bytes_le(self.hasher.finalize().as_bytes()) % BigUint::from(C)
    }
}

/// Global parameters for the scheme.
pub struct Params {
    h1: G,
    h2: G,
    h3: G,
    h4: G,
}

trait HasLabel {
    fn label() -> &'static [u8];
}

impl HasLabel for RistrettoPoint {
    fn label() -> &'static [u8] {
        b"RISTRETTO"
    }
}

impl Default for Params {
    fn default() -> Self {
        let mut rng = ChaCha20Rng::from_seed(*blake3::hash(b"extremely random string").as_bytes());
        Params::random(&mut rng)
    }
}

impl Params {
    /// Generate random parameters using the given RNG.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        Params {
            h1: G::random(&mut rng),
            h2: G::random(&mut rng),
            h3: G::random(&mut rng),
            h4: G::random(&mut rng),
        }
    }
}

/// The private key of the issuer.
pub struct IssuerPrivateKey {
    x: Scalar,
}

/// The public key of the issuer.
pub struct IssuerPublicKey {
    w: G,
}

impl IssuerPrivateKey {
    /// Generate random private key for the issuer.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        IssuerPrivateKey {
            x: Scalar::random(&mut rng),
        }
    }

    /// Computes the public key of the issuer given the private one.
    pub fn public(&self) -> IssuerPublicKey {
        IssuerPublicKey {
            w: G::generator() * self.x,
        }
    }
}

/// The private PRF key held by the client as they request credential issuance.
pub struct ClientPrivateKey {
    k: Scalar,
}

/// The request sent to the server by the client, proving that they know their private key.
pub struct CredentialRequest {
    big_k: G,
    gamma: Scalar,
    k_bar: Scalar,
}

impl ClientPrivateKey {
    /// Generate a new client private key.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        ClientPrivateKey {
            k: Scalar::random(&mut rng),
        }
    }

    /// Create a request for a new credential issuance associated to the given private key.
    pub fn credential_request(
        &self,
        params: &Params,
        mut rng: impl CryptoRngCore,
    ) -> CredentialRequest {
        let big_k = params.h2 * self.k;
        let k_prime = Scalar::random(&mut rng);
        let big_k_1 = params.h2 * k_prime;

        let gamma = {
            let mut fiat_shamir = FiatShamir::new(CLIENT_ISSUANCE_LABEL);
            fiat_shamir.update(big_k.to_bytes().as_ref());
            fiat_shamir.update(big_k_1.to_bytes().as_ref());
            let mut fiat_shamir_rng = fiat_shamir.rng();

            Scalar::random(&mut fiat_shamir_rng)
        };

        let k_bar = gamma * self.k + k_prime;

        CredentialRequest {
            big_k,
            gamma,
            k_bar,
        }
    }
}

/// The response the server sends back upon a request for issuance.
pub struct CredentialResponse {
    t: Scalar,
    a: G,
    e: Scalar,
    gamma: Scalar,
    z: Scalar,
}

impl CredentialRequest {
    /// Responds to the given credential request with the data needed for the client to construct a
    /// new credential.
    pub fn respond(
        &self,
        issuer_private_key: &IssuerPrivateKey,
        issuer_public_key: &IssuerPublicKey,
        params: &Params,
        t: Scalar,
        mut rng: impl CryptoRngCore,
    ) -> Option<CredentialResponse> {
        let big_k_1 = params.h2 * self.k_bar + self.big_k * self.gamma.neg();
        let client_gamma = {
            let mut fiat_shamir = FiatShamir::new(CLIENT_ISSUANCE_LABEL);
            fiat_shamir.update(self.big_k.to_bytes().as_ref());
            fiat_shamir.update(big_k_1.to_bytes().as_ref());
            let mut fiat_shamir_rng = fiat_shamir.rng();
            Scalar::random(&mut fiat_shamir_rng)
        };

        if client_gamma != self.gamma {
            return None;
        }

        let e = Scalar::random(&mut rng);
        // TODO unwrap here is probably okay, because e is completely random.
        let a = (G::generator() + params.h1 * t + self.big_k) * (e + issuer_private_key.x).invert();
        let x_a = G::generator() + params.h1 * t + self.big_k;
        let x_g = G::generator() * e + issuer_public_key.w;

        let alpha = Scalar::random(&mut rng);
        let y_a = a * alpha;
        let y_g = G::generator() * alpha;

        let gamma = {
            let mut fiat_shamir = FiatShamir::new(SERVER_ISSUANCE_LABEL);
            fiat_shamir.update(x_a.to_bytes().as_ref());
            fiat_shamir.update(x_g.to_bytes().as_ref());
            fiat_shamir.update(y_a.to_bytes().as_ref());
            fiat_shamir.update(y_g.to_bytes().as_ref());

            Scalar::random(&mut fiat_shamir.rng())
        };

        let z = gamma * (issuer_private_key.x + e) + alpha;

        Some(CredentialResponse { t, a, e, gamma, z })
    }
}

/// A credential which the client holds privately.
pub struct Credential {
    t: Scalar,
    a: G,
    e: Scalar,
    k: Scalar,
}

impl ClientPrivateKey {
    /// Creates a new credential using the original request, response from the server, and the
    /// client's private PRF key.
    pub fn create_credential(
        &self,
        params: &Params,
        request: &CredentialRequest,
        response: &CredentialResponse,
        issuer_public_key: &IssuerPublicKey,
    ) -> Option<Credential> {
        let x_a = G::generator() + params.h1 * response.t + request.big_k;
        let x_g = G::generator() * response.e + issuer_public_key.w;
        let y_prime_a = response.a * response.z + x_a * response.gamma.neg();
        let y_prime_g = G::generator() * response.z + x_g * response.gamma.neg();

        let server_gamma = {
            let mut fiat_shamir = FiatShamir::new(SERVER_ISSUANCE_LABEL);
            fiat_shamir.update(x_a.to_bytes().as_ref());
            fiat_shamir.update(x_g.to_bytes().as_ref());
            fiat_shamir.update(y_prime_a.to_bytes().as_ref());
            fiat_shamir.update(y_prime_g.to_bytes().as_ref());

            Scalar::random(&mut fiat_shamir.rng())
        };

        if response.gamma != server_gamma {
            return None;
        }

        Some(Credential {
            t: response.t,
            a: response.a,
            e: response.e,
            k: self.k,
        })
    }
}

#[test]
fn test_credentials() {
    use rand_core::{OsRng, RngCore};

    for _ in 0..1 {
        let issuer_private_key: IssuerPrivateKey = IssuerPrivateKey::random(OsRng);
        let issuer_public_key = issuer_private_key.public();
        let params: Params = Params::random(OsRng);
        let k: ClientPrivateKey = ClientPrivateKey::random(OsRng);
        let req = k.credential_request(&params, OsRng);
        let bound = OsRng.next_u64() % MAX_RANGE_PROOF_BOUND;
        let epoch = OsRng.next_u32();
        let t = OsRng.next_u64() % bound;
        let resp = req
            .respond(
                &issuer_private_key,
                &issuer_public_key,
                &params,
                Scalar::from(t),
                OsRng,
            )
            .unwrap();
        let cred = k
            .create_credential(&params, &req, &resp, &issuer_public_key)
            .unwrap();
        let rate_limit_bound = 5;
        for i in 0..2u64.pow(rate_limit_bound) {
            let proof = cred.prove(&params, bound, epoch, OsRng, rate_limit_bound, i).unwrap();
            assert!(proof.verify(&params, &issuer_private_key));
        }
    }
}

/// A proof that the
pub struct Proof {
    bound: Scalar,
    rate_limit_exponent: u32,
    epoch: u32,
    a_prime: G,
    b_bar: G,
    y: G,
    com: Vec<G>,
    c_y: G,
    c_star: G,
    gamma: Scalar,
    z_e: Scalar,
    z_r2: Scalar,
    z_r3: Scalar,
    z_delta: Scalar,
    z_k: Scalar,
    z_s: Scalar,
    gamma0: Vec<Scalar>,
    z0: Vec<Scalar>,
    z1: Vec<Scalar>,
    t_y: Scalar,
    z_1y: Scalar,
    z_2y: Scalar,
    z_3y: Scalar,
    z_4y: Scalar,
    t_star: Scalar,
}

impl Proof {
    /// The upper bound which this proof proves the secret value is less than or equal to.
    pub fn bound(&self) -> &Scalar {
        &self.bound
    }

    /// The logarithm of the rate limiting bound.
    pub fn rate_limiting_exponent(&self) -> u32 {
        self.rate_limit_exponent
    }

    /// The rate limiting token itself, of which only a certain number can be created per epoch.
    pub fn rate_limiting_token(&self) -> &G {
        &self.y
    }

    /// The epoch that this proof is computed for.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }
}

impl Credential {
    /// Prove that the credential's underlying value is less than or equal to the given bound,
    /// along with proving/producing a valid rate limiting token for this epoch.
    pub fn prove(
        &self,
        params: &Params,
        bound: u64,
        epoch: u32,
        mut rng: impl CryptoRngCore,
        rate_limit_exponent: u32,
        i: u64,
    ) -> Option<Proof> {
        let bound_bigint = BigUint::from(bound);
        let t_bigint = scalar_to_bigint(&self.t);
        if t_bigint > bound_bigint {
            return None;
        }
        let delta_bigint = &bound_bigint - t_bigint;
        if bound > MAX_RANGE_PROOF_BOUND {
            return None;
        }
        let bound = Scalar::from(bound);
        if rate_limit_exponent > MAX_RATE_LIMIT_EXPONENT {
            return None;
        }
        let mut fiat_shamir = FiatShamir::new(ZKAGE_PROOF_LABEL);

        // == PoK of Credential: Commitment Phase ==
        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let e_prime = Scalar::random(&mut rng);
        let r2_prime = Scalar::random(&mut rng);
        let r3_prime = Scalar::random(&mut rng);
        let delta_prime = Scalar::random(&mut rng);
        let k_prime = Scalar::random(&mut rng);
        let s_prime = Scalar::random(&mut rng);

        let b = G::generator() + params.h1 * self.t + params.h2 * self.k;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let a_bar = a_prime * (self.e.neg()) + b_bar * r2;
        eprintln!("prove, a_bar = {}", debug_hash(a_bar.to_bytes()));
        // TODO again, probably okay cause its totally random
        let r3 = r1.invert();
        let delta = bound - self.t;
        // TODO check that delta >= 0
        let a1 = a_prime * e_prime + b_bar * r2_prime;
        eprintln!("prove, a1 = {}", debug_hash(a1.to_bytes()));
        let a2 =
            b_bar * r3_prime + params.h1 * delta_prime + params.h2 * k_prime + params.h3 * s_prime;
        eprintln!("prove, a2 = {}", debug_hash(a2.to_bytes()));

        fiat_shamir.update(a_prime.to_bytes().as_ref());
        fiat_shamir.update(b_bar.to_bytes().as_ref());

        fiat_shamir.update(a1.to_bytes().as_ref());
        fiat_shamir.update(a2.to_bytes().as_ref());
        // == End ==

        // == PRF + Commitments and Associated Proofs: Commitment Phase ==
        let y = params.h2
            * (self.k
                + Scalar::from(2u64.pow(rate_limit_exponent)) * Scalar::from(epoch as u64)
                + Scalar::from(i))
            .invert();
        fiat_shamir.update(y.to_bytes().as_ref());
        let mut com = Vec::with_capacity(rate_limit_exponent as usize);
        let mut s = Vec::with_capacity(rate_limit_exponent as usize);
        let mut s_star = Scalar::from(0u64);
        let mut c0 = Vec::with_capacity(rate_limit_exponent as usize);
        let mut c1 = Vec::with_capacity(rate_limit_exponent as usize);
        let mut c0_prime = Vec::with_capacity(rate_limit_exponent as usize);
        let mut c1_prime = Vec::with_capacity(rate_limit_exponent as usize);
        let mut r = Vec::with_capacity(rate_limit_exponent as usize);
        let mut gamma = Vec::with_capacity(rate_limit_exponent as usize);
        let mut z = Vec::with_capacity(rate_limit_exponent as usize);
        for j in 0..rate_limit_exponent {
            let s_j = Scalar::random(&mut rng);
            s.push(s_j);
            let i_j = if (i >> j) & 1 != 0 { 1 } else { 0 };
            let com_j = params.h3 * s_j + params.h2 * Scalar::from(i_j as u64);
            com.push(com_j);
            fiat_shamir.update(com_j.to_bytes().as_ref());
            s_star += Scalar::from(2u64.pow(j)) * s_j;
            let r_j = Scalar::random(&mut rng);
            r.push(r_j);
            let gamma_j = Scalar::random(&mut rng);
            gamma.push(gamma_j);
            let z_j = Scalar::random(&mut rng);
            z.push(z_j);
            let c0_j = com_j;
            c0.push(c0_j);
            let c1_j = com_j - params.h2;
            c1.push(c1_j);
            let (c0_prime_j, c1_prime_j) = if i_j == 0 {
                let c0_prime_j = params.h3 * r_j;
                c0_prime.push(c0_prime_j);
                let c1_prime_j = params.h3 * z_j + c1_j * gamma_j.neg();
                c1_prime.push(c1_prime_j);
                (c0_prime_j, c1_prime_j)
            } else {
                let c0_prime_j = params.h3 * z_j + c0_j * gamma_j.neg();
                c0_prime.push(c0_prime_j);
                let c1_prime_j = params.h3 * r_j;
                c1_prime.push(c1_prime_j);
                (c0_prime_j, c1_prime_j)
            };
            fiat_shamir.update(c0_prime_j.to_bytes().as_ref());
            fiat_shamir.update(c1_prime_j.to_bytes().as_ref());
            eprintln!(
                "prove, c0_prime_{} = {}",
                j,
                debug_hash(c0_prime_j.to_bytes())
            );
            eprintln!(
                "prove, c1_prime_{} = {}",
                j,
                debug_hash(c1_prime_j.to_bytes())
            );
        }
        let y1 = y * k_prime.neg();
        eprintln!("prove, y1 = {}", debug_hash(y1.to_bytes()));
        fiat_shamir.update(y1.to_bytes().as_ref());
        // == End ==

        // == Range Proof: Commitment Phase ==
        let (y1, y2, y3, y4): (BigInt, BigInt, BigInt, BigInt) =
            math::lagrange_decomposition::decompose(&mut rng, delta_bigint.into());
        let y1 = bigint_to_scalar(&y1.into_parts().1).unwrap();
        let y2 = bigint_to_scalar(&y2.into_parts().1).unwrap();
        let y3 = bigint_to_scalar(&y3.into_parts().1).unwrap();
        let y4 = bigint_to_scalar(&y4.into_parts().1).unwrap();
        let r_y = Scalar::random(&mut rng);
        let r_y_tilde = Scalar::random(&mut rng);
        let y_i_tilde_bound = bound_bigint.sqrt() * BigUint::from(C) * BigUint::from(L);
        let (y1_tilde, y2_tilde, y3_tilde, y4_tilde) = {
            if bound_bigint > BigUint::from(0u64) {
                let y1_tilde: BigUint = RandomBits::new(255).sample(&mut rng);
                let y1_tilde: BigUint = y1_tilde % &y_i_tilde_bound;
                let y2_tilde: BigUint = RandomBits::new(255).sample(&mut rng);
                let y2_tilde: BigUint = y2_tilde % &y_i_tilde_bound;
                let y3_tilde: BigUint = RandomBits::new(255).sample(&mut rng);
                let y3_tilde: BigUint = y3_tilde % &y_i_tilde_bound;
                let y4_tilde: BigUint = RandomBits::new(255).sample(&mut rng);
                let y4_tilde: BigUint = y4_tilde % &y_i_tilde_bound;

                (
                    bigint_to_scalar(&y1_tilde).unwrap(),
                    bigint_to_scalar(&y2_tilde).unwrap(),
                    bigint_to_scalar(&y3_tilde).unwrap(),
                    bigint_to_scalar(&y4_tilde).unwrap(),
                )
            } else {
                (
                    Scalar::from(0u64),
                    Scalar::from(0u64),
                    Scalar::from(0u64),
                    Scalar::from(0u64),
                )
            }
        };
        let c_y = G::generator() * r_y
            + params.h1 * y1
            + params.h2 * y2
            + params.h3 * y3
            + params.h4 * y4;
        fiat_shamir.update(c_y.to_bytes().as_ref());
        let d_y = G::generator() * r_y_tilde
            + params.h1 * y1_tilde
            + params.h2 * y2_tilde
            + params.h3 * y3_tilde
            + params.h4 * y4_tilde;
        eprintln!("prove, d_y = {}", debug_hash(d_y.to_bytes()));
        fiat_shamir.update(d_y.to_bytes().as_ref());
        let alpha = delta_prime
            - Scalar::from(2u64) * (y1 * y1_tilde + y2 * y2_tilde + y3 * y3_tilde + y4 * y4_tilde);
        let alpha_tilde = y1_tilde.square().neg()
            + y2_tilde.square().neg()
            + y3_tilde.square().neg()
            + y4_tilde.square().neg();
        let r_star = Scalar::random(&mut rng);
        let c_star = G::generator() * r_star + params.h1 * alpha;
        fiat_shamir.update(c_star.to_bytes().as_ref());
        let r_star_tilde = Scalar::random(&mut rng);
        let d_star = G::generator() * r_star_tilde + params.h1 * alpha_tilde;
        eprintln!("prove, d_star = {}", debug_hash(d_star.to_bytes()));
        fiat_shamir.update(d_star.to_bytes().as_ref());
        // == End ==

        // == Challenge Phase ==
        let challenge_gamma: Scalar = bigint_to_scalar(&fiat_shamir.rph()).unwrap();
        // == End ==

        // == Proof of Knowledge of Credential: Response ==
        let z_e = challenge_gamma.neg() * self.e + e_prime;
        let z_r2 = challenge_gamma * r2 + r2_prime;
        let z_r3 = challenge_gamma * r3 + r3_prime;
        let z_delta = challenge_gamma * delta + delta_prime;
        let z_k = challenge_gamma.neg() * (self.k + Scalar::from(i)) + k_prime;
        let z_s = challenge_gamma.neg() * s_star + s_prime;
        // == End ==

        // == Proofs for commitments + PRF: Response ==
        let mut gamma0 = Vec::new();
        let mut z0 = Vec::new();
        let mut z1 = Vec::new();
        for j in 0..rate_limit_exponent {
            let i_j = if (i >> j) & 1 != 0 { 1 } else { 0 };
            let j = j as usize;
            if i_j == 0 {
                gamma0.push(challenge_gamma - gamma[j]);
                z0.push(gamma0[j] * s[j] + r[j]);
                z1.push(z[j]);
            } else {
                gamma0.push(gamma[j]);
                z0.push(z[j]);
                z1.push((challenge_gamma - gamma0[j]) * s[j] + r[j]);
            }
        }
        // == End ==

        // == Range Proof: Response ==
        let t_y = challenge_gamma * r_y + r_y_tilde;
        let z_1y = challenge_gamma * y1 + y1_tilde;
        let z_2y = challenge_gamma * y2 + y2_tilde;
        let z_3y = challenge_gamma * y3 + y3_tilde;
        let z_4y = challenge_gamma * y4 + y4_tilde;
        let t_star = challenge_gamma * r_star + r_star_tilde;
        // == End ==

        Some(Proof {
            bound,
            rate_limit_exponent,
            epoch,
            a_prime,
            b_bar,
            y,
            com,
            c_y,
            c_star,
            gamma: challenge_gamma,
            z_e,
            z_r2,
            z_r3,
            z_delta,
            z_k,
            z_s,
            gamma0,
            z0,
            z1,
            t_y,
            z_1y,
            z_2y,
            z_3y,
            z_4y,
            t_star,
        })
    }
}

impl Proof {
    /// Verify that the given proof is correct.
    pub fn verify(&self, params: &Params, issuer_private_key: &IssuerPrivateKey) -> bool {
        if scalar_to_bigint(&self.bound) > BigUint::from(MAX_RANGE_PROOF_BOUND) {
            eprintln!("1");
            return false;
        }
        if BigUint::from(self.rate_limit_exponent) > BigUint::from(MAX_RATE_LIMIT_EXPONENT) {
            eprintln!("2");
            return false;
        }
        if self.rate_limit_exponent != self.z0.len() as u32
            && self.rate_limit_exponent != self.z1.len() as u32
            && self.rate_limit_exponent != self.com.len() as u32
        {
            eprintln!("3");
            return false;
        }
        if self.a_prime == G::identity() {
            eprintln!("4");
            return false;
        }

        let mut fiat_shamir = FiatShamir::new(ZKAGE_PROOF_LABEL);
        fiat_shamir.update(self.a_prime.to_bytes().as_ref());
        fiat_shamir.update(self.b_bar.to_bytes().as_ref());

        let z_i_y_bound =
            scalar_to_bigint(&self.bound).sqrt() * BigUint::from(C) * (BigUint::from(L) + 1u64);

        let z_1y = scalar_to_bigint(&self.z_1y);
        let z_2y = scalar_to_bigint(&self.z_2y);
        let z_3y = scalar_to_bigint(&self.z_3y);
        let z_4y = scalar_to_bigint(&self.z_4y);

        if z_1y > z_i_y_bound || z_2y > z_i_y_bound || z_3y > z_i_y_bound || z_4y > z_i_y_bound {
            eprintln!("5");
            return false;
        }

        let a_bar = self.a_prime * issuer_private_key.x;
        eprintln!("verify, a_bar = {}", debug_hash(a_bar.to_bytes()));
        let h1 = G::generator() + params.h1 * self.bound + {
            let mut acc = G::identity();
            for (j, com_j) in self.com.iter().enumerate() {
                acc += com_j * Scalar::from(2u64.pow(j as u32));
            }
            acc.neg()
        };
        let a1 = self.a_prime * self.z_e + self.b_bar * self.z_r2 + a_bar * self.gamma.neg();
        let a2 = self.b_bar * self.z_r3
            + params.h1 * self.z_delta
            + params.h2 * self.z_k
            + params.h3 * self.z_s
            + h1 * self.gamma.neg();
        eprintln!("verify, a1 = {}", debug_hash(a1.to_bytes()));
        fiat_shamir.update(a1.to_bytes().as_ref());
        eprintln!("verify, a2 = {}", debug_hash(a2.to_bytes()));
        fiat_shamir.update(a2.to_bytes().as_ref());
        fiat_shamir.update(self.y.to_bytes().as_ref());

        for j in 0..(self.rate_limit_exponent as usize) {
            fiat_shamir.update(self.com[j].to_bytes().as_ref());
            let gamma1_j = self.gamma - self.gamma0[j];
            let c0_j = self.com[j];
            let c1_j = self.com[j] - params.h2;
            let c0_prime_j = params.h3 * self.z0[j] + c0_j * self.gamma0[j].neg();
            let c1_prime_j = params.h3 * self.z1[j] + c1_j * gamma1_j.neg();
            eprintln!(
                "verify, c0_prime_{} = {}",
                j,
                debug_hash(c0_prime_j.to_bytes())
            );
            fiat_shamir.update(c0_prime_j.to_bytes().as_ref());
            eprintln!(
                "verify, c1_prime_{} = {}",
                j,
                debug_hash(c1_prime_j.to_bytes())
            );
            fiat_shamir.update(c1_prime_j.to_bytes().as_ref());
        }

        let y1 = self.y * self.z_k.neg()
            + (params.h2
                - self.y
                    * (Scalar::from(2u64.pow(self.rate_limit_exponent))
                        * Scalar::from(self.epoch)))
                * self.gamma.neg();
        eprintln!("verify, y1 = {}", debug_hash(y1.to_bytes()));
        fiat_shamir.update(y1.to_bytes().as_ref());
        fiat_shamir.update(self.c_y.to_bytes().as_ref());

        let d_y = self.c_y * self.gamma.neg()
            + G::generator() * self.t_y
            + params.h1 * self.z_1y
            + params.h2 * self.z_2y
            + params.h3 * self.z_3y
            + params.h4 * self.z_4y;
        eprintln!("verify, d_y = {}", debug_hash(d_y.to_bytes()));
        fiat_shamir.update(d_y.to_bytes().as_ref());
        let f_star = self.gamma * self.z_delta
            - (self.z_1y.square() + self.z_2y.square() + self.z_3y.square() + self.z_4y.square());
        fiat_shamir.update(self.c_star.to_bytes().as_ref());
        let d_star =
            self.c_star * self.gamma.neg() + G::generator() * self.t_star + params.h1 * f_star;
        eprintln!("verify, d_star = {}", debug_hash(d_star.to_bytes()));
        fiat_shamir.update(d_star.to_bytes().as_ref());

        fiat_shamir.rph() == scalar_to_bigint(&self.gamma)
    }
}

fn scalar_to_bigint(s: &Scalar) -> BigUint {
    BigUint::from_bytes_le(s.as_bytes())
}

fn bigint_to_scalar(b: &BigUint) -> Option<Scalar> {
    use std::ops::Neg;
    let q = scalar_to_bigint(&(Scalar::ONE.neg())) + BigUint::from(1u64);
    if b >= &q {
        return None;
    }
    let b_bs = b.to_bytes_le();
    let mut s_bs = [0u8; 32];
    for i in 0..32 {
        if i >= b_bs.len() {
            break;
        }
        s_bs[i] = b_bs[i];
    }

    Some(Scalar::from_bytes_mod_order(s_bs))
}

fn debug_hash<B: AsRef<[u8]>>(b: B) -> String {
    format!("{}", blake3::hash(b.as_ref()))[0..6].into()
}
