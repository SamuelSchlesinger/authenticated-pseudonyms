use bls12_381::{Bls12, G1Affine, G1Projective, G2Affine, Scalar};
use pairing::group::ff::Field;
use pairing::group::{Group, GroupEncoding};
use pairing::Engine;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use subtle::{Choice, ConstantTimeEq, CtOption};

use std::ops::Neg;

const CLIENT_ISSUANCE_LABEL: &[u8] = b"CLIENT_ISSUANCE";
const PSEUDONYM_LABEL: &[u8] = b"PSEUDONYM";
const GLOBAL_LABEL: &[u8] = b"SOCIAL_LOGIN";

/// Parameters for the protocol.
#[derive(Clone, Debug)]
pub struct Params {
    h: G1Affine,
}

impl Params {
    pub fn default() -> Self {
        let mut rng = ChaCha20Rng::from_seed(*blake3::hash(b"a very special string").as_bytes());
        Params {
            h: G1Projective::random(&mut rng).into(),
        }
    }
}

struct FiatShamir {
    hasher: blake3::Hasher,
}

impl FiatShamir {
    fn new(label: &[u8], nonce: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(GLOBAL_LABEL);
        hasher.update(G1Affine::label());
        hasher.update(label);
        hasher.update(nonce);
        FiatShamir { hasher }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    fn rng(&self) -> impl CryptoRngCore {
        ChaCha20Rng::from_seed(*self.hasher.finalize().as_bytes())
    }
}

trait HasLabel {
    fn label() -> &'static [u8];
}

impl HasLabel for G1Affine {
    fn label() -> &'static [u8] {
        b"BLS12_381"
    }
}

/// The private key of the issuer.
#[derive(Debug, Clone)]
pub struct IssuerPrivateKey {
    x: Scalar,
}

/// The public key of the issuer.
#[derive(Debug, Clone)]
pub struct IssuerPublicKey {
    w: G2Affine,
}

/// The private PRF key held by the client as they request credential issuance.
#[derive(Debug, Clone)]
pub struct ClientPrivateKey {
    k: Scalar,
}

/// The request sent to the server by the client, proving that they know their private key.
#[derive(Debug, Clone)]
pub struct CredentialRequest {
    big_k: G1Affine,
    // This zkp is not currently necessary (the commitment still is though), however if other
    // fields were to be included in this proof you'd need this, so it is useful to keep around.
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
    pub fn request(&self, params: &Params, mut rng: impl CryptoRngCore) -> CredentialRequest {
        let big_k = params.h * self.k;
        let k_prime = Scalar::random(&mut rng);
        let big_k_1 = params.h * k_prime;

        let gamma = {
            let mut fiat_shamir = FiatShamir::new(CLIENT_ISSUANCE_LABEL, b"");
            fiat_shamir.update(GroupEncoding::to_bytes(&big_k).as_ref());
            fiat_shamir.update(GroupEncoding::to_bytes(&big_k_1).as_ref());
            let mut fiat_shamir_rng = fiat_shamir.rng();

            Scalar::random(&mut fiat_shamir_rng)
        };

        let k_bar = gamma * self.k + k_prime;

        CredentialRequest {
            big_k: big_k.into(),
            gamma,
            k_bar,
        }
    }
}

/// The response the server sends back upon a request for issuance.
#[derive(Debug, Clone)]
pub struct CredentialResponse {
    a: G1Affine,
    e: Scalar,
}

impl CredentialRequest {
    /// Responds to the given credential request with the data needed for the client to construct a
    /// new credential.
    pub fn respond(
        &self,
        issuer_private_key: &IssuerPrivateKey,
        params: &Params,
        mut rng: impl CryptoRngCore,
    ) -> Option<CredentialResponse> {
        let big_k_1 = params.h * self.k_bar + self.big_k * self.gamma.neg();
        let client_gamma = {
            let mut fiat_shamir = FiatShamir::new(CLIENT_ISSUANCE_LABEL, b"");
            fiat_shamir.update(G1Affine::from(self.big_k).to_compressed().as_ref());
            fiat_shamir.update(G1Affine::from(big_k_1).to_compressed().as_ref());
            let mut fiat_shamir_rng = fiat_shamir.rng();
            Scalar::random(&mut fiat_shamir_rng)
        };

        if client_gamma != self.gamma {
            return None;
        }

        let e = Scalar::random(&mut rng);
        let a = (G1Affine::generator() + G1Projective::from(&self.big_k))
            * (e + issuer_private_key.x).invert().unwrap();
        Some(CredentialResponse { a: a.into(), e })
    }
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
            w: (G2Affine::generator() * self.x).into(),
        }
    }
}

/// A credential which the client holds privately.
#[derive(Debug, Clone)]
pub struct Credential {
    a: G1Affine,
    e: Scalar,
    k: Scalar,
}

impl ClientPrivateKey {
    /// Creates a new credential using the original request, response from the server, and the
    /// client's private PRF key.
    pub fn create_credential(
        &self,
        request: &CredentialRequest,
        response: &CredentialResponse,
        issuer_public_key: &IssuerPublicKey,
    ) -> Option<Credential> {
        if Bls12::pairing(&response.a, &issuer_public_key.w)
            != Bls12::pairing(
                &(response.a * response.e.neg() + G1Affine::generator() + request.big_k).into(),
                &G2Affine::generator(),
            )
        {
            return None;
        }

        Some(Credential {
            a: response.a,
            e: response.e,
            k: self.k,
        })
    }
}

impl Credential {
    /// Verify the validity of the given credential.
    pub fn verify(&self, params: &Params, issuer_public_key: &IssuerPublicKey) -> Choice {
        Bls12::pairing(&self.a, &issuer_public_key.w).ct_eq(&Bls12::pairing(
            &G1Affine::from(&self.a * self.e.neg() + G1Affine::generator() + params.h * self.k),
            &G2Affine::generator(),
        ))
    }

    pub fn vrf_key(&self) -> &Scalar {
        &self.k
    }
}

/// A local pseudonym derived for a particular context.
#[derive(Debug, Clone)]
pub struct Pseudonym {
    relying_party_id: Scalar,
    a_prime: G1Affine,
    b_bar: G1Affine,
    a_bar: G1Affine,
    y: G1Affine,
    gamma: Scalar,
    z_e: Scalar,
    z_r2: Scalar,
    z_r3: Scalar,
    z_k: Scalar,
}

impl Credential {
    /// Compute a pseudonym for the given context.
    pub fn pseudonym_for(
        &self,
        params: &Params,
        relying_party_id: Scalar,
        nonce: &[u8],
        mut rng: impl CryptoRngCore,
    ) -> CtOption<Pseudonym> {
        let mut fiat_shamir = FiatShamir::new(PSEUDONYM_LABEL, nonce);

        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let e_prime = Scalar::random(&mut rng);
        let r2_prime = Scalar::random(&mut rng);
        let r3_prime = Scalar::random(&mut rng);
        let k_prime = Scalar::random(&mut rng);

        let b = G1Affine::generator() + params.h * self.k;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let a_bar = a_prime * self.e.neg() + b_bar * r2;
        let r3 = r1.invert();

        fiat_shamir.update(GroupEncoding::to_bytes(&a_prime).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&b_bar).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&a_bar).as_ref());

        let a1 = a_prime * e_prime + b_bar * r2_prime;
        let a2 = b_bar * r3_prime + params.h * k_prime;

        fiat_shamir.update(GroupEncoding::to_bytes(&a1).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&a2).as_ref());

        let y = G1Affine::generator() * (self.k + relying_party_id).invert().unwrap();

        fiat_shamir.update(GroupEncoding::to_bytes(&y).as_ref());

        let y1 = y * k_prime.neg();

        fiat_shamir.update(GroupEncoding::to_bytes(&y1).as_ref());

        let gamma = Scalar::random(fiat_shamir.rng());

        let z_e = gamma.neg() * self.e + e_prime;
        let z_r2 = gamma * r2 + r2_prime;
        let z_r3 = r3.map(|r3| gamma * r3 + r3_prime);
        let z_k = gamma.neg() * self.k + k_prime;

        z_r3.map(|z_r3| Pseudonym {
            relying_party_id,
            a_prime: a_prime.into(),
            b_bar: b_bar.into(),
            a_bar: a_bar.into(),
            y: y.into(),
            gamma,
            z_e,
            z_r2,
            z_r3,
            z_k,
        })
    }
}

impl Pseudonym {
    /// Verify the pseudonym's correctness.
    pub fn verify(
        &self,
        params: &Params,
        issuer_public_key: &IssuerPublicKey,
        nonce: &[u8],
    ) -> Choice {
        let mut choice = Choice::from(1);

        choice &= !self.a_prime.ct_eq(&G1Affine::identity());
        choice &= Bls12::pairing(&self.a_prime, &issuer_public_key.w)
            .ct_eq(&Bls12::pairing(&self.a_bar, &G2Affine::generator()));

        let mut fiat_shamir = FiatShamir::new(PSEUDONYM_LABEL, nonce);

        fiat_shamir.update(GroupEncoding::to_bytes(&self.a_prime).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&self.b_bar).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&self.a_bar).as_ref());

        let a1 = self.a_prime * self.z_e + self.b_bar * self.z_r2 + self.a_bar * self.gamma.neg();
        let a2 =
            self.b_bar * self.z_r3 + params.h * self.z_k + G1Affine::generator() * self.gamma.neg();

        fiat_shamir.update(GroupEncoding::to_bytes(&a1).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&a2).as_ref());

        fiat_shamir.update(GroupEncoding::to_bytes(&self.y).as_ref());

        let y1 = self.y * self.z_k.neg()
            + (G1Affine::generator() - self.y * self.relying_party_id) * self.gamma.neg();

        fiat_shamir.update(GroupEncoding::to_bytes(&y1).as_ref());

        let gamma = Scalar::random(fiat_shamir.rng());

        choice &= gamma.ct_eq(&self.gamma);

        choice
    }

    /// Return which relying party this pseudonym is meant for.
    pub fn relying_party_id(&self) -> &Scalar {
        &self.relying_party_id
    }

    /// Return the pseudonym ID which can be compared to other pseudonym IDs.
    pub fn pseudonym_id(&self) -> &G1Affine {
        &self.y
    }
}

#[test]
fn test() {
    for _ in 0..10 {
        use rand_core::OsRng;
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key, &params, OsRng)
            .unwrap();
        let cred1 = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key.public())
            .unwrap();
        assert!(bool::from(
            cred1.verify(&params, &issuer_private_key.public())
        ));
        let relying_party_id = Scalar::random(OsRng);
        let pseudonym1 = cred1
            .pseudonym_for(&params, relying_party_id, b"nonce", OsRng)
            .unwrap();
        assert!(bool::from(pseudonym1.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        assert_eq!(pseudonym1.relying_party_id(), &relying_party_id);
    }
}
