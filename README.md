# Authenticated Pseudonyms

This project is intended for demonstration purposes only. It is not intended
for use in a production environment. It currently contains unaudited,
experimental cryptography which is not suited for production environments.

[![Rust](https://github.com/SamuelSchlesinger/authenticated-pseudonyms/actions/workflows/rust.yml/badge.svg)](https://github.com/SamuelSchlesinger/authenticated-pseudonyms/actions/workflows/rust.yml)

In many circumstances, one wants to authenticate in an anonymous or
pseudonymous way. For this purpose, we can think of anonymity as a single use
pseudonym. In that sense, authenticated pseudonyms can be a powerful primitive
for anonymous authentication and authorization. They can enable anonymous
rate limiting schemes, local pseudonyms for identity, and even anonymous voting
schemes.

In our work, we rely on the BBS signature scheme, and the Dodis-Yampolskiy VRF.
We utilize both the publicly verifiable and privately verifiable variants of
BBS, yielding approaches with various cryptography
assumptions and capabilities. Our publicly verifiable approaches rely on
pairings, and we use the BLS12-381 pairing in this implementation. Our
privately verifiable approach does not rely on pairings, and we instantiate
that with Ristretto.

The basic idea is to use as your credential a BBS signature of a VRF key, which
you obscure before sending to the signer. Then, when you show your BBS
signature, you include the output of the VRF and a zero-knowledge proof of
correctness of this output, connected to the BBS signature proof via a DLEQ
proof.  On top of this, you can also have other fields in the BBS signature and
prove various things about them. In our rate limited approach, we prove
something about the VRF input, mainly that one of the inputs is a number
between `0` and `RATE_LIMIT - 1`, and the other is the value representing the
current epoch where we permit up to `RATE_LIMIT` requests. The `RATE_LIMIT`
must be a power of two, as we use a binary decomposition based range proof.

Our main use case is signing `(k, t)` where `t` is some other value decided by
the issuer. We prove that `t <= BOUND` for some publicly known bound, as well
as rate limiting in the way I describe above. Thus, each token requires two
range proofs. Because we are signing the input `t` to the `t <= BOUND` range
proof, we can use an approximate approach called SHARP in order to create a
more efficient range proof. There are examples of this approach below.

# Examples

## Publicly Verifiable Age Range Proof with Rate Limiting

```rust
// globally decided upon amongst all parties
let params = Params::default();

// on issuer
let issuer_private_key = IssuerPrivateKey::random(OsRng);

// on client
let client_private_key = ClientPrivateKey::random(OsRng);
let credential_request = client_private_key.credential_request(&params, OsRng);

// on issuer
let t = 1; // for instance the current minute
let credential_response = credential_request.respond(
    &issuer_private_key,
    &issuer_private_key.public(),
    &params,
    t,
    OsRng).unwrap();

// on client
let credential = client_private_key.create_credential(
    &params,
    &credential_request,
    &credential_response,
    &issuer_public_key).unwrap();
let epoch = 0; // for instance the current day
let bound = 2; // for instance five days in the past
let rate_limit_exponent = 10; // rate limit = 2^10
let i = 0; // anything under 2^10
let proof = credential.prove(
    &params,
    bound,
    epoch,
    OsRng,
    rate_limit_exponent,
    i);

if let Some(_extant) = db.lookup(proof.rate_limiting_token()) {
    panic!("reused i");
}

// on issuer
assert!(proof.verify(
    &params,
    &issuer_public_key)
    && proof.bound() == 2
    && proof.epoch() == 2
    && proof.rate_limit_exponent() == 10
);

db.insert(proof.rate_limiting_token());
```

## Privately Verifiable Age Range Proof with Rate Limiting

```rust
// globally decided upon amongst all parties
let params = Params::default();

// on issuer
let issuer_private_key = IssuerPrivateKey::random(OsRng);

// on client
let client_private_key = ClientPrivateKey::random(OsRng);
let credential_request = client_private_key.credential_request(&params, OsRng);

// on issuer
let t = 1; // for instance the current minute
let credential_response = credential_request.respond(
    &issuer_private_key,
    &issuer_private_key.public(),
    &params,
    t,
    OsRng).unwrap();

// on client
let credential = client_private_key.create_credential(
    &params,
    &credential_request,
    &credential_response,
    &issuer_public_key).unwrap();
let epoch = 0; // for instance the current day
let bound = 2; // for instance five days in the past
let rate_limit_exponent = 10; // rate limit = 2^10
let i = 0; // anything under 2^10
let proof = credential.prove(
    &params,
    bound,
    epoch,
    OsRng,
    rate_limit_exponent,
    i);

if let Some(_extant) = db.lookup(proof.rate_limiting_token()) {
    panic!("reused i");
}

// on issuer
assert!(proof.verify(
    &params,
    &issuer_private_key)
    && proof.bound() == 2
    && proof.epoch() == 2
    && proof.rate_limit_exponent() == 10
);

db.insert(proof.rate_limiting_token());
```

This is not an officially supported Google product. This project is not
eligible for the [Google Open Source Software Vulnerability Rewards
Program](https://bughunters.google.com/open-source-security).
