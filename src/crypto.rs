extern crate data_encoding;
extern crate ring;

use ring::aead;
use ring::aead::BoundKey;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;

lazy_static! {
    static ref RNG: SystemRandom = ring::rand::SystemRandom::new();
}

fn derive_pbkdf2_hmac_sha256(
    b_password: &[u8],
    iterations: u32,
    salt: &[u8],
) -> [u8; digest::SHA256_OUTPUT_LEN] {
    let n_iter = NonZeroU32::new(iterations).unwrap();
    let mut pbkdf2_key = [0u8; digest::SHA256_OUTPUT_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        n_iter,
        salt,
        b_password,
        &mut pbkdf2_key,
    );
    pbkdf2_key
}

pub const IV_BYTES_LENGTH: usize = 12;
pub type IV = [u8; IV_BYTES_LENGTH];

pub fn generate_iv() -> IV {
    let mut nonce_vec = [0u8; IV_BYTES_LENGTH];
    RNG.fill(&mut nonce_vec).unwrap();
    nonce_vec
}

pub const SALT_BYTES_LENGTH: usize = 16;
pub type SALT = [u8; SALT_BYTES_LENGTH];

pub fn generate_salt() -> SALT {
    let mut nonce_vec = [0u8; SALT_BYTES_LENGTH];
    RNG.fill(&mut nonce_vec).unwrap();
    nonce_vec
}

struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

pub fn encrypt(
    plaintext: &str,
    password: &str,
    iterations: u32,
    b_salt: SALT,
    b_iv: IV,
) -> Result<String, String> {
    // Derive PBKDF2 key
    let pbkdf2_key = derive_pbkdf2_hmac_sha256(password.as_bytes(), iterations, &b_salt);

    // Gather additional data
    let b_version = 0u8.to_be_bytes();
    let b_iterations = iterations.to_be_bytes();

    let mut v_aad = Vec::<u8>::with_capacity(b_version.len() + b_iterations.len() + b_salt.len());
    v_aad.extend_from_slice(&b_version);
    v_aad.extend_from_slice(&b_iterations);
    v_aad.extend_from_slice(&b_salt);
    let aad = aead::Aad::from(v_aad.clone());

    // Ring uses the same input variable as output
    let mut in_out = plaintext.as_bytes().to_vec();

    // IV must be used at most once per encryption
    let iv_as_nonce = aead::Nonce::assume_unique_for_key(b_iv);
    let nonce_sequence = OneNonceSequence::new(iv_as_nonce);

    // Generate an encryption key
    let unbound_key =
        aead::UnboundKey::new(&aead::AES_256_GCM, &pbkdf2_key).expect("Could not load the key");
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);

    // Encrypt data into in_out variable
    sealing_key
        .seal_in_place_append_tag(aad, &mut in_out)
        .unwrap();

    // Box everything in a readable format
    export(&v_aad, &b_iv, &in_out)
}

fn get_pretty_hexencoder() -> data_encoding::Encoding {
    let mut spec = data_encoding::HEXLOWER.specification();
    spec.wrap.width = 78;
    spec.wrap.separator = String::from("\n");
    spec.encoding().unwrap()
}

fn export(aad: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<String, String> {
    let hex = get_pretty_hexencoder();
    let data: Vec<u8> = [aad, iv, ciphertext].concat();

    Ok(hex.encode(&data).trim().to_string())
}
