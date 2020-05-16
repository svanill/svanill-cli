use crate::format::{SvanillBox, SvanillBoxV0};
use ring::aead;
use ring::aead::BoundKey;
use ring::rand::SecureRandom;
use ring::rand::SystemRandom;
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;

use anyhow::Result;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("decryption failure (wrong password?)")]
    CannotDecrypt,
    #[error("encryption failure")]
    CannotEncrypt,
    #[error("cannot correctly load the encryption key")]
    LoadEncryptionKey,
}

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

const IV_BYTES_LENGTH: usize = 12;
type IV = [u8; IV_BYTES_LENGTH];

fn generate_iv() -> IV {
    let mut nonce_vec = [0u8; IV_BYTES_LENGTH];
    RNG.fill(&mut nonce_vec).unwrap();
    nonce_vec
}

const SALT_BYTES_LENGTH: usize = 16;
type SALT = [u8; SALT_BYTES_LENGTH];

fn generate_salt() -> SALT {
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

pub fn encrypt(plaintext: &str, password: &str, iterations: u32) -> Result<String, CryptoError> {
    let b_plaintext: &[u8] = plaintext.as_bytes();
    let b_salt = generate_salt();
    let b_iv = generate_iv();

    encrypt_v0(
        SvanillBoxV0::new(iterations, b_salt, b_iv),
        b_plaintext,
        password,
    )
}

fn encrypt_v0(sb: SvanillBoxV0, plaintext: &[u8], password: &str) -> Result<String, CryptoError> {
    // Derive PBKDF2 key
    let pbkdf2_key = derive_pbkdf2_hmac_sha256(password.as_bytes(), sb.iterations, &sb.salt);

    // Setup the additional data
    let aad = aead::Aad::from(sb.aad);

    // Ring uses the same input variable as output
    //let mut in_out = &mut sb.content;

    // IV must be used at most once per encryption
    let iv_as_nonce = aead::Nonce::assume_unique_for_key(sb.iv);
    let nonce_sequence = OneNonceSequence::new(iv_as_nonce);

    // Generate an encryption key
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &pbkdf2_key)
        .or(Err(CryptoError::LoadEncryptionKey))?;
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);

    let mut in_out = plaintext.to_vec();

    // Encrypt data into in_out variable
    sealing_key
        .seal_in_place_append_tag(aad, &mut in_out)
        .or(Err(CryptoError::CannotEncrypt))?;

    // Box everything in a readable format
    Ok(sb.serialize(&in_out))
}

pub fn decrypt(maybe_hex_string: &str, password: &str) -> Result<String> {
    let (metadata, ciphertext) = SvanillBox::deserialize(maybe_hex_string)?;

    match metadata {
        SvanillBox::V0(sb) => Ok(decrypt_v0(sb, &ciphertext, password.as_bytes())?),
    }
}

fn decrypt_v0(
    sb: SvanillBoxV0,
    ciphertext: &[u8],
    b_password: &[u8],
) -> Result<String, CryptoError> {
    // Derive PBKDF2 key
    let pbkdf2_key = derive_pbkdf2_hmac_sha256(b_password, sb.iterations, &sb.salt);

    // Setup iv for Ring use
    let nonce = ring::aead::Nonce::assume_unique_for_key(sb.iv);

    // Setup the additional data
    let aad: aead::Aad<Vec<u8>> = aead::Aad::from(sb.aad.to_vec());

    // Generate a decryption key
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &pbkdf2_key).unwrap();
    let opening_key = aead::LessSafeKey::new(unbound_key);

    // Ring uses the same input variable as output
    let mut in_out = ciphertext.to_vec();

    // Decrypt data into in_out variable
    let decrypted_data = opening_key
        .open_in_place(nonce, aad, &mut in_out)
        .or(Err(CryptoError::CannotDecrypt))?;

    Ok(String::from_utf8(decrypted_data.to_vec()).expect("Expected utf-8"))
}
