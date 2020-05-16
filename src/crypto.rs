extern crate data_encoding;
extern crate ring;

use crate::format::{SvanillBox, SvanillBoxV0};
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
    let b_plaintext: &[u8] = plaintext.as_bytes();
    encrypt_v0(
        SvanillBoxV0::new(iterations, b_salt, b_iv),
        b_plaintext,
        password,
    )
}

pub fn encrypt_v0(sb: SvanillBoxV0, plaintext: &[u8], password: &str) -> Result<String, String> {
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
    let unbound_key =
        aead::UnboundKey::new(&aead::AES_256_GCM, &pbkdf2_key).expect("Could not load the key");
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);

    let mut in_out = plaintext.to_vec();

    // Encrypt data into in_out variable
    sealing_key
        .seal_in_place_append_tag(aad, &mut in_out)
        .unwrap();

    // Box everything in a readable format
    Ok(sb.serialize(&in_out))
}

pub fn decrypt(maybe_hex_string: &str, password: &str) -> Result<String, String> {
    let (metadata, ciphertext) = SvanillBox::deserialize(maybe_hex_string)?;

    match metadata {
        SvanillBox::V0(sb) => decrypt_v0(sb, &ciphertext, password.as_bytes()),
    }
}

fn decrypt_v0(sb: SvanillBoxV0, ciphertext: &[u8], b_password: &[u8]) -> Result<String, String> {
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
        .or(Err("Cannot decrypt (wrong password?)".to_string()))?;

    Ok(String::from_utf8(decrypted_data.to_vec()).expect("Expected utf-8"))
}
