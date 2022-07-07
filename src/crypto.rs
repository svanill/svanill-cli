use crate::format::{hex_to_bytes, SvanillBox, SvanillBoxV0};
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
    #[error("iterations necessary to derive the key exceed the allowed amount")]
    TooManyDeriveKeyIterations,
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
type Salt = [u8; SALT_BYTES_LENGTH];

fn generate_salt() -> Salt {
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

pub fn encrypt(b_plaintext: &[u8], password: &str, iterations: u32) -> Result<String, CryptoError> {
    let b_salt = generate_salt();
    let b_iv = generate_iv();

    encrypt_v0(
        SvanillBoxV0::new(iterations, b_salt, b_iv),
        b_plaintext,
        password.as_bytes(),
    )
}

fn encrypt_v0(
    sb: SvanillBoxV0,
    b_plaintext: &[u8],
    password: &[u8],
) -> Result<String, CryptoError> {
    // Derive PBKDF2 key
    let pbkdf2_key = derive_pbkdf2_hmac_sha256(password, sb.iterations, &sb.salt);

    // Setup the additional data
    let aad = aead::Aad::from(sb.aad);

    // IV must be used at most once per encryption
    let iv_as_nonce = aead::Nonce::assume_unique_for_key(sb.iv);
    let nonce_sequence = OneNonceSequence::new(iv_as_nonce);

    // Generate an encryption key
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &pbkdf2_key)
        .or(Err(CryptoError::LoadEncryptionKey))?;
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);

    // Ring uses the same input variable as output
    let mut in_out = b_plaintext.to_vec();

    // Encrypt data into in_out variable
    sealing_key
        .seal_in_place_append_tag(aad, &mut in_out)
        .or(Err(CryptoError::CannotEncrypt))?;

    // Box everything in a readable format
    Ok(sb.serialize(&in_out))
}

pub fn decrypt(maybe_hex_string: &[u8], password: &str, max_iterations: u32) -> Result<Vec<u8>> {
    let data = hex_to_bytes(maybe_hex_string)?;
    let (metadata, ciphertext) = SvanillBox::deserialize(&data)?;

    match metadata {
        SvanillBox::V0(sb) => {
            if sb.iterations > max_iterations {
                return Err(From::from(CryptoError::TooManyDeriveKeyIterations));
            }
            Ok(decrypt_v0(sb, &ciphertext, password.as_bytes())?)
        }
    }
}

fn decrypt_v0(
    sb: SvanillBoxV0,
    ciphertext: &[u8],
    b_password: &[u8],
) -> Result<Vec<u8>, CryptoError> {
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

    // Return decrytped_data, not in_out (it can be longer than the decrypted data)
    Ok(decrypted_data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_decrypt() -> Result<()> {
        let encrypted_blob =
            b"00000186a0a3bae66273a6d918cdfc148934bc765afff80179dd881c2bde91f4e65acb6c3fd7fc
            db3f08ef07d8d22a0ae951333716d7d5a1c74d41b9";

        let res = decrypt(encrypted_blob, "testpw", 100_000);
        assert_eq!(b"Hello World".to_vec(), res?);
        Ok(())
    }
    #[test]
    fn it_encrypt() -> Result<()> {
        // Without moking Ring::SecureRandom the easiest thing to do is to
        // feed the encrypt result to decrypt (whose tests are expected to pass)
        let b_plaintext = b"Hello World";
        let encrypted_blob = encrypt(b_plaintext, "testpw", 1)?;
        let res = decrypt(encrypted_blob.as_bytes(), "testpw", 2);
        assert_eq!(b"Hello World".to_vec(), res?);
        Ok(())
    }
}
