use ring::aead;
use ring::pbkdf2;
use std::convert::TryInto;
use std::iter::Iterator;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HexError {
    #[error("not in hex format")]
    CannotDecode,
}

#[derive(Error, Debug)]
pub enum SvanillBoxError {
    #[error("cannot parse, the data is empty")]
    EmptyString,
    #[error("encrypted content is too short")]
    ContentTooShort,
    #[error("Unsupported format `{0}`. Did you encrypt the data with a different (newer) version of Svanill?")]
    UnsupportedFormat(u8),
}

fn get_pretty_hexencoder() -> data_encoding::Encoding {
    let mut spec = data_encoding::HEXLOWER.specification();
    spec.wrap.width = 78;
    spec.wrap.separator = String::from("\n");
    spec.encoding().unwrap()
}

pub struct SvanillBoxV0 {
    #[allow(dead_code)]
    version: u8,
    pub iterations: u32,
    pub salt: [u8; 16],
    pub iv: [u8; 12],
    pub aad: [u8; 21],
    #[allow(dead_code)]
    alg_key: ring::pbkdf2::Algorithm,
    #[allow(dead_code)]
    alg_cipher: &'static aead::Algorithm,
}

impl SvanillBoxV0 {
    pub fn new(iterations: u32, salt: [u8; 16], iv: [u8; 12]) -> Self {
        let mut aad: [u8; 21] = [0; 21];
        // aad[0], version, is already zero
        aad[1..5].copy_from_slice(&iterations.to_be_bytes());
        aad[5..21].copy_from_slice(&salt);

        Self {
            version: 0,
            iterations,
            salt,
            iv,
            aad,
            alg_key: pbkdf2::PBKDF2_HMAC_SHA256,
            alg_cipher: &aead::AES_256_GCM,
        }
    }

    pub fn to_vec(&self, content: &[u8]) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::with_capacity(self.aad.len() + self.iv.len() + content.len());
        data.extend_from_slice(&self.aad);
        data.extend_from_slice(&self.iv);
        data.extend_from_slice(content);
        data
    }

    pub fn serialize(&self, ciphertext: &[u8]) -> String {
        let hex = get_pretty_hexencoder();
        hex.encode(&self.to_vec(ciphertext)).trim().to_string()
    }

    pub fn deserialize(data: &[u8]) -> Result<(SvanillBoxV0, Vec<u8>), SvanillBoxError> {
        // We need at least 33 bytes for ancillary data, plus the ciphertext
        if data.len() < 34 {
            return Err(SvanillBoxError::ContentTooShort);
        }

        // iterations, 4 bytes
        let b_iterations: [u8; 4] = data[1..5].try_into().unwrap();

        Ok((
            SvanillBoxV0::new(
                // iterations, 4 bytes
                u32::from_be_bytes(b_iterations),
                // salt, 16 bytes
                data[5..21].try_into().unwrap(),
                // iv, 12 bytes
                data[21..33].try_into().unwrap(),
            ),
            // cyphertext|tag
            data[33..].to_vec(),
        ))
    }
}

pub enum SvanillBox {
    V0(SvanillBoxV0),
}

impl From<SvanillBoxV0> for SvanillBox {
    fn from(sb: SvanillBoxV0) -> Self {
        SvanillBox::V0(sb)
    }
}

impl SvanillBox {
    pub fn deserialize(data: &[u8]) -> Result<(SvanillBox, Vec<u8>), SvanillBoxError> {
        match data.get(0) {
            Some(0) => SvanillBoxV0::deserialize(data).map(|(x, y)| (x.into(), y)),
            Some(v) => Err(SvanillBoxError::UnsupportedFormat(v.to_owned())),
            None => Err(SvanillBoxError::EmptyString),
        }
    }
}

pub fn hex_to_bytes(hex_string: &[u8]) -> Result<Vec<u8>, HexError> {
    // remove spaces
    let hex_data: Vec<u8> = hex_string
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    // decode
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(&hex_data)
        .map_err(|_| HexError::CannotDecode)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod hex_to_bytes_tests {
        use super::*;

        #[test]
        fn it_converts_hex_to_bytes() {
            let hexstr = b"0010";
            let bytes = vec![0, 16];
            assert_eq!(bytes, hex_to_bytes(hexstr).unwrap());
        }

        #[test]
        fn it_is_case_insenstive() {
            let hexstr = b"a0A0";
            let bytes = vec![160, 160];
            assert_eq!(bytes, hex_to_bytes(hexstr).unwrap());
        }

        #[test]
        fn it_ignores_whitespaces() {
            let hexstr = b" 0\r0\n1\n\n\r\n0\n";
            let bytes = vec![0, 16];
            assert_eq!(bytes, hex_to_bytes(hexstr).unwrap());
        }

        #[test]
        fn it_converts_the_empty_string() {
            let hexstr = b"";
            let bytes: Vec<u8> = Vec::new();
            assert_eq!(bytes, hex_to_bytes(hexstr).unwrap());
        }

        #[test]
        fn it_err_on_nonhex_data() {
            let hexstr = b"foobar";
            assert!(hex_to_bytes(hexstr).is_err());
        }
    }

    mod svanillboxv0_tests {
        use super::*;

        #[test]
        fn it_implements_to_vec_with_the_right_sequence() {
            let iterations = u32::from_be_bytes([1, 1, 1, 1]);
            let salt = [2; 16];
            let iv = [3; 12];
            let sb = SvanillBoxV0::new(iterations, salt, iv);
            let content = [4; 5];

            let sb_vec = sb.to_vec(&content);
            assert_eq!(
                b"01111222222222222222233333333333344444"
                    .iter()
                    .map(|x| x - 48) // 48 is ascii ord for char '0'
                    .collect::<Vec<u8>>(),
                sb_vec,
            );
        }

        #[test]
        fn it_serializes_to_hex() {
            let iterations = u32::from_be_bytes([1, 1, 1, 1]);
            let salt = [2; 16];
            let iv = [3; 12];
            let sb = SvanillBoxV0::new(iterations, salt, iv);
            let content = [4; 9];

            assert_eq!(
                String::from("000101010102020202020202020202020202020202030303030303030303030303040404040404\n040404"),
                sb.serialize(&content),
            );
        }

        #[test]
        fn it_deserialize() {
            let b_version = [0];
            let b_iterations = [0, 0, 0, 1];
            let b_salt = [2; 16];
            let b_iv = [3; 12];
            let b_orig_content = [4; 9];

            let mut data: Vec<u8> = Vec::with_capacity(42);
            data.extend_from_slice(&b_version);
            data.extend_from_slice(&b_iterations);
            data.extend_from_slice(&b_salt);
            data.extend_from_slice(&b_iv);
            data.extend_from_slice(&b_orig_content);

            let (sb, content) = SvanillBoxV0::deserialize(&data).unwrap();

            assert_eq!(0, sb.version);
            assert_eq!(1, sb.iterations);
            assert_eq!(b_salt.to_vec(), sb.salt);
            assert_eq!(b_iv.to_vec(), sb.iv);
            assert_eq!(b_orig_content.to_vec(), content);
        }
    }

    mod svanillbox_tests {
        use super::*;

        #[test]
        fn it_deserialize_v0_format() -> Result<(), SvanillBoxError> {
            let data = hex_to_bytes(b"000000000102020202020202020202020202020202030303030303030303030303040404040404\n040404").unwrap();
            let (sb, content) = SvanillBox::deserialize(&data)?;

            assert!(match sb {
                SvanillBox::V0(_) => true,
            });

            assert_eq!([4u8; 9].to_vec(), content);

            Ok(())
        }

        #[test]
        fn it_deserialize_unsupported_format() {
            let hexstr = String::from("01000000000");
            let res = SvanillBox::deserialize(hexstr.as_bytes());

            assert!(res.is_err());
        }
    }
}
