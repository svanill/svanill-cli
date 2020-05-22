use anyhow::{anyhow, Result};
use ring::aead;
use ring::pbkdf2;
use std::convert::TryInto;
use std::iter::Iterator;

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

    pub fn deserialize(data: &[u8]) -> Result<(SvanillBoxV0, Vec<u8>)> {
        // We need at least 33 bytes for ancillary data, plus the ciphertext
        if data.len() < 34 {
            return Err(anyhow!("Content is too short"));
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
    pub fn deserialize(data: &[u8]) -> Result<(SvanillBox, Vec<u8>)> {
        match data.get(0) {
            Some(0) => SvanillBoxV0::deserialize(&data).and_then(|(x,y)| Ok((x.into(),y))),
            Some(v) => Err(anyhow!(
                "Unsupported format: {}. Did you encrypt the data with a different (newer) version of Svanill?",v
            )),
            None => Err(anyhow!("Deserialize error: empty string")),
        }
    }
}

pub fn hex_to_bytes(hex_string: &[u8]) -> Result<Vec<u8>> {
    // remove spaces
    let hex_data: Vec<u8> = hex_string
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    // decode
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(&hex_data)
        .or_else(|_| Err(anyhow!("Decode error: not hex format")))
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
}
