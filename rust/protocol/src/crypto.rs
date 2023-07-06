//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use std::convert::TryInto;
use std::result::Result;

use aes::cipher::{NewCipher, StreamCipher};
use aes::{Aes256, Aes256Ctr};
use block_modes::block_padding::{Padding, Pkcs7};
use block_modes::{BlockMode, Cbc};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

#[derive(Debug)]
pub enum EncryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EncryptionError::BadKeyOrIv => write!(f, "BadKeyOrIv"),
        }
    }
}

#[derive(Debug)]
pub enum DecryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
    /// Either the input is malformed, or the MAC doesn't match on decryption.
    ///
    /// These cases should not be distinguished; message corruption can cause either problem.
    BadCiphertext(&'static str, Option<String>),
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecryptionError::BadKeyOrIv => write!(f, "BadKeyOrIv"),
            DecryptionError::BadCiphertext(desc, detail) => {
                let default = "--".to_string();
                let detail = if detail.is_some() {
                    detail.as_ref().unwrap()
                } else {
                    &default
                };
                write!(f, "BadCiphertext: {}: {}", desc, detail)
            }
        }
    }
}

fn aes_256_ctr_encrypt(ptext: &[u8], key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let key: [u8; 32] = key.try_into().map_err(|_| EncryptionError::BadKeyOrIv)?;

    let zero_nonce = [0u8; 16];
    let mut cipher = Aes256Ctr::new(key[..].into(), zero_nonce[..].into());

    let mut ctext = ptext.to_vec();
    cipher.apply_keystream(&mut ctext);
    Ok(ctext)
}

fn aes_256_ctr_decrypt(ctext: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptionError> {
    aes_256_ctr_encrypt(ctext, key).map_err(|e| match e {
        EncryptionError::BadKeyOrIv => DecryptionError::BadKeyOrIv,
    })
}

pub fn aes_256_cbc_encrypt(
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    match Cbc::<Aes256, Pkcs7>::new_from_slices(key, iv) {
        Ok(mode) => Ok(mode.encrypt_vec(ptext)),
        Err(block_modes::InvalidKeyIvLength) => Err(EncryptionError::BadKeyOrIv),
    }
}

pub fn aes_256_cbc_decrypt(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(DecryptionError::BadCiphertext(
            "ciphertext length must be a non-zero multiple of 16",
            None,
        ));
    }

    let mode =
        Cbc::<Aes256, Pkcs7>::new_from_slices(key, iv).map_err(|_| DecryptionError::BadKeyOrIv)?;
    mode.decrypt_vec(ctext)
        .map_err(|e| DecryptionError::BadCiphertext("failed to decrypt", Some(e.to_string())))
}

pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 should accept any size key");
    hmac.update(input);
    hmac.finalize().into_bytes().into()
}

pub(crate) fn aes256_ctr_hmacsha256_encrypt(
    msg: &[u8],
    cipher_key: &[u8],
    mac_key: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let mut ctext = aes_256_ctr_encrypt(msg, cipher_key)?;
    let mac = hmac_sha256(mac_key, &ctext);
    ctext.extend_from_slice(&mac[..10]);
    Ok(ctext)
}

pub(crate) fn aes256_ctr_hmacsha256_decrypt(
    ctext: &[u8],
    cipher_key: &[u8],
    mac_key: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if ctext.len() < 10 {
        return Err(DecryptionError::BadCiphertext("truncated ciphertext", None));
    }
    let ptext_len = ctext.len() - 10;
    let our_mac = hmac_sha256(mac_key, &ctext[..ptext_len]);
    let same: bool = our_mac[..10].ct_eq(&ctext[ptext_len..]).into();
    if !same {
        return Err(DecryptionError::BadCiphertext(
            "MAC verification failed",
            None,
        ));
    }
    aes_256_ctr_decrypt(&ctext[..ptext_len], cipher_key)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn aes_cbc_test() {
        let key = hex::decode("4e22eb16d964779994222e82192ce9f747da72dc4abe49dfdeeb71d0ffe3796e")
            .expect("valid hex");
        let iv = hex::decode("6f8a557ddc0a140c878063a6d5f31d3d").expect("valid hex");

        let ptext = hex::decode("30736294a124482a4159").expect("valid hex");

        let ctext = aes_256_cbc_encrypt(&ptext, &key, &iv).expect("valid key and IV");
        assert_eq!(
            hex::encode(ctext.clone()),
            "dd3f573ab4508b9ed0e45e0baf5608f3"
        );

        let recovered = aes_256_cbc_decrypt(&ctext, &key, &iv).expect("valid");
        assert_eq!(hex::encode(ptext), hex::encode(recovered.clone()));

        // padding is invalid:
        assert!(aes_256_cbc_decrypt(&recovered, &key, &iv).is_err());
        assert!(aes_256_cbc_decrypt(&ctext, &key, &ctext).is_err());

        // bitflip the IV to cause a change in the recovered text
        let bad_iv = hex::decode("ef8a557ddc0a140c878063a6d5f31d3d").expect("valid hex");
        let recovered = aes_256_cbc_decrypt(&ctext, &key, &bad_iv).expect("still valid");
        assert_eq!(hex::encode(recovered), "b0736294a124482a4159");
    }

    #[test]
    fn aes_ctr_test() {
        let key = hex::decode("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
            .expect("valid hex");
        let ptext = [0u8; 35];

        let ctext = aes_256_ctr_encrypt(&ptext, &key).expect("valid key");
        assert_eq!(
            hex::encode(ctext),
            "e568f68194cf76d6174d4cc04310a85491151e5d0b7a1f1bc0d7acd0ae3e51e4170e23"
        );
    }
}
