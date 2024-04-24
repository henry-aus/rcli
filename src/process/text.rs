use crate::{process_genpass, TextSignFormat};
use anyhow::Result;

use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::aead::generic_array::GenericArray;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305,
};
use sha2::Digest;
use sha2::Sha256;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::{
    collections::HashMap,
    io::{Read, Write},
};

pub trait TextSigner {
    // signer could sign any input data
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    // verifier could verify any input data
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

pub trait Encryptor {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait Decryptor {
    fn decrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub struct ChaChaPoly1305 {
    key: String,
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let signature = Signature::from_bytes(sig);
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}

impl ChaChaPoly1305 {
    pub fn new(key: String) -> Self {
        Self { key }
    }

    fn normalized_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.key.as_bytes());
        let result = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&result[..]);
        hash_bytes
    }
}

impl Encryptor for ChaChaPoly1305 {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let key = self.normalized_key();
        let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        let mut obsf = cipher.encrypt(&nonce, &buf[..])?;
        obsf.splice(..0, nonce.iter().copied());
        let encrypt_base64_result = URL_SAFE_NO_PAD.encode(obsf);
        Ok(encrypt_base64_result.as_bytes().to_vec())
    }
}

impl Decryptor for ChaChaPoly1305 {
    fn decrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;
        let key = self.normalized_key();
        let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        let base64_decode_result = URL_SAFE_NO_PAD.decode(buf)?;
        // Get nonce from payload.
        let (nonce, ciphertext) = base64_decode_result.split_at(NonceSize::to_usize());
        let nonce = GenericArray::from_slice(nonce);
        let plaintext = cipher.decrypt(nonce, ciphertext)?;
        //String::from_utf8(plaintext).unwrap()
        Ok(plaintext)
    }
}

impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to &[u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk: SigningKey = SigningKey::generate(&mut csprng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.to_bytes().to_vec());
        map.insert("ed25519.pk", pk.to_bytes().to_vec());

        Ok(map)
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8], // (ptr, length)
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
    };

    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

pub fn process_text_encrypt(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    key: String,
) -> Result<()> {
    let encryptor = ChaChaPoly1305::new(key);
    let content = encryptor.encrypt(reader)?;
    let _ = writer.write_all(&content[..]);
    Ok(())
}

pub fn process_text_decrypt(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    key: String,
) -> Result<()> {
    let decryptor = ChaChaPoly1305::new(key);
    let content = decryptor.decrypt(reader)?;
    let _ = writer.write_all(&content[..]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = TextSignFormat::Blake3;
        let sig = "33Ypo4rveYpWmJKAiGnnse-wHQhMVujjmcVkV4Tl43k";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_encrypt_decrypt() -> Result<()> {
        let mut encrypt_reader = "hello".as_bytes();
        let mut encrypt_writer = Vec::new();
        let mut decrypt_writer = Vec::new();
        let key = "abc".to_string();
        let _ = process_text_encrypt(&mut encrypt_reader, &mut encrypt_writer, key.clone());
        //println!("{:?}", String::from_utf8(encrypt_writer.clone()));
        let mut decrypt_reader: &[u8] = &encrypt_writer;
        let _ = process_text_decrypt(&mut decrypt_reader, &mut decrypt_writer, key);
        let result = String::from_utf8(decrypt_writer)?;
        //println!("{:?}", &result);
        assert_eq!("hello", result);
        Ok(())
    }

    #[test]
    fn test_process_text_decrypt() -> Result<()> {
        let mut decrypt_writer = Vec::new();
        let key = "abc".to_string();
        let mut decrypt_reader: &[u8] = "YHrdNb2VSVEaj7iYn2zTQoE_60QxY6gsKYqzdEiAiPbH".as_bytes();
        let _ = process_text_decrypt(&mut decrypt_reader, &mut decrypt_writer, key);
        let result = String::from_utf8(decrypt_writer)?;
        //println!("{:?}", &result);
        assert_eq!("hello", result);
        Ok(())
    }
}
