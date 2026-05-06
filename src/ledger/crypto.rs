use super::*;

impl Ledger {
    fn cipher(&self) -> Option<Aes256Gcm> {
        self.enc_key.as_ref().map(|k| {
            let key = Key::<Aes256Gcm>::from_slice(k.as_bytes());
            Aes256Gcm::new(key)
        })
    }

    pub(crate) fn encrypt_value(&self, plaintext: &[u8]) -> Result<Vec<u8>, sled::Error> {
        let Some(cipher) = self.cipher() else {
            return Ok(plaintext.to_vec());
        };
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| sled::Error::Unsupported(format!("encrypt failed: {e}")))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub(crate) fn decrypt_value(&self, bytes: &[u8]) -> Result<Vec<u8>, sled::Error> {
        let Some(cipher) = self.cipher() else {
            return Ok(bytes.to_vec());
        };
        if bytes.len() < 12 {
            return Err(sled::Error::Unsupported("ciphertext too short".into()));
        }
        let (nonce_b, ct) = bytes.split_at(12);
        let nonce = Nonce::from_slice(nonce_b);
        cipher
            .decrypt(nonce, ct)
            .map_err(|e| sled::Error::Unsupported(format!("decrypt failed: {e}")))
    }
}
