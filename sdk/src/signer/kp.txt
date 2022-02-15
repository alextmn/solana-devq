#![cfg(feature = "full")]

use {
    crate::{
        pubkey::Pubkey,
        signature::Signature,
        signer::{Signer, SignerError},
    },
    rand::{rngs::OsRng, RngCore, Rng},
    std::{
        error,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        path::Path,
    },
    wasm_bindgen::prelude::*,
    rsa::{ RsaPrivateKey, RsaPublicKey, pkcs1, padding},
};

#[wasm_bindgen]
#[derive(Debug)]
pub struct Keypair(RsaPrivateKey);

impl Keypair {
    /// Constructs a new, random `Keypair` using a caller-proveded RNG
    pub fn generate<R: Rng>(csprng: &mut R) -> Self
    where
        R: RngCore + Rng,
    {
        let bits = 2048;
        let pk: RsaPrivateKey = RsaPrivateKey::new(&mut csprng, bits).unwrap();
        return Self(pk);
    }

    /// Constructs a new, random `Keypair` using `OsRng`
    pub fn new() -> Self {
        let mut rng = OsRng::default();
        Self::generate(&mut rng)
    }

    /// Recovers a `Keypair` from a byte array
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, pkcs1::Error> {
        pkcs1::FromRsaPrivateKey::from_pkcs1_der(bytes).map(Self)
    }

    /// Returns this `Keypair` as a byte array
    pub fn to_bytes(&self) -> &[u8] {
        let pk: pkcs1::RsaPrivateKeyDocument = pkcs1::ToRsaPrivateKey::to_pkcs1_der(&self.0).unwrap();
        pk.as_der()
    }

    /// Recovers a `Keypair` from a base58-encoded string
    pub fn from_base58_string(s: &str) -> Self {
        Self::from_bytes(&bs58::decode(s).into_vec().unwrap()).unwrap()
    }

    /// Returns this `Keypair` as a base58-encoded string
    pub fn to_base58_string(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

}

impl Signer for Keypair {
    fn pubkey(&self) -> Pubkey {
        let public_key = RsaPublicKey::from(&self.0);
        let der: pkcs1::RsaPublicKeyDocument = pkcs1::ToRsaPublicKey::to_pkcs1_der(&public_key).unwrap();

        Pubkey::new(der.as_der())
    }

    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(self.pubkey())
    }

    fn sign_message(&self, message: &[u8]) -> Signature {
        let sha2 = Some(rsa::hash::Hash::SHA2_256);
        let padding = padding::PaddingScheme::PKCS1v15Sign{hash: sha2};
        let sig = self.0.sign(padding, message).unwrap();
        Signature::new(&sig)
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        Ok(self.sign_message(message))
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

impl<T> PartialEq<T> for Keypair
where
    T: Signer,
{
    fn eq(&self, other: &T) -> bool {
        self.pubkey() == other.pubkey()
    }
}

/// Reads a JSON-encoded `Keypair` from a `Reader` implementor
pub fn read_keypair<R: Read>(reader: &mut R) -> Result<Keypair, std::io::Error> {
    let bytes: Vec<u8> = serde_json::from_reader(reader)?;
    let keypair= Keypair::from_bytes(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
    return keypair;
}

/// Reads a `Keypair` from a file
pub fn read_keypair_file<F: AsRef<Path>>(path: F) -> Result<Keypair, std::io::Error> {
    let mut file = File::open(path.as_ref())?;
    read_keypair(&mut file)
}

/// Writes a `Keypair` to a `Write` implementor with JSON-encoding
pub fn write_keypair<W: Write>(
    keypair: &Keypair,
    writer: &mut W,
) -> Result<String, Box<dyn error::Error>> {
    let keypair_bytes = keypair.to_bytes();
    let serialized = serde_json::to_string(&keypair_bytes.to_vec())?;
    writer.write_all(&serialized.clone().into_bytes())?;
    Ok(serialized)
}

/// Writes a `Keypair` to a file with JSON-encoding
pub fn write_keypair_file<F: AsRef<Path>>(
    keypair: &Keypair,
    outfile: F,
) -> Result<String, Box<dyn error::Error>> {
    let outfile = outfile.as_ref();

    if let Some(outdir) = outfile.parent() {
        fs::create_dir_all(outdir)?;
    }

    let mut f = {
        #[cfg(not(unix))]
        {
            OpenOptions::new()
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new().mode(0o600)
        }
    }
    .write(true)
    .truncate(true)
    .create(true)
    .open(outfile)?;

    write_keypair(keypair, &mut f)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        // bip39::{Language, Mnemonic, MnemonicType, Seed},
        std::mem,
    };

    fn tmp_file_path(name: &str) -> String {
        use std::env;
        let out_dir = env::var("FARF_DIR").unwrap_or_else(|_| "farf".to_string());
        let keypair = Keypair::new();

        format!("{}/tmp/{}-{}", out_dir, name, keypair.pubkey())
    }

    #[test]
    fn test_write_keypair_file() {
        let outfile = tmp_file_path("test_write_keypair_file.json");
        let serialized_keypair = write_keypair_file(&Keypair::new(), &outfile).unwrap();
        let keypair_vec: Vec<u8> = serde_json::from_str(&serialized_keypair).unwrap();
        assert!(Path::new(&outfile).exists());
        assert_eq!(
            keypair_vec,
            read_keypair_file(&outfile).unwrap().to_bytes().to_vec()
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                File::open(&outfile)
                    .expect("open")
                    .metadata()
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        assert_eq!(
            read_keypair_file(&outfile).unwrap().pubkey().as_ref().len(),
            mem::size_of::<Pubkey>()
        );
        fs::remove_file(&outfile).unwrap();
        assert!(!Path::new(&outfile).exists());
    }

    #[test]
    fn test_write_keypair_file_overwrite_ok() {
        let outfile = tmp_file_path("test_write_keypair_file_overwrite_ok.json");

        write_keypair_file(&Keypair::new(), &outfile).unwrap();
        write_keypair_file(&Keypair::new(), &outfile).unwrap();
    }

    #[test]
    fn test_write_keypair_file_truncate() {
        let outfile = tmp_file_path("test_write_keypair_file_truncate.json");

        write_keypair_file(&Keypair::new(), &outfile).unwrap();
        read_keypair_file(&outfile).unwrap();

        // Ensure outfile is truncated
        {
            let mut f = File::create(&outfile).unwrap();
            f.write_all(String::from_utf8([b'a'; 2048].to_vec()).unwrap().as_bytes())
                .unwrap();
        }
        write_keypair_file(&Keypair::new(), &outfile).unwrap();
        read_keypair_file(&outfile).unwrap();
    }
}
