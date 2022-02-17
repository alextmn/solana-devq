//! The `logger` module configures `env_logger`

use std::panic;

use dilithium::params::*;
use dilithium::sign::{ keypair, sign, verify };
use rand::{CryptoRng, RngCore};
use rand_prev::SeedableRng;
use sha2::{Digest, Sha256};
use rand_prev::prelude::StdRng;

pub const SECRET_KEY_LENGTH:usize = 32;

pub struct Signature {}
pub struct Signer {}
pub struct Verifier {}

#[derive(Debug)]
pub struct SecretKey { key:[u8; 32], sk:[u8; SECRETKEYBYTES], pk: [u8; PUBLICKEYBYTES]  }

#[derive(Debug)]
pub struct PublicKey { key:[u8; 32], pk:[u8; PUBLICKEYBYTES] }

#[derive(Debug)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey
}

#[derive(Debug)]
pub struct Error {}

impl Keypair {
    pub fn generate<R>(csprng: &mut R) -> Self
    where
        R: RngCore  + CryptoRng,
        {
            // seed for the dilithium key
            let mut seed = [0u8; 32];
            csprng.fill_bytes(&mut seed);
            let mut rng = StdRng::from_seed(seed);

            let (mut pk, mut sk) = ([0; PUBLICKEYBYTES], [0; SECRETKEYBYTES]);
            keypair(&mut rng, &mut pk, &mut sk);

            let mut hasher  =  Sha256::new();
            hasher.update(&pk);
            let result = hasher.finalize();
            
            let mut sol_sk = SecretKey{key:[0; 32], sk, pk};
            let mut sol_pk = PublicKey{key:[0; 32], pk};

            sol_sk.key.copy_from_slice(result.as_slice());
            sol_pk.key.copy_from_slice(result.as_slice());

            Keypair{secret:sol_sk, public:sol_pk}
    }

    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        let mut hasher  =  Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&result);

        let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(seed);
        Ok(Keypair::generate(&mut rng))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        panic!("not implemented yet");
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        panic!("not implemented yet");
    }
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 32] {
        panic!("not implemented yet");
    }
    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        panic!("not implemented yet");
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        let key_pair = Keypair::from_bytes(bytes)?;
        Ok(key_pair.secret)
    }
}

impl PublicKey {
    pub fn from(sk: &SecretKey)-> Self {
        PublicKey {key: sk.key, pk: sk.pk}
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        panic!("not implemented yet");
    }
    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        panic!("not implemented yet");
    }
    pub fn verify(&self, message:&[u8], signature: &Signature)-> Result<Self, Error>{
        panic!("not implemented yet");
    }
    pub fn verify_strict(&self, message:&[u8], signature: &Signature)-> Result<(), Error>{
        panic!("not implemented yet");
    }
}

impl Error {
    pub fn to_string(&self) -> String {
        panic!("not implemented yet");
    }
}
