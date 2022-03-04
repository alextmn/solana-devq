//! The `logger` module configures `env_logger`

use std::panic;

use dilithium::params::*;
use dilithium::sign::{ keypair, sign, verify };
use rand::{CryptoRng, RngCore};
use rand_prev::SeedableRng;
use sha2::{Digest, Sha256, Sha512};
use rand_prev::prelude::StdRng;

use std::collections::HashMap;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref SK_CACHE: Mutex<HashMap<[u8; 32], SecretKey>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };

    static ref PUB_CACHE: Mutex<HashMap<[u8; 32], PublicKey>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };

    static ref SIG_CACHE: Mutex<HashMap<[u8; 64], Signature>> = {
        let m = HashMap::new();
        Mutex::new(m)
    };
    
}
pub const SECRET_KEY_LENGTH:usize = 32;

#[derive(Clone)]
#[derive(Copy)]
pub struct Signature {key:[u8; 64], sig: [u8; BYTES] }
pub struct Signer {}
pub struct Verifier {}

#[derive(Debug)]
#[derive(Clone)]
#[derive(Copy)]
pub struct SecretKey { key:[u8; 32], sk:[u8; SECRETKEYBYTES], pk: [u8; PUBLICKEYBYTES]  }

#[derive(Debug)]
#[derive(Clone)]
#[derive(Copy)]
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
            // seed for the dilithium key, TODO: 2.5 KB
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

            let mut map = SK_CACHE.lock().unwrap();
            map.insert(sol_sk.key, sol_sk.clone());

            let mut map_pk = PUB_CACHE.lock().unwrap();
            map_pk.insert(sol_pk.key, sol_pk.clone());

            Keypair{secret:sol_sk, public:sol_pk}
    }

    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        {
            let map = SK_CACHE.lock().unwrap();
            let k = &bytes[..32];
            if map.contains_key(k) {
                let sol_sk = map[k];
                let sol_pk = PublicKey{key:sol_sk.key.clone(), pk: sol_sk.pk.clone()};
                return Ok( Keypair{secret:sol_sk, public:sol_pk});
            }
        }

        let mut hasher  =  Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&result);

        let mut rng: rand::rngs::StdRng = rand::SeedableRng::from_seed(seed);
        Ok(Keypair::generate(&mut rng))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(&self.secret.key[..]);
        k
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let mut sig = [0u8; BYTES];
        sign(&mut sig, &msg, &self.secret.sk);
        
        let mut hasher  =  Sha512::new();
        hasher.update(&sig);
        let result = hasher.finalize();

        let mut key = [0u8; 64];
        key.copy_from_slice(&result.as_slice());

        let s = Signature{key, sig};

        let mut map = SIG_CACHE.lock().unwrap();
        map.insert(s.key, s.clone());
        s
    }
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.key
    }
    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        let map = SIG_CACHE.lock().unwrap();
        match map.get(bytes) {
            Some(val) => Ok(*val),
            None => Ok(Signature{key:[0u8; 64],sig:[0u8; BYTES] }),
        }
    }
    pub fn sig_value(&self) -> Vec<u8> {
        self.sig.to_vec()
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
        let mut k = [0u8; 32];
        k.copy_from_slice(&self.key[..]);
        k
    }
    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        let map = PUB_CACHE.lock().unwrap();
        match map.contains_key(bytes){
            true => Ok(map[bytes]),
            false => Ok(PublicKey{ key:[0u8; 32], pk:[0u8; PUBLICKEYBYTES]}),
        } 
    }
    pub fn verify(&self, message:&[u8], signature: &Signature)-> Result<Self, Error>{
        let result = verify(&message, &signature.sig, &self.pk);
        match result {
            true => Ok(*self),
            false => Err(Error{}),
        }
    }
    pub fn verify_strict(&self, message:&[u8], signature: &Signature)-> Result<(), Error>{
        let result = verify(&message, &signature.sig, &self.pk);
        match result {
            true => Ok(()),
            false => Err(Error{}),
        }
    }

    pub fn pk_value(&self) -> Vec<u8> {
        self.pk.to_vec()
    }
}

impl Error {
    pub fn to_string(&self) -> String {
        
        panic!("not implemented yet");
    }
}
