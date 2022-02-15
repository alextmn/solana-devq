//! The `logger` module configures `env_logger`
pub const SECRET_KEY_LENGTH:usize = 32;

pub struct Signature {}
pub struct Signer {}
pub struct Verifier {}

#[derive(Debug)]
pub struct SecretKey {}

#[derive(Debug)]
pub struct PublicKey {}

#[derive(Debug)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey
}

#[derive(Debug)]
pub struct Error {}

impl Keypair {
    pub fn generate<R>(csprng: &mut R) -> Self{
        panic!("not implemented yet");
    }

    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        panic!("not implemented yet");
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
        panic!("not implemented yet");
    }
}

impl SecretKey {
    pub fn from_bytes(bytes: &[u8])-> Result<Self, Error>{
        panic!("not implemented yet");
    }
}

impl PublicKey {
    pub fn from(sk: &SecretKey)-> Self {
        panic!("not implemented yet");
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
