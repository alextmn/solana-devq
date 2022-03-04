#![cfg(feature = "full")]

use {
    crate::{feature_set::FeatureSet, instruction::Instruction, precompiles::PrecompileError},
    bytemuck::{bytes_of, Pod, Zeroable},
    solana_sdk::zcom_keypair,
    std::sync::Arc,
};

pub const PUBKEY_SERIALIZED_SIZE: usize = 32;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;

// bytemuck requires structures to be aligned
pub const SIGNATURE_OFFSETS_START: usize = 2;


// #[derive(Default, Debug, Copy, Clone, Zeroable, Pod)]
// #[repr(C)]
// pub struct Ed25519SignatureOffsets {
//     signature_offset: u16,             // offset to ed25519 signature of 64 bytes
//     signature_instruction_index: u16,  // instruction index to find signature
//     public_key_offset: u16,            // offset to public key of 32 bytes
//     public_key_instruction_index: u16, // instruction index to find public key
//     message_data_offset: u16,          // offset to start of message data
//     message_data_size: u16,            // size of message data
//     message_instruction_index: u16,    // index of instruction data to get message data
// }

pub fn new_zcom_key_instruction(keypair: &zcom_keypair::Keypair, message: &[u8]) -> Instruction {

    // real signature and pub key should be Vec to support different sizes
    let sig = keypair.sign(message);
    let signature_ref = sig.to_bytes();
    let sig_value = sig.sig_value();

    let pubkey_ref = keypair.public.to_bytes();
    let pubkey_value =  keypair.public.pk_value();
    

    assert_eq!(pubkey_ref.len(), PUBKEY_SERIALIZED_SIZE);
    assert_eq!(signature_ref.len(), SIGNATURE_SERIALIZED_SIZE);

    let mut instruction_data = Vec::with_capacity(
        sig_value.len()
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .saturating_add(PUBKEY_SERIALIZED_SIZE)
            .saturating_add(message.len()),
    );

    Instruction {
        program_id: solana_sdk::zcom_key_program::id(),
        accounts: vec![],
        data: instruction_data,
    }
}

pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]],
    _feature_set: &Arc<FeatureSet>,
) -> Result<(), PrecompileError> {
    // it will push a ref to the real post quantum pubkey/signature
    // TODO: To Implement
    Ok(())
}


#[cfg(test)]
pub mod test {
    use solana_program::{pubkey::Pubkey, system_instruction};


    use {
        super::*,
        crate::{
            feature_set::FeatureSet,
            hash::Hash,
            signature::{Keypair, Signer},
            transaction::Transaction,
        },
        rand::{thread_rng},
        std::sync::Arc,
    };

    #[test]
    fn test_zcom_transaction() {
        solana_logger::setup();

        // 1. post-quantum public key and signature lookup instruction
        let privkey = zcom_keypair::Keypair::generate(&mut thread_rng());
        let keypair = Keypair::from_bytes(&privkey.to_bytes()).unwrap();

        let message_arr = b"hello";
        let instruction = new_zcom_key_instruction(&privkey, message_arr);

        // 2. transfer instruction
        let pubkey1 = Pubkey::new(&[1; 32]);
        let transfer = system_instruction::transfer(&keypair.pubkey(), &pubkey1, 1);


        let tx = Transaction::new_signed_with_payer(
            &[transfer, pub_instruction.clone(), sign_instruction],
            Some(&keypair.pubkey()),
            &[&keypair],
            Hash::default(),
        );

        let feature_set = Arc::new(FeatureSet::all_enabled());

        assert!(tx.verify_precompiles(&feature_set).is_ok());

    }
   
  }
