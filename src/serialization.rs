use ark_bn254::Bn254;
use ark_circom::ethereum;
use ark_ec::pairing::Pairing;
use ark_groth16::{Proof, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use color_eyre::Result;

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct SerializableProvingKey(pub ProvingKey<Bn254>);

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct SerializableProof(pub Proof<Bn254>);

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq)]
pub struct SerializableInputs(pub Vec<<Bn254 as Pairing>::ScalarField>);

pub fn serialize_proof(proof: &SerializableProof) -> Vec<u8> {
    let mut serialized_data = Vec::new();
    proof
        .serialize_uncompressed(&mut serialized_data)
        .expect("Serialization failed");
    serialized_data
}

pub fn deserialize_proof(data: Vec<u8>) -> SerializableProof {
    SerializableProof::deserialize_uncompressed(&mut &data[..]).expect("Deserialization failed")
}

pub fn serialize_proving_key(pk: &SerializableProvingKey) -> Vec<u8> {
    let mut serialized_data = Vec::new();
    pk.serialize_uncompressed(&mut serialized_data)
        .expect("Serialization failed");
    serialized_data
}

pub fn deserialize_proving_key(data: Vec<u8>) -> SerializableProvingKey {
    SerializableProvingKey::deserialize_uncompressed(&mut &data[..])
        .expect("Deserialization failed")
}

pub fn serialize_inputs(inputs: &SerializableInputs) -> Vec<u8> {
    let mut serialized_data = Vec::new();
    inputs
        .serialize_uncompressed(&mut serialized_data)
        .expect("Serialization failed");
    serialized_data
}

pub fn deserialize_inputs(data: Vec<u8>) -> SerializableInputs {
    SerializableInputs::deserialize_uncompressed(&mut &data[..]).expect("Deserialization failed")
}

// Convert proof to U256-tuples as expected by the Solidity Groth16 Verifier
pub fn to_ethereum_proof(proof: &SerializableProof) -> ethereum::Proof {
    ethereum::Proof::from(proof.0.clone())
}

pub fn to_ethereum_inputs(inputs: &SerializableInputs) -> ethereum::Inputs {
    ethereum::Inputs::from(&inputs.0[..])
}
