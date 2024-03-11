#!/bin/bash

mkdir -p build
cd build    
if [ ! -f powersOfTau28_hez_final_20.ptau ]; then
    echo "Download power of tau...."
    wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau
    echo "Finished download!"
else 
    echo "Powers of tau file already downloaded... Skip download action!"
fi
cd ..

echo "compiling circuit"
circom src/proof_of_passport.circom -l node_modules --r1cs --wasm --output build

echo "building zkey"
yarn snarkjs groth16 setup build/proof_of_passport.r1cs build/powersOfTau28_hez_final_20.ptau build/proof_of_passport.zkey

echo "building vkey"
echo "salut" | yarn snarkjs zkey contribute build/proof_of_passport.zkey build/proof_of_passport_final.zkey