Don't forget to rerun ./setup for the right circuit if the circuit is changed.

Run one of those:
```
WITNESS_CPP="$(pwd)"/src/semaphore.circom cargo run --release
WITNESS_CPP="$(pwd)"/src/multiplier.circom cargo run --release
WITNESS_CPP="$(pwd)"/src/proof_of_passport.circom.circom cargo run --release
```

multiplier works well (replace in ./setup.sh, in src/main.rs and in the command)
can't get it to work with semaphore.circom => that's because of my conversion functions
let's try with proof_of_passport.circom

to avoid duplicate symbol error, delete node_modules here

# semaphore-witness-example

This is an example template for building a circuit to be used with the rust native witness generator circom-witness-rs. 
Besides building the required graph file, it also shows an example to use 

## Usage
Pass the absolute path to your circuits in the `WITNESS_CPP` env var.
In the example below, everything is in the project directory.

```
WITNESS_CPP="$(pwd)"/src/semaphore.circom cargo build --release
```

This will produce a `graph.bin` file in the root project folder, which contains the execution graph of the witness generator. 
You will need to pass this file during runtime of the libary later.
