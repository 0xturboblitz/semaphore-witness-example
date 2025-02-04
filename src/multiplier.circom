pragma circom 2.1.4;

/*This circuit template checks that c is the multiplication of a and b.*/  

template Multiplier2 () {

   // Declaration of signals.  
   signal input a;
   signal input b;  
   signal output c;  

   // Constraints.
   c <== a * b;

   a === 2;
}

component main { public [ a ] } = Multiplier2();