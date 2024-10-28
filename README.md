# chainark
a ZKP library to prove a chain of any given relationship, such as block chain, signature chain, etc, which is based on gnark plonk.


3 kinds circuits are defined:
- unit circuit: several unit circuits can be predefined to handle different distance from begin to end point. for example, in below picture, 3 unit circuit A/B/C are defined to handle different distance x, y-x, and z-y.
- genesis circuit: aborb the first unit proof to generate the genesis proof. 
- recursive circuit: concate the first proof(genesis proof or recursive proof) to generate a new recursive proof.


<img width="635" alt="image" src="https://github.com/user-attachments/assets/4f782ada-eb07-4222-a4e2-ad8a722e2696">

In this lib, genesis/recursive circuit are defined, unit circuit is defined by user.


