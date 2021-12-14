# coinzdense-python
Simple Hash Based Post Quantum Signatures : Python implementation

The coinZdense project is a continuation of the spq\_sigs project using lessons learned to create a new
has-based signatures library for use in/with utility-blockchains, blockchain-based distributed exchanges, and other setups where 
key-reuse-by design is required and the solution should be post-quantum ready. 

Please note that the signatures for coinZdense aren't compatible with those from it's predecesor spq\_sigs.

This project currently hasn't reached MVP status yet. Focus is currently on creating a stable API and signature format. The code is currently single-threaded and thus quite a bit slower than the python version of spq\_sigs. Stabilizing state serialisation format isn't a focus yet, and neither is cross-language compatibility of state serialization. 

## New signature format

* signature header
* level signature array

The complete signature consists of two parts. The signature header and an array of level signatures. Note that a complete signature consists of a level-signature signing a message digest, followed by a level-signature signing the pubkey of the key that signed the message digest, followed by a level-signature signing the pubkey of the key that signed that one, and so up.

### signature header

* pubkey array
* signature sequence number.

The signature header consists of an array containing the pubkeys of the involved level keys, starting at the message digest signing key, up to the unchanging top level signing key.

After the pubkey array, a 64 bit big endian signature sequence number is added.

### level signature

* merkle header
* signature

Each level signature consists of two parts: A merkle header tying the signature to the pubkey, and the actual level signature. 

#### level merkle header

The level merkle header contains all the merkle-tree node values needed to get from the signature validation hash to a reconstructed pubkey value that should match the level pubkey.  

#### level signature

The level signature contains an array of OTS value pairs. Together with the message digest or lower level pubkey, these OTS value pairs are used to reconstruct the OTS pubkeys and one lower level merkle-tree node value. A value that together with the merkle header should be able to reconstruct the pubkey.

### shortened signatures

Note that a full signature will often contain many the same level-signatures as older signatures did. The API provides the possibility to ommit these signatures, assuming the blockchain or server already recorded these. 


