#!/usr/bin/python3
from libnacl import crypto_kdf_keygen as keygen
from libnacl import crypto_kdf_derive_from_key as key_derive
from libnacl import crypto_kdf_KEYBYTES as KEY_BYTES
from nacl.hash import blake2b as hash_function
from nacl.encoding import RawEncoder, Base32Encoder
## New and improved signature format:
#  + pubkeys[n]: Depth first list of level-key pubkeys, last one is the entities root level pubkey
#  + sig_index : 64 bit number representing the global signature index
#  + signatures[m]: Depth first list of signatures.The m value will be shorter than n unless one of the level
#                 indices is zero.
#      + salt 
#      + merkle_header
#      + signature
#

def ots_values_per_signature(hashlen, otsbits):
    return ((hashlen-1)*2 // otsbits)+2

class LevelKey:
    def __init__(self, hashlen, otsbits, height, seed, startno, sig_index):
        print(startno)
        self.hashlen=hashlen
        self.otsbits=otsbits
        self.height=height
        self.salt = key_derive(hashlen, startno, "Signatur", seed)
        print("Creating huge privkey", hashlen, "x", (1 << (height + 1)) * ots_values_per_signature(hashlen, otsbits)) 
        self.privkey = list()
        for idx in range(startno + 1, startno + 1 + (1 << (height + 1)) * ots_values_per_signature(hashlen, otsbits)):
            self.privkey.append(key_derive(hashlen, idx, "Signatur", seed))
        print(len(self.privkey))
        big_pubkey = list()
        for index, privpart in enumerate(self.privkey):
            res = privpart
            for _ in range(0, 1 << otsbits):
                res = hash_function(res, digest_size=hashlen, key=self.salt, encoder=RawEncoder)
            big_pubkey.append(res)
        self.big_pubkey = [hash_function(b"".join(big_pubkey[i:i+ots_values_per_signature(hashlen, otsbits)//2]),digest_size=hashlen, key=self.salt, encoder=RawEncoder) for i in range(0, len(big_pubkey), ots_values_per_signature(hashlen, otsbits)//2)]
        print(len(self.big_pubkey))
        pubkey = self.big_pubkey.copy()
        while len(pubkey) > 1:
            pubkey = [hash_function(pubkey[i] + pubkey[i+1], digest_size=hashlen, key=self.salt, encoder=RawEncoder) for
                i in range(0, len(pubkey), 2)]
        self.pubkey = pubkey[0]
        self.sig_index=sig_index


def deep_count(hash_len, ots_bits, harr):
    if len(harr) == 1:
        return 1 + ots_values_per_signature(hash_len, ots_bits) * (1 << harr[0])
    ccount = deep_count(hash_len, ots_bits, harr[1:])
    return 1 + (1 << harr[0]) * (ots_values_per_signature(hash_len, ots_bits) + ccount)

def idx_to_list(hash_len, ots_bits, idx, harr, start=0):
    if len(harr) == 1:
        return [[start, idx]]
    bits = 0
    for num in harr[1:]:
        bits += num
    deepersigs = 1 << bits
    lindex = idx // deepersigs
    dindex = idx % deepersigs
    dstart = start + 1 + ots_values_per_signature(hash_len, ots_bits) * (1 << harr[0]) + \
        lindex * deep_count(hash_len, ots_bits, harr[1:])
    return [[start, lindex]] + idx_to_list(hash_len, ots_bits, dindex, harr[1:], dstart)


def get_level_keys(hashlen, otsbits, heights, seed, idx):
    init_list = idx_to_list(hashlen, otsbits, idx,heights)
    rval = list()
    for index, init_vals in enumerate(init_list):
        rval.append(LevelKey(hashlen, otsbits, heights[index], seed, init_vals[0], init_vals[1]))
    return rval
    
seed=keygen()
level_keys = get_level_keys(24, 6, [7, 5, 6], seed, 37449)
