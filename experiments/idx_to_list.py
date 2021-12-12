#!/usr/bin/python3
from libnacl import crypto_kdf_keygen as keygen
from libnacl import crypto_kdf_derive_from_key as key_derive
from libnacl import crypto_kdf_KEYBYTES as KEY_BYTES
from nacl.hash import blake2b as hash_function
from nacl.encoding import RawEncoder, Base32Encoder
import json
## New and improved signature format:
#  + pubkeys[n]: Depth first list of level-key pubkeys, last one is the entities root level pubkey
#  + sig_index : 64 bit number representing the global signature index
#  + signatures[m]: Depth first list of signatures.The m value will be shorter than n unless one of the level
#                 indices is zero.
#      + salt 
#      + merkle_header
#      + signature
#

def ots_pairs_per_signature(hashlen, otsbits):
    return ((hashlen*8-1) // otsbits)+1

def ots_values_per_signature(hashlen, otsbits):
    return 2 * ots_pairs_per_signature(hashlen, otsbits)

def to_merkle_tree(pubkey_in, hashlen, salt):
    mt = dict()
    mt["0"] = dict()
    mt["1"] = dict()
    if len(pubkey_in) > 2:
        mt0, mt["0"]["node"] = to_merkle_tree(pubkey_in[:len(pubkey_in)//2], hashlen, salt)
        if "0" in mt0:
            mt["0"]["0"] = mt0["0"]
            mt["0"]["1"] = mt0["1"]
            mt["0"]["node"] = mt0["0"]["node"]
        mt1, mt["1"]["node"] = to_merkle_tree(pubkey_in[len(pubkey_in)//2:], hashlen, salt)
        if "0" in mt1:
            mt["1"]["0"] = mt1["0"]
            mt["1"]["1"] = mt1["1"]
            mt["1"]["node"] = mt1["0"]["node"]
        return mt, hash_function(mt["0"]["node"] + mt["1"]["node"], digest_size=hashlen, key=salt, encoder=RawEncoder)
    mt["0"]["node"] = pubkey_in[0]
    mt["1"]["node"] = pubkey_in[1]
    return mt, hash_function(pubkey_in[0] + pubkey_in[1], digest_size=hashlen, key=salt, encoder=RawEncoder)

class LevelKey:
    def __init__(self, hashlen, otsbits, height, seed, startno, sig_index):
        self.hashlen=hashlen
        self.otsbits=otsbits
        self.height=height
        self.salt = key_derive(hashlen, startno, "Signatur", seed)
        self.privkey = list()
        vps = ots_values_per_signature(hashlen, otsbits)
        self.chop_count = ots_pairs_per_signature(hashlen, otsbits)
        sig_count = 1 << height
        pkeystart = startno + 1
        pkeyend = pkeystart + vps * sig_count
        for idx in range(pkeystart, pkeyend):
            self.privkey.append(key_derive(hashlen, idx, "Signatur", seed))
        big_pubkey = list()
        for index, privpart in enumerate(self.privkey):
            res = privpart
            for _ in range(0, 1 << otsbits):
                res = hash_function(res, digest_size=hashlen, key=self.salt, encoder=RawEncoder)
            big_pubkey.append(res)
        pubkey = list()
        for idx1 in range(0,sig_count):
            pubkey.append(hash_function(b"".join(big_pubkey[idx1*vps:idx1*vps+vps]),digest_size=hashlen, key=self.salt, encoder=RawEncoder))
        self.merkle_tree, self.pubkey = to_merkle_tree(pubkey, hashlen, self.salt)
        self.sig_index=sig_index

    def merkle_header(self):
        fstring = "0" + str(self.height) + "b"
        as_binlist = list(format(self.sig_index,fstring))
        header = list()
        while len(as_binlist) > 0:
            subtree = self.merkle_tree
            for idx in as_binlist[:-1]:
                subtree = subtree[idx]
            inverse = str(1 - int(as_binlist[-1]))
            header.append(subtree[inverse]["node"])
            as_binlist = as_binlist[:-1]
        return b"".join(header)

    def sign(self, digest):
        header = self.merkle_header()
        print(header)
        as_bigno = int.from_bytes(digest,byteorder='big', signed=True)
        as_int_list = list()
        for time in range(0,self.chop_count):
            as_int_list.append(as_bigno % (1 << self.otsbits))
            as_bigno = as_bigno >> self.otsbits
        as_int_list.reverse()

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
level_keys = get_level_keys(24, 6, [7, 5, 6, 9], seed, 37449)
level_keys[3].sign(b"abcdefghijklmnopqrstuvwxyz012345ABCDEFGHIJKLMNOPQRSTUVWXYZ67890%")
