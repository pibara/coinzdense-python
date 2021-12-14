#!/usr/bin/python3
from libnacl import crypto_kdf_keygen as keygen
from libnacl import crypto_kdf_derive_from_key as key_derive
from libnacl import crypto_kdf_KEYBYTES as KEY_BYTES
from nacl.hash import blake2b as hash_function
from nacl.encoding import RawEncoder, Base32Encoder, Base64Encoder
from nacl.pwhash.argon2id import kdf, SALTBYTES
from nacl.utils import random
import json
import time
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
    def __init__(self, hashlen, otsbits, height, seed, startno, sig_index, backup):
        self.startno = startno
        self.hashlen=hashlen
        self.otsbits=otsbits
        self.height=height
        self.salt = key_derive(hashlen, startno, "Signatur", seed)
        self.privkey = list()
        self.vps = ots_values_per_signature(hashlen, otsbits)
        self.chop_count = ots_pairs_per_signature(hashlen, otsbits)
        sig_count = 1 << height
        pkeystart = startno + 1
        pkeyend = pkeystart + self.vps * sig_count
        for idx in range(pkeystart, pkeyend):
            self.privkey.append(key_derive(hashlen, idx, "Signatur", seed))
        self.backup = backup
        if self.backup is None:
            self.backup = dict()
            self.backup["merkle_bottom"] = None
            self.backup["signature"] = None
        if self.backup["merkle_bottom"] is None:
            big_pubkey = list()
            for index, privpart in enumerate(self.privkey):
                res = privpart
                for _ in range(0, 1 << otsbits):
                    res = hash_function(res, digest_size=hashlen, key=self.salt, encoder=RawEncoder)
                big_pubkey.append(res)
            pubkey = list()
            for idx1 in range(0,sig_count):
                pubkey.append(hash_function(b"".join(big_pubkey[idx1*self.vps:idx1*self.vps+self.vps]),digest_size=hashlen, key=self.salt, encoder=RawEncoder))
            self.backup["merkle_bottom"] = pubkey
        else:
            pubkey = self.backup["merkle_bottom"]
        self.merkle_tree, self.pubkey = to_merkle_tree(pubkey, hashlen, self.salt)
        self.sig_index=sig_index
        if self.backup["signature"] is None:
            self.signature = None
        else:
            self.signature = self.backup["signature"]

    def get_signed_by_parent(self, parent):
        self.signature = parent.sign(self.pubkey)
        self.backup["signature"] = self.signature

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
        return self.salt + b"".join(header)

    def sign(self, digest):
        signature = self.merkle_header()
        as_bigno = int.from_bytes(digest,byteorder='big', signed=True)
        as_int_list = list()
        for time in range(0,self.chop_count):
            as_int_list.append(as_bigno % (1 << self.otsbits))
            as_bigno = as_bigno >> self.otsbits
        as_int_list.reverse()
        my_ots_key =  self.privkey[self.sig_index * self.vps: (self.sig_index + 1) * self.vps]
        my_sigparts = [[as_int_list[i//2], my_ots_key[i], my_ots_key[i+1]] for i in range(0,len(my_ots_key),2)]
        for sigpart in my_sigparts:
            count1 = sigpart[0] + 1
            count2 = (1 << self.otsbits) - sigpart[0]
            sig1 = sigpart[1]
            for _ in range(0,count1):
                sig1 = hash_function(sig1, digest_size=self.hashlen, key=self.salt, encoder=RawEncoder)
            signature += sig1
            sig2 = sigpart[2]
            for _ in range(0,count2):
                sig2 = hash_function(sig2, digest_size=self.hashlen, key=self.salt, encoder=RawEncoder)
            signature += sig2
        return signature



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
        if index > 0:
            rval[index].get_signed_by_parent(rval[index - 1])
    return rval

def sign_digest(level_keys, digest, index, compressed=False):
    rval = b""
    for level_key in reversed(level_keys):
        rval += level_key.pubkey
    rval += index.to_bytes(8, 'big')
    rval += level_keys[-1].sign(digest)
    done = False
    for level_key in reversed(level_keys[1:]):
        if not done: 
            rval += level_key.signature
            if level_key.sig_index != 0 and compressed:
                done = True
    return rval

def sign_string(level_keys, msg, index, hashlen, compressed=False):
    digest = hash_function(msg.encode("latin1"), digest_size=hashlen, encoder=RawEncoder)
    return sign_digest(level_keys, digest, index, compressed)


def _serialize(inp):
    if isinstance(inp,dict):
        output = dict()
        for key,val in inp.items():
            if isinstance(val, (int, float, str, bool, type(None))):
                output[key] = val
            elif isinstance(val,(dict, list)):
                if key == "merkle_bottom":
                    output[key] = [v.hex() for v in val]
                else:
                    output[key] = _serialize(val)
            elif isinstance(val, bytes):
                if key in ["seedhash","signature"]:
                    output[key] = val.hex()
                else:
                    raise RuntimeError("Unexpected bytes type data in backup structure")
            else:
                print(type(val))
                raise RuntimeError("Unexpected backup data type")
    elif isinstance(inp, list):
        output = list()
        for idx, val in enumerate(inp):
            if isinstance(val, (int, float, str, bool, type(None))):
                output.append(val)
            elif isinstance(val,(dict, list)):
                output.append(_serialize(val))
            else:
                raise RuntimeError("Unexpected backup data type")
    elif isinstance(inp, type(None)):
        return None
    else:
        raise RuntimeError("Unexpected backup data type")
    return output

def _deserialize(inp):
    if isinstance(inp,dict):
        output = dict()
        for key,val in inp.items():
            if isinstance(val, (int, float, bool, type(None))):
                output[key] = val
            elif isinstance(val,(dict, list)):
                if key == "merkle_bottom":
                    output[key] = [bytes.fromhex(v) for v in val]
                else:
                    output[key] = _deserialize(val)
            elif isinstance(val, str):
                if key in ["seedhash","signature"]:
                    output[key] = bytes.fromhex(val)
                else:
                    output[key] = val
            else:
                raise RuntimeError("Unexpected backup data type")
    elif isinstance(inp, list):
        output = list()
        for idx, val in enumerate(inp):
            if isinstance(val, (int, float, str, bool, type(None))):
                output.append(val)
            elif isinstance(val,(dict, list)):
                output.append(_deserialize(val))
            else:
                raise RuntimeError("Unexpected backup data type")
    elif isinstance(inp, type(None)):
        return None
    else:
        raise RuntimeError("Unexpected backup data type")
    return output

class SigningKey:
    def __init__(self, hashlen, otsbits, heights, seed=None, idx=0, backup=None, one_client=False, password=None):
        self.hashlen = hashlen
        self.otsbits = otsbits
        self.heights = heights
        self.max_idx = (1 << sum(heights)) - 1 
        self.backup = _deserialize(backup)
        self.idx = idx
        self.seed = seed
        salt = None
        if seed is None:
            if password is None:
                self.seed = keygen()
            else:
                if self.backup is not None and "salt" in self.backup:
                    salt = bytes.fromhex(self.backup["salt"])
                else:
                    salt = random(SALTBYTES)
                self.seed = kdf(KEY_BYTES, password, salt)
        seedhash = hash_function(self.seed, digest_size=hashlen, encoder=Base32Encoder)
        init_list = idx_to_list(hashlen, otsbits, idx,heights)
        if self.backup is None:
            self.backup = dict()
            self.backup["hashlen"] = hashlen
            self.backup["otsbits"] = otsbits
            self.backup["heights"] = heights
            self.backup["idx"] = idx
            self.backup["seedhash"] = seedhash
            self.backup["key_cache"] = dict()
            if salt is not None:
                self.backup["salt"] = salt.hex()
        if self.backup["hashlen"] != hashlen or \
           self.backup["otsbits"] != otsbits or \
           self.backup["seedhash"] != seedhash or \
           self.backup["heights"] != heights:
               raise RuntimeError("Invocation parameters of SigningKey constructor don't match backup")
        if self.backup["idx"] > idx:
            raise RuntimeError("Backup has a higher index number than blockchain, this should not be possible, possible MITM or key-DOS attack")
        elif self.backup["idx"] < idx and one_client:
            raise RuntimeError("Another client may be using a copy of your signing key")
        init_list = idx_to_list(hashlen, otsbits, idx,heights)
        needed = set([val[0] for val in init_list])
        drop = set()
        for key in self.backup["key_cache"].keys():
            if key not in needed:
                drop.add(key)
        for key in drop:
            del self.backup["key_cache"][key]
        for key in needed:
            if key not in self.backup["key_cache"].keys():
                self.backup["key_cache"][key] = None
        restore_info = [self.backup["key_cache"][val[0]] for val in init_list]
        self.level_keys = list()
        for index, init_vals in enumerate(init_list):
            backup = restore_info[index]
            self.level_keys.append(LevelKey(hashlen, otsbits, heights[index], self.seed, init_vals[0], init_vals[1], backup))
            if index > 0:
                self.level_keys[index].get_signed_by_parent(self.level_keys[index-1])
            self.backup["key_cache"][init_vals[0]] = self.level_keys[index].backup
        

    def _increment_index(self):
        new_idx = self.idx + 1
        if new_idx <= self.max_idx:
            init_list = idx_to_list(self.hashlen, self.otsbits, new_idx, self.heights)
            for index, vals in enumerate(init_list):
                if self.level_keys[index].startno != vals[0]:
                    self.level_keys[index] = LevelKey(self.hashlen, self.otsbits, self.heights[index], self.seed, vals[0], vals[1], None)
                    if index>0:
                        self.level_keys[index].get_signed_by_parent(self.level_keys[index - 1])
                    self.backup["key_cache"][vals[0]] = self.level_keys[index].backup
                    del self.backup["key_cache"][self.level_keys[index].startno]
                else:
                    self.level_keys[index].sig_index = vals[1]
        self.idx = new_idx
        self.backup["idx"] = new_idx


    def sign_digest(self, digest, compressed=False):
        if self.idx > self.max_idx:
            raise RuntimeError("SigningKey exhausted")
        print("   - idx = ", self.idx, "max_idx = ", self.max_idx)
        rval = b""
        for level_key in reversed(self.level_keys):
            rval += level_key.pubkey
        rval += self.idx.to_bytes(8, 'big')
        rval += self.level_keys[-1].sign(digest)
        done = False
        for level_key in reversed(self.level_keys[1:]):
            if not done:
                rval += level_key.signature
                if level_key.sig_index != 0 and compressed:
                    done = True
        self._increment_index()
        return rval

    def sign_string(self, msg, compressed=False):
        digest = hash_function(msg.encode("latin1"), digest_size=self.hashlen, encoder=RawEncoder)
        return self.sign_digest(digest, compressed)
    def sign_data(msg, compressed=False):
        digest = hash_function(msg, digest_size=self.hashlen, encoder=RawEncoder)
        return self.sign_digest(digest, compressed)
    def serialize(self):
        return _serialize(self.backup)




key = SigningKey(hashlen=24, otsbits=6, heights=[7, 3, 6], password=b"What kind of dumb password is this?")
start = time.time()
sig = key.sign_string("In een groen groen groen groen knollen knollen land")
print(0,len(sig), time.time() - start)
backup = key.serialize()
print(json.dumps(backup, indent=1))
sign_index = key.idx
seed2 = key.seed
key2 = SigningKey(hashlen=24, otsbits=6, heights=[7, 3, 6], idx=sign_index, backup=backup, password=b"What kind of dumb password is this?")
try:
    for idx in range(0, 1 << 16):
        start = time.time()
        sig = key2.sign_string("In een groen groen groen groen knollen knollen land",compressed=True)
        print(idx, len(sig), time.time() - start)
except RuntimeError as ex:
    print(ex)
backup = key.serialize()
sign_index = key.idx
key3 = SigningKey(hashlen=24, otsbits=6, heights=[7, 3, 6], seed=seed2, idx=sign_index, backup=backup)
start = time.time()
sig = key2.sign_string("In een groen groen groen groen knollen knollen land",compressed=True)
print(idx, len(sig), time.time() - start)
