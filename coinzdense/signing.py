#!/usr/bin/python3
"""Python module for Simple Post Quantum Signatures

This module provides simple BLAKE2 hash-based based signature using a simple
design made out of a combination of a merkle tree and dual OTS chains.
"""
import json as _json
from libnacl import crypto_kdf_keygen as _nacl2_keygen
from libnacl import crypto_kdf_derive_from_key as _nacl2_key_derive
from libnacl import crypto_kdf_KEYBYTES as _NACL2_KEY_BYTES
from nacl.hash import blake2b as _nacl1_hash_function
from nacl.encoding import RawEncoder as _Nacl1RawEncoder
from nacl.encoding import Base32Encoder as _Nacl1Base32Encoder
from nacl.pwhash.argon2id import kdf as _nacl1_kdf
from nacl.pwhash.argon2id import SALTBYTES as _NACL1_SALTBYTES
from nacl.utils import random as _nacl1_random


def _ots_pairs_per_signature(hashlen, otsbits):
    return ((hashlen*8-1) // otsbits)+1


def _ots_values_per_signature(hashlen, otsbits):
    return 2 * _ots_pairs_per_signature(hashlen, otsbits)


def _to_merkle_tree(pubkey_in, hashlen, salt):
    mtree = dict()
    mtree["0"] = dict()
    mtree["1"] = dict()
    if len(pubkey_in) > 2:
        mt0, mtree["0"]["node"] = _to_merkle_tree(pubkey_in[:len(pubkey_in)//2],
                                                  hashlen,
                                                  salt)
        if "0" in mt0:
            mtree["0"]["0"] = mt0["0"]
            mtree["0"]["1"] = mt0["1"]
            mtree["0"]["node"] = mt0["0"]["node"]
        mt1, mtree["1"]["node"] = _to_merkle_tree(pubkey_in[len(pubkey_in)//2:],
                                                  hashlen,
                                                  salt)
        if "0" in mt1:
            mtree["1"]["0"] = mt1["0"]
            mtree["1"]["1"] = mt1["1"]
            mtree["1"]["node"] = mt1["0"]["node"]
        return mtree, _nacl1_hash_function(
                mtree["0"]["node"] + mtree["1"]["node"],
                digest_size=hashlen,
                key=salt,
                encoder=_Nacl1RawEncoder)
    mtree["0"]["node"] = pubkey_in[0]
    mtree["1"]["node"] = pubkey_in[1]
    return mtree, _nacl1_hash_function(
            pubkey_in[0] + pubkey_in[1],
            digest_size=hashlen,
            key=salt,
            encoder=_Nacl1RawEncoder)


class _LevelKey:
    # pylint: disable=too-many-instance-attributes
    def __init__(self, hashlen, otsbits, height, seed, startno, sig_index, backup):
        # pylint: disable=too-many-arguments
        self.startno = startno
        self.hashlen = hashlen
        self.otsbits = otsbits
        self.height = height
        self.salt = _nacl2_key_derive(hashlen,
                                      startno,
                                      "Signatur",
                                      seed)
        self.privkey = list()
        self.vps = _ots_values_per_signature(hashlen,
                                             otsbits)
        self.chop_count = _ots_pairs_per_signature(hashlen,
                                                   otsbits)
        for idx in range(startno + 1,
                         startno + 1 + self.vps * (1 << height)):
            self.privkey.append(
                    _nacl2_key_derive(hashlen,
                                      idx,
                                      "Signatur",
                                      seed)
                    )
        self.backup = backup
        if self.backup is None:
            self.backup = dict()
            self.backup["merkle_bottom"] = None
            self.backup["signature"] = None
        if self.backup["merkle_bottom"] is None:
            big_pubkey = list()
            for privpart in self.privkey:
                res = privpart
                for _ in range(0, 1 << otsbits):
                    res = _nacl1_hash_function(res,
                                               digest_size=hashlen,
                                               key=self.salt,
                                               encoder=_Nacl1RawEncoder)
                big_pubkey.append(res)
            pubkey = list()
            for idx1 in range(0, 1 << height):
                pubkey.append(_nacl1_hash_function(
                    b"".join(big_pubkey[idx1*self.vps:idx1*self.vps+self.vps]),
                    digest_size=hashlen,
                    key=self.salt,
                    encoder=_Nacl1RawEncoder))
            self.backup["merkle_bottom"] = pubkey
        else:
            pubkey = self.backup["merkle_bottom"]
        self.merkle_tree, self.pubkey = _to_merkle_tree(pubkey,
                                                        hashlen,
                                                        self.salt)
        self.sig_index = sig_index
        if self.backup["signature"] is None:
            self.signature = None
        else:
            self.signature = self.backup["signature"]

    def get_signed_by_parent(self, parent):
        """Get signed by level key one leve up"""
        self.signature = parent.sign(self.pubkey)
        self.backup["signature"] = self.signature

    def merkle_header(self):
        """Calculate the merkle header for the curent signature"""
        fstring = "0" + str(self.height) + "b"
        as_binlist = list(
                format(self.sig_index,
                       fstring)
            )
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
        """Sign for a digest"""
        signature = self.merkle_header()
        as_bigno = int.from_bytes(digest,
                                  byteorder='big',
                                  signed=True)
        as_int_list = list()
        for _ in range(0, self.chop_count):
            as_int_list.append(as_bigno % (1 << self.otsbits))
            as_bigno = as_bigno >> self.otsbits
        as_int_list.reverse()
        my_ots_key = self.privkey[self.sig_index * self.vps: (self.sig_index + 1) * self.vps]
        my_sigparts = [
                [
                    as_int_list[i//2],
                    my_ots_key[i],
                    my_ots_key[i+1]
                ] for i in range(0, len(my_ots_key), 2)
            ]
        for sigpart in my_sigparts:
            count1 = sigpart[0] + 1
            count2 = (1 << self.otsbits) - sigpart[0]
            sig1 = sigpart[1]
            for _ in range(0, count1):
                sig1 = _nacl1_hash_function(
                        sig1,
                        digest_size=self.hashlen,
                        key=self.salt,
                        encoder=_Nacl1RawEncoder)
            signature += sig1
            sig2 = sigpart[2]
            for _ in range(0, count2):
                sig2 = _nacl1_hash_function(
                        sig2,
                        digest_size=self.hashlen,
                        key=self.salt,
                        encoder=_Nacl1RawEncoder)
            signature += sig2
        return signature


def _deep_count(hash_len, ots_bits, harr):
    if len(harr) == 1:
        return 1 + _ots_values_per_signature(hash_len, ots_bits) * (1 << harr[0])
    ccount = _deep_count(hash_len, ots_bits, harr[1:])
    return 1 + (1 << harr[0]) * (_ots_values_per_signature(hash_len, ots_bits) + ccount)


def _idx_to_list(hash_len, ots_bits, idx, harr, start=0):
    if len(harr) == 1:
        return [[start, idx]]
    bits = 0
    for num in harr[1:]:
        bits += num
    deepersigs = 1 << bits
    lindex = idx // deepersigs
    dindex = idx % deepersigs
    dstart = start + 1 + _ots_values_per_signature(hash_len, ots_bits) * (1 << harr[0]) + \
        lindex * _deep_count(hash_len, ots_bits, harr[1:])
    return [[start, lindex]] + _idx_to_list(hash_len, ots_bits, dindex, harr[1:], dstart)


def _jsonable(inp):
    # pylint: disable=too-many-branches
    if isinstance(inp, dict):
        output = dict()
        for key, val in inp.items():
            if isinstance(val, (int, float, str, bool, type(None))):
                output[key] = val
            elif isinstance(val, (dict, list)):
                if key == "merkle_bottom":
                    output[key] = [v.hex() for v in val]
                else:
                    output[key] = _jsonable(val)
            elif isinstance(val, bytes):
                if key in ["seedhash", "signature"]:
                    output[key] = val.hex()
                else:
                    raise RuntimeError("Unexpected bytes type data in backup structure")
            else:
                raise RuntimeError("Unexpected backup data type")
    elif isinstance(inp, list):
        output = list()
        for val in inp:
            if isinstance(val, (int, float, str, bool, type(None))):
                output.append(val)
            elif isinstance(val, (dict, list)):
                output.append(_jsonable(val))
            else:
                raise RuntimeError("Unexpected backup data type")
    elif isinstance(inp, type(None)):
        return None
    else:
        raise RuntimeError("Unexpected backup data type")
    return output


def _dejsonable(inp):
    # pylint: disable=too-many-branches
    if isinstance(inp, dict):
        output = dict()
        for key, val in inp.items():
            if isinstance(val, (int, float, bool, type(None))):
                output[key] = val
            elif isinstance(val, (dict, list)):
                if key == "merkle_bottom":
                    output[key] = [bytes.fromhex(v) for v in val]
                else:
                    output[key] = _dejsonable(val)
            elif isinstance(val, str):
                if key in ["seedhash", "signature"]:
                    output[key] = bytes.fromhex(val)
                else:
                    output[key] = val
            else:
                raise RuntimeError("Unexpected backup data type")
    elif isinstance(inp, list):
        output = list()
        for val in inp:
            if isinstance(val, (int, float, str, bool, type(None))):
                output.append(val)
            elif isinstance(val, (dict, list)):
                output.append(_dejsonable(val))
            else:
                raise RuntimeError("Unexpected backup data type")
    elif isinstance(inp, type(None)):
        return None
    else:
        raise RuntimeError("Unexpected backup data type")
    return output


class SigningKey:
    """Class for creating multi-level-key coinZdense signatures"""
    # pylint: disable=too-many-instance-attributes
    def __init__(self, hashlen, otsbits, heights, seed=None, idx=0, backup=None,
                 one_client=False, password=None):
        # pylint: disable=too-many-locals, too-many-arguments, too-many-branches
        self.hashlen = hashlen
        self.otsbits = otsbits
        self.heights = heights
        self.max_idx = (1 << sum(heights)) - 1
        self.backup = None
        if backup is not None:
            self.backup = _dejsonable(_json.loads(backup))
        self.idx = idx
        self.seed = seed
        salt = None
        if seed is None:
            if password is None:
                self.seed = _nacl2_keygen()
            else:
                salt = bytes.fromhex(self.backup["salt"]) if \
                    (self.backup is not None and "salt" in self.backup) \
                    else _nacl1_random(_NACL1_SALTBYTES)
                self.seed = _nacl1_kdf(_NACL2_KEY_BYTES,
                                       password,
                                       salt)
        if self.backup is None:
            self.backup = dict()
            self.backup["hashlen"] = hashlen
            self.backup["otsbits"] = otsbits
            self.backup["heights"] = heights
            self.backup["idx"] = idx
            self.backup["seedhash"] = _nacl1_hash_function(self.seed,
                                                           digest_size=hashlen,
                                                           encoder=_Nacl1Base32Encoder)
            self.backup["key_cache"] = dict()
            if salt is not None:
                self.backup["salt"] = salt.hex()
        if self.backup["hashlen"] != hashlen or \
           self.backup["otsbits"] != otsbits or \
           self.backup["heights"] != heights:
            raise RuntimeError("Mismatch of key-structure params and backup")
        if self.backup["seedhash"] != _nacl1_hash_function(
                self.seed,
                digest_size=hashlen,
                encoder=_Nacl1Base32Encoder):
            raise RuntimeError("Wrong password or seed")
        if self.backup["idx"] > idx:
            raise RuntimeError("Backup has a higher index number than blockchain")
        if self.backup["idx"] < idx and one_client:
            raise RuntimeError("Another client may be using a copy of your signing key")
        init_list = _idx_to_list(hashlen, otsbits, idx, heights)
        drop = set()
        for key in self.backup["key_cache"].keys():
            if key not in {val[0] for val in init_list}:
                drop.add(key)
        for key in drop:
            del self.backup["key_cache"][key]
        for key in {val[0] for val in init_list}:
            if key not in self.backup["key_cache"].keys():
                self.backup["key_cache"][key] = None
        restore_info = [self.backup["key_cache"][val[0]] for val in init_list]
        self.level_keys = list()
        for index, init_vals in enumerate(init_list):
            self.level_keys.append(
                    _LevelKey(
                        hashlen,
                        otsbits,
                        heights[index],
                        self.seed,
                        init_vals[0],
                        init_vals[1],
                        restore_info[index]
                    )
                )
            if index > 0:
                self.level_keys[index].get_signed_by_parent(self.level_keys[index-1])
            self.backup["key_cache"][init_vals[0]] = self.level_keys[index].backup

    def _increment_index(self):
        new_idx = self.idx + 1
        if new_idx <= self.max_idx:
            init_list = _idx_to_list(self.hashlen,
                                     self.otsbits,
                                     new_idx,
                                     self.heights)
            for index, vals in enumerate(init_list):
                if self.level_keys[index].startno != vals[0]:
                    self.level_keys[index] = _LevelKey(
                            self.hashlen,
                            self.otsbits,
                            self.heights[index],
                            self.seed,
                            vals[0],
                            vals[1],
                            None)
                    if index > 0:
                        self.level_keys[index].get_signed_by_parent(self.level_keys[index - 1])
                    self.backup["key_cache"][vals[0]] = self.level_keys[index].backup
                    del self.backup["key_cache"][self.level_keys[index].startno]
                else:
                    self.level_keys[index].sig_index = vals[1]
        self.idx = new_idx
        self.backup["idx"] = new_idx

    def sign_digest(self, digest, compressed=False):
        """Sign a digest using a complete multi-level signature"""
        if self.idx > self.max_idx:
            raise RuntimeError("SigningKey exhausted")
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
        """Sign a string using a complete multi-level signature"""
        digest = _nacl1_hash_function(msg.encode("latin1"),
                                      digest_size=self.hashlen,
                                      encoder=_Nacl1RawEncoder)
        return self.sign_digest(digest, compressed)

    def sign_data(self, msg, compressed=False):
        """Sign a bytes using a complete multi-level signature"""
        digest = _nacl1_hash_function(msg,
                                      digest_size=self.hashlen,
                                      encoder=_Nacl1RawEncoder)
        return self.sign_digest(digest,
                                compressed)

    def serialize(self):
        """Serialize signing key state to a JSON string"""
        return _json.dumps(_jsonable(self.backup),
                           indent=1)
