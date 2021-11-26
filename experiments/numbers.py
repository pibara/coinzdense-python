#!/usr/bin/python3
from libnacl import crypto_kdf_keygen as keygen
from libnacl import crypto_kdf_derive_from_key as key_derive
from libnacl import crypto_kdf_KEYBYTES as KEY_BYTES
from nacl.hash import blake2b as hash_function
from nacl.encoding import RawEncoder, Base32Encoder

class SubKeys:
    def __init__(self, hashlen, key):
        assert isinstance(hashlen, int)
        assert hashlen > 15
        assert hashlen < 65
        assert isinstance(key,bytes)
        assert len(key) == KEY_BYTES
        self._key = key
        self.hashlen = hashlen
    def __getitem__(self, index):
        return key_derive(self.hashlen, index, "Signatur",self._key)

class Entropy:
    def __call__(self):
        return keygen()


class TreeIndexFinder:
    def __init__(self, hashlen, wotsbits, height_array):
        assert isinstance(hashlen, int)
        assert hashlen > 15
        assert hashlen < 65
        assert isinstance(wotsbits, int)
        assert wotsbits > 3
        assert wotsbits < 17
        assert isinstance(height_array, list)
        assert len(height_array) < 256
        assert isinstance(height_array[0], int)
        assert height_array[0] > 2
        assert height_array[0] < 17
        assert 39 * wotsbits >= hashlen * 8
        print(" - ", height_array)
        self.hashlen = hashlen
        self.wotsbits = wotsbits
        self.height = height_array[0]
        self.child = None
        self.subkeys_per_signature = 2 * (hashlen * 8 + wotsbits -1) // wotsbits
        self.max_signature_count = (1 << self.height)
        self.subkeys_at_level = 1 + self.max_signature_count * self.subkeys_per_signature
        if len(height_array) > 1:
            self.child = TreeIndexFinder(hashlen, wotsbits, height_array[1:])

    def deep_subkeys(self):
        if self.child:
            print("+ ",self.height, ":", self.subkeys_at_level, "+", self.max_signature_count * self.child.deep_subkeys())
            return self.subkeys_at_level + self.max_signature_count * self.child.deep_subkeys()
        print("+", self.height, ":", self.subkeys_at_level)
        return self.subkeys_at_level

    def indices_to_one(self, indices, own_start_index=0):
        if len(indices) > 1:
            start_index = own_start_index + indices[0]*self.child.deep_subkeys()
            return self.child.indices_to_one(indices[1:], start_index)
        return own_start_index


entropy = Entropy()
master_key = entropy()
keys = SubKeys(42, master_key)
print(keys[0])
ifinder = TreeIndexFinder(48, 13, [6,7,8])
for l1 in range(0,64):
    for l2 in range(0,128):
        print(l1,l2, ":" , ifinder.indices_to_one([l1,l2]))

print(ifinder.indices_to_one([3,67, 174]))

#res = hash_function(b"hoHo",digest_size=48, key=b"houhoiuhlojhl", encoder=RawEncoder)
#print(res)
#print(res.hex())

