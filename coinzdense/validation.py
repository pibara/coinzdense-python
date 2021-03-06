#!/usr/bin/python
from nacl.hash import blake2b as _nacl1_hash_function
from nacl.encoding import RawEncoder as _Nacl1RawEncoder

class _Signature:
    def __init__(self, hashlen, otsbits, heights, signature):
        self.hashlen = hashlen
        self.otsbits = otsbits
        self.heights = heights
        self.signature = signature
        self.pubkeys = []
        self.pubkey = None
        header_len = 9 + hashlen * (3 + len(heights))
        if len(signature) > header_len:
            self.privhash = signature[:hashlen]
            self.sigcount = int.from_bytes(signature[hashlen:hashlen+1],"big")
            self.sigindex = int.from_bytes(signature[hashlen+1:hashlen+9],"big")
            self.msgsalt = signature[hashlen+9:2*hashlen+9]
            self.msgdigest = signature[2*hashlen+9: 3*hashlen+9]
            pubkeys = signature[3*hashlen+9:header_len]
            self.pubkeys = [pubkeys[i:i+hashlen] for i in range(0,len(pubkeys),hashlen)]
            ## Fixme: rest of signature
        else:
            raise RuntimeError("Invalid signature size")
    def get_pubkey(self):
        return self.pubkey
    def validate(self, stored_index=None):
        print("Validator not yet implemented")
        return True

def keystruct_to_dict(keystructure, parent=None, parent_path=None):
    rval = dict()
    if parent is None:
        parent = _nacl1_hash_function(b"",
                                           digest_size=24,
                                           encoder=_Nacl1RawEncoder)
        rval[parent.hex()] = ""
    for key in keystructure:
        subkey_digest = _nacl1_hash_function(key.encode(),
                                             digest_size=24,
                                             key=parent,
                                             encoder=_Nacl1RawEncoder)
        if parent_path is None:
            path = key
        else:
            path = parent_path + [key]
        rval[subkey_digest.hex()] = path
        val = keystructure[key]
        if isinstance(val, dict):
            subresult = keystruct_to_dict(val, subkey_digest, path)
            for key2 in subresult:
                rval[key2] = subresult[key2]
    return rval



class ValidationEnv:
    def __init__(self, hashlen, otsbits, keyspace, path, hierarchy):
        self.hashlen = hashlen
        self.otsbits = otsbits
        self.heights = keyspace[0]["heights"]
        self.keystructure = keystruct_to_dict(hierarchy, parent_path=path)
        print(self.keystructure)

    def signature(self, signature):
        return _Signature(self.hashlen, self.otsbits, self.heights, signature)
