#!/usr/bin/python
import base58

class _Signature:
    def __init__(self, hashlen, otsbits, heights, signature):
        self.hashlen = hashlen
        self.otsbits = otsbits
        self.heights = heights
        self.signature = signature
        self.pubkeys = []
        self.pubkey = None
        header_len = 8 + hashlen * len(heights)
        if len(signature) > header_len:
            self.pubkeys = [base58.b58encode(b"cZ" + signature[hashlen*i:hashlen*(i+1)]) for i in range(0,len(heights))]
            self.pubkey = self.pubkeys[-1]
            self.sig_index = signature[hashlen*len(heights):hashlen*len(heights)+8] # FIXME
    def get_pubkey(self):
        return self.pubkey
    def validate(self, stored_index=None):
        print("Validator not yet implemented")
        return True


class ValidationEnv:
    def __init__(self, hashlen, otsbits, heights):
        self.hashlen = hashlen
        self.otsbits = otsbits
        self.heights = heights

    def signature(self, signature):
        return _Signature(self.hashlen, self.otsbits, self.heights, signature)
