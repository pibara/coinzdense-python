#!/usr/bin/python3
from libnacl import crypto_kdf_KEYBYTES as _NACL2_KEY_BYTES
from nacl.pwhash.argon2id import SALTBYTES as _NACL1_SALTBYTES
from nacl.utils import random as _nacl1_random
from nacl.secret import SecretBox as Nacl1SecretBox
from nacl.hash import blake2b as _nacl1_hash_function
from nacl.encoding import RawEncoder as _Nacl1RawEncoder
from nacl.pwhash.argon2id import kdf as _nacl1_kdf

def _keypath_to_id(path):
    rval = _nacl1_hash_function(b"",
                                digest_size=24,
                                encoder=_Nacl1RawEncoder)
    for part in path:
        rval = _nacl1_hash_function(part.encode(),
                                    digest_size=24,
                                    key=rval,
                                    encoder=_Nacl1RawEncoder)
    return rval

class _Wallet:
    def __init__(self, encwallet, privid, rawkey):
        self.encwallet = encwallet
        self.privid = privid
        self.key = rawkey

    def __bytes__(self):
        return self.encwallet

    def __getitem__(self, subkey_name):
        class PartialWallet:
            def __init__(self, salt, key, privid):
                self.salt = salt
                self.key = key
                self.privid = privid
            def __bytes__(self):
                return self.key
            def __getitem__(self, subsubkey_name):
                subprivid = _nacl1_hash_function(subsubkey_name.encode(),
                                                 digest_size=24,
                                                 key=self.privid,
                                                 encoder=_Nacl1RawEncoder)
                twopart = _nacl1_hash_function(subsubkey_name.encode(),
                                               digest_size=_NACL1_SALTBYTES + Nacl1SecretBox.KEY_SIZE,
                                               key=self.key,
                                               encoder=_Nacl1RawEncoder)
                salt = twopart[:_NACL1_SALTBYTES]
                key = twopart[_NACL1_SALTBYTES:]
                return PartialWallet(salt, key, privid)
            def create_wallet(self, salt, key, password):
                wallet_key = _nacl1_kdf(_NACL2_KEY_BYTES,
                                        password,
                                        self.salt)
                box = Nacl1SecretBox(wallet_key)
                encwallet = salt + box.encrypt(self.key)
                return _Wallet(encwallet, privid, key)
        privid = _nacl1_hash_function(subkey_name.encode(),
                                      digest_size=24,
                                      key=self.privid,
                                      encoder=_Nacl1RawEncoder)
        twopart = _nacl1_hash_function(subkey_name.encode(),
                                       digest_size=_NACL1_SALTBYTES + Nacl1SecretBox.KEY_SIZE,
                                       key=self.key,
                                       encoder=_Nacl1RawEncoder)
        salt = twopart[:_NACL1_SALTBYTES]
        key = twopart[_NACL1_SALTBYTES:]
        return PartialWallet(salt, key, privid)


def create_wallet(salt, key, password, path):
    assert len(salt) == _NACL1_SALTBYTES
    assert len(key) == Nacl1SecretBox.KEY_SIZE
    privid = _keypath_to_id(path)
    wallet_key = _nacl1_kdf(_NACL2_KEY_BYTES,
                          password,
                          salt)
    box = Nacl1SecretBox(wallet_key)
    encwallet = salt + box.encrypt(key)
    return _Wallet(encwallet, privid, key)

def open_wallet(wdata, password, path):
    # FIXME assert wdata length
    print("Opening wallet", path,"with password", password)
    salt = wdata[:_NACL1_SALTBYTES]
    encwallet = wdata[_NACL1_SALTBYTES:]
    privid = _keypath_to_id(path)
    wallet_key = _nacl1_kdf(_NACL2_KEY_BYTES,
                            password,
                            salt)
    box = Nacl1SecretBox(wallet_key)
    key = box.decrypt(encwallet)
    return _Wallet(encwallet, privid, key)

