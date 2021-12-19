#!/usr/bin/python3
import sys
import time
from nacl.utils import random
from nacl.pwhash.argon2id import SALTBYTES
from nacl.secret import SecretBox
import coinzdense.signing
import coinzdense.validation
import coinzdense.wallet

salt = random(SALTBYTES)
key = random(SecretBox.KEY_SIZE)
print(key.hex())
wallet = coinzdense.wallet.create_wallet(salt, key, b"This is a stupid passphrase")
wallet_bytes = bytes(wallet)
print("Wallet:", wallet_bytes.hex())
wallet = coinzdense.wallet.open_wallet(wallet_bytes, b"This is a stupid passphrase")
print(wallet.key.hex())
subwallet = wallet["ACTIVE"].create_wallet(b"Another dumb password")
print(subwallet.key.hex())
subsubwallet = subwallet["POSTING"].create_wallet(b"And one more dumb wallet")
print(subsubwallet.key.hex())

venv = coinzdense.validation.ValidationEnv(hashlen=24, otsbits=6, heights=[2, 3, 4])

key = coinzdense.signing.SigningKey(hashlen=24, otsbits=6, heights=[2, 3, 4], key=subsubwallet.key)
start = time.time()
sig = key.sign_string("In een groen groen groen groen knollen knollen land")
print(0,len(sig), time.time() - start)
valsig = venv.signature(sig)
print(valsig.get_pubkey(), valsig.validate())
backup = key.serialize()
print(backup)
sign_index = key.idx
seed2 = key.key
key2 = coinzdense.signing.SigningKey(hashlen=24, otsbits=6, heights=[2, 3, 4], key=subsubwallet.key,
                  idx=sign_index, backup=backup)
try:
    for idx in range(0, 1 << 9):
        start = time.time()
        sig = key2.sign_string(
                "In een groen groen groen groen knollen knollen land",
                compressed=True)
        print(idx, len(sig), time.time() - start)
except RuntimeError as ex:
    print(ex)
backup = key.serialize()
sign_index = key.idx
key3 = coinzdense.signing.SigningKey(hashlen=24, otsbits=6, heights=[2, 3, 4],
                  key=seed2, idx=sign_index, backup=backup)
start = time.time()
sig = key2.sign_string("In een groen groen groen groen knollen knollen land",compressed=True)
print(idx, len(sig), time.time() - start)
