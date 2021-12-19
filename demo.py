#!/usr/bin/python3
import sys
import time
import os
from nacl.utils import random
from nacl.pwhash.argon2id import SALTBYTES
from nacl.secret import SecretBox
import coinzdense.signing
import coinzdense.validation
import coinzdense.wallet


wallet_path = "./coinzdense.wallet"
passphrase = b"This is a stupid passphrase"
if os.path.exists(wallet_path):
    with open(wallet_path,"rb") as wfil:
        wallet = coinzdense.wallet.open_wallet(wfil.read(),
                                               passphrase)
        print("Using existing wallet")
else:
    salt = random(SALTBYTES)
    key = random(SecretBox.KEY_SIZE)
    wallet = coinzdense.wallet.create_wallet(salt,
                                             key,
                                             passphrase)
    with open(wallet_path,"wb") as wfil:
        wfil.write(bytes(wallet))
        print("Saved wallet for later")

subwallet = wallet["ACTIVE"]["POSTING"].create_wallet(b"Another dumb password")

key = coinzdense.signing.SigningKey(hashlen=24, otsbits=6, heights=[2, 3, 4], wallet=subwallet)


venv = coinzdense.validation.ValidationEnv(hashlen=24, otsbits=6, heights=[2, 3, 4])

start = time.time()
sig = key.sign_string("In een groen groen groen groen knollen knollen land")
print(0,len(sig), time.time() - start)
valsig = venv.signature(sig)
print(valsig.get_pubkey(), valsig.validate())
backup = key.serialize()
print(backup)
sign_index = key.idx
seed2 = key.key
key2 = coinzdense.signing.SigningKey(hashlen=24, otsbits=6, heights=[2, 3, 4], wallet=subwallet,
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
                  wallet=subwallet, idx=sign_index, backup=backup)
start = time.time()
sig = key2.sign_string("In een groen groen groen groen knollen knollen land",compressed=True)
print(idx, len(sig), time.time() - start)
