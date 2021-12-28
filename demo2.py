#!/usr/bin/python3
import sys
import time
import os
from nacl.utils import random
from nacl.pwhash.argon2id import SALTBYTES
from nacl.secret import SecretBox
import coinzdense.fs
import coinzdense.app


etc_env = coinzdense.fs.EtcEnv(["~/.coinzdense/etc","/etc/coinzdense.d","./etc/coinzdense.d"])
conf = etc_env["HIVISH-DEMO"]
app = coinzdense.app.BlockChainEnv(conf)
active = app["ACTIVE"]
posting = active["POSTING"]


owner_wallet_path = "./coinzdense-owner.wallet"
posting_wallet_path = "./coinzdense-posting.wallet"
owner_passphrase = b"This is a stupid passphrase"
posting_passphrase = b"Another dumb password"
message = "Ok, ok, I admit it, it was me, I did it."

if os.path.exists(posting_wallet_path):
    print("Reading posting wallet")
    with open(posting_wallet_path,"rb") as wfil:
        subwallet = posting.open_wallet(wfil.read(),
                                        posting_passphrase)
else:
    # Ok, no posting wallet, check if the owner wallet does exist
    if os.path.exists(owner_wallet_path):
        # If it does, open it
        print("Reading owner wallet")
        with open(owner_wallet_path,"rb") as wfil:
            wallet = app.open_wallet(wfil.read(),
                                     owner_passphrase)
    else:
        print("Creating owner wallet")
        # Get some randomness
        salt = random(SALTBYTES)
        key = random(SecretBox.KEY_SIZE)
        # create the new wallet
        wallet = app.create_wallet(salt,
                                   key,
                                   owner_passphrase)
        # save it to disk
        print("Saving owner wallet")
        with open(owner_wallet_path,"wb") as wfil:
            wfil.write(bytes(wallet))
    # Create a derived wallet with it's own passphrase
    print("Deriving posting wallet")
    salt2 = random(SALTBYTES)
    key2 = random(SecretBox.KEY_SIZE)
    subwallet = wallet["ACTIVE"]["POSTING"].create_wallet(salt2,
                                                          key2,
                                                          posting_passphrase)
    # Write it to disk
    print("Saving posting wallet")
    with open(posting_wallet_path,"wb") as wfil:
        wfil.write(bytes(subwallet))

print("Creating the signing key")
key = app.get_signing_key(subwallet)
print("Signing a message")
sig = key.sign_string(message)
print("Creating a validator")
venv = app.get_validator()
print("Validating a signature")
valsig = venv.signature(sig)
print(valsig.get_pubkey(), valsig.validate())
backup = key.serialize()
print(backup)
sign_index = key.idx
seed2 = key.key
print("Restoring a signing key")
key2 = app.get_signing_key(subwallet, idx=sign_index, backup=backup)
print("Lotsa signing")
try:
    for idx in range(0, 1 << 9):
        start = time.time()
        sig = key2.sign_string(
                "In een groen groen groen groen knollen knollen land",
                compressed=True)
        print(idx, len(sig), time.time() - start)
except RuntimeError as ex:
    print(ex)
print("Backing up exausted key")
backup = key.serialize()
sign_index = key.idx
print("Restoring exausted key")
key3 = app.get_signing_key(wallet=subwallet, idx=sign_index, backup=backup)
start = time.time()
sig = key3.sign_string("In een groen groen groen groen knollen knollen land",compressed=True)
print(idx, len(sig), time.time() - start)

