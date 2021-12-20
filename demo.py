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

# here we store our wallets
owner_wallet_path = "./coinzdense-owner.wallet"
posting_wallet_path = "./coinzdense-posting.wallet"
# hard-coded passphrase, bad idea, but this is just a demo
owner_passphrase = b"This is a stupid passphrase"
posting_passphrase = b"Another dumb password"
# Something we want to sign
message = "Ok, ok, I admit it, it was me, I did it."
# check if posting wallet exists
if os.path.exists(posting_wallet_path):
    # Use existing posting wallet if it exists
    print("Reading posting wallet")
    with open(posting_wallet_path,"rb") as wfil:
        subwallet = coinzdense.wallet.open_wallet(wfil.read(),
                                                  posting_passphrase,
                                                  "ACTIVE/POSTING")
else:
    # Ok, no posting wallet, check if the owner wallet does exist
    if os.path.exists(owner_wallet_path):
        # If it does, open it
        print("Reading owner wallet")
        with open(owner_wallet_path,"rb") as wfil:
            wallet = coinzdense.wallet.open_wallet(wfil.read(),
                                                   owner_passphrase)
    else:
        print("Creating owner wallet")
        # Get some randomness
        salt = random(SALTBYTES)
        key = random(SecretBox.KEY_SIZE)
        # create the new wallet
        wallet = coinzdense.wallet.create_wallet(salt,
                                             key,
                                             owner_passphrase)
        # save it to disk
        print("Saving owner wallet")
        with open(owner_wallet_path,"wb") as wfil:
            wfil.write(bytes(wallet))
    # Create a derived wallet with it's own passphrase
    print("Deriving posting wallet")
    subwallet = wallet["ACTIVE"]["POSTING"].create_wallet(posting_passphrase)
    # Write it to disk
    print("Saving posting wallet")
    with open(posting_wallet_path,"wb") as wfil:
        wfil.write(bytes(subwallet))

# Use the open wallet to make ourselves a 3-level signing-key
key = coinzdense.signing.SigningKey(hashlen=24, otsbits=6, heights=[2, 3, 4], wallet=subwallet)
# Mah
sig = key.sign_string(message)


keystructure = {"ACTIVE" : { "POSTING" : None}}
venv = coinzdense.validation.ValidationEnv(hashlen=24, otsbits=6, heights=[2, 3, 4], keystructure=keystructure)
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
