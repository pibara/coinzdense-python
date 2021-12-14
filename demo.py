#!/usr/bin/python3
import time
import coinzdense.signing
import coinzdense.validation

venv = coinzdense.validation.ValidationEnv(hashlen=24, otsbits=6, heights=[2, 3, 4])

key = coinzdense.signing.SigningKey(hashlen=24, otsbits=6, heights=[2, 3, 4],
                 password=b"What kind of dumb password is this?")
start = time.time()
sig = key.sign_string("In een groen groen groen groen knollen knollen land")
print(0,len(sig), time.time() - start)
valsig = venv.signature(sig)
print(valsig.get_pubkey(), valsig.validate())
backup = key.serialize()
print(backup)
sign_index = key.idx
seed2 = key.seed
key2 = coinzdense.signing.SigningKey(hashlen=24, otsbits=6, heights=[2, 3, 4],
                  idx=sign_index, backup=backup, password=b"What kind of dumb password is this?")
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
                  seed=seed2, idx=sign_index, backup=backup)
start = time.time()
sig = key2.sign_string("In een groen groen groen groen knollen knollen land",compressed=True)
print(idx, len(sig), time.time() - start)
