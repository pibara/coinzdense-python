import asyncio
import time
from libnacl import crypto_kdf_derive_from_key as _nacl2_key_derive
from coinzdense.layerzero.level import LevelKey, LevelValidation
from coinzdense.layerzero.wif import key_from_creds
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

async def main():
    key = key_from_creds("coinzdense", "demodemo","secretpassword12345")
    executor = ProcessPoolExecutor(max_workers=4)
    levelkey = LevelKey(seedkey=key, wen3index=0, hashlen=20, otsbits=7, height=10)
    levelkey.announce(executor)
    await levelkey.require()
    print(levelkey.get_pubkey().hex())
    print()
    sig1 = levelkey.sign_data(b"hohohohoho", 644)
    sig2 = levelkey.sign_data(b"hohohohoho", 645)
    validate = LevelValidation(hashlen=20, otsbits=7, height=10)
    signature = validate.signature(level_signature=sig1)
    ok = signature.validate_data(b"hohohohoho")
    print(ok)

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
