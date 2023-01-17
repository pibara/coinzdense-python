import asyncio
import time
from libnacl import crypto_kdf_derive_from_key as _nacl2_key_derive
from coinzdense.layerzero.onetime import OneTimeSigningKey
from coinzdense.layerzero.wif import key_from_creds
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor


async def main():
    print("reference, no executor")
    key = key_from_creds("coinzdense", "demodemo","secretpassword12345")
    otsk = []
    start = time.time()
    for index in range(0,1024):
        salt = _nacl2_key_derive(20, index, "levelslt", key)
        otsk.append(OneTimeSigningKey(20, 7, salt, key, 1000000*index))
        otsk[-1].get_pubkey()
    reference = time.time() - start
    print("    done, reference =", int(reference),"sec")
    for workers in [1,2,3,4]:
        for usethreads in [False, True]:
            print("workers =", workers, "use threads =", usethreads)
            if usethreads:
                executor = ThreadPoolExecutor(max_workers=workers)
            else:
                executor = ProcessPoolExecutor(max_workers=workers)
            key = key_from_creds("coinzdense", "demodemo","secretpassword12345")
            otsk = []
            start = time.time()
            for index in range(0,1024):
                salt = _nacl2_key_derive(20, index, "levelslt", key)
                otsk.append(OneTimeSigningKey(20, 7, salt, key, 1000000*index))
                otsk[-1].announce(executor)
            cnt = 0
            for index in range(0,1024):
                while not await otsk[index].available():
                    cnt += 1
                    await asyncio.sleep(0.1)
            measurement = time.time() - start
            print("    done", int(100*measurement/reference),"%")

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
