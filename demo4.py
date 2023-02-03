import asyncio
from coinzdense.layerzero.level import LevelKey, LevelValidation
from coinzdense.layerzero.wif import key_from_creds
from concurrent.futures import ProcessPoolExecutor

MAX_WORKERS = 4   # Max number of concurent process workers
HASH_LENGTH = 20  # Hash length used bu coinZdense
OTS_BITS    = 7   # Number of bits to encode at once with one-time signing keys
MT_HEIGHT   = 10  # The height of the level key merkle tree


async def main():
    key = key_from_creds("coinzdense", "demodemo","secretpassword12345")
    executor = ProcessPoolExecutor(max_workers=MAX_WORKERS)
    levelkey = LevelKey(seedkey=key,
                        wen3index=0,
                        hashlen=HASH_LENGTH,
                        otsbits=OTS_BITS,
                        height=MT_HEIGHT)
    levelkey.announce(executor)
    await levelkey.require()
    message = b"hohohohoho"
    sig1 = levelkey.sign_data(message, 644)
    sig2 = levelkey.sign_data(message, 645)
    print(len(sig1))
    validate = LevelValidation(hashlen=HASH_LENGTH,
                               otsbits=OTS_BITS,
                               height=MT_HEIGHT)
    for sig in [sig1, sig2]:
        signature = validate.signature(level_signature=sig)
        ok = signature.validate_data(message)
        print(ok)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
