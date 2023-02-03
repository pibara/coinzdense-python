"""One-time signing (OTS) keys and signature validation"""
import asyncio
from concurrent.futures import Executor
from asyncio.events import AbstractEventLoop
from libnacl import crypto_kdf_derive_from_key as _nacl2_key_derive
from libnacl import crypto_kdf_KEYBYTES as _nacl2_kdf_KEYBYTES
from nacl.hash import blake2b as _nacl1_hash_function
from nacl.encoding import RawEncoder as _Nacl1RawEncoder

def _ots_pairs_per_signature(hashlen, otsbits):
    """Calculate the number of one-time-signature private-key up-down duos needed to
    sign a single digest"""
    return ((hashlen*8-1) // otsbits)+1

def _calculate_pubkey(privkey, otsbits, hashlen, salt):
    pubparts = []
    # Calculate the full-sized one-time-signing pubkey
    for privpart in privkey:
        res = privpart
        # Calculate one chunk of the full-sized one-time-signing pubkey
        for _ in range(0, 1 << otsbits):
            res = _nacl1_hash_function(res,
                                       digest_size=hashlen,
                                       key=salt,
                                       encoder=_Nacl1RawEncoder)
        pubparts.append(res)
    # Calculate the normal-sized one-time-signing pubkey
    pubkey_long = b"".join(pubparts)
    return _nacl1_hash_function(
            pubkey_long,
            digest_size=hashlen,
            key=salt,
            encoder=_Nacl1RawEncoder)

class OneTimeSigningKey:
    """Signing key for making a single one-time signature with"""
    # pylint: disable=too-many-arguments, too-many-instance-attributes
    def __init__(self, hashlen, otsbits, levelsalt, key, startno, pubkey=None, loop=None):
        # pylint: disable=too-many-branches
        """Constructor"""
        if not isinstance(hashlen, int):
            raise TypeError("hashlen must be an integer")
        if not isinstance(otsbits, int):
            raise TypeError("otsbits must be an integer")
        if not isinstance(levelsalt, bytes):
            raise TypeError("levelsalt must be an bytes")
        if not isinstance(key, bytes):
            raise TypeError("key must be an bytes")
        if not isinstance(startno, int):
            raise TypeError("startno must be an integer")
        if pubkey is not None and not isinstance(pubkey, bytes):
            raise TypeError("pubkey must be an bytes or None")
        if loop is not None and not isinstance(loop, AbstractEventLoop):
            raise TypeError("loop must be concurrent.futures.Executor or None")
        if (hashlen < 16 or hashlen > 64):
            raise ValueError("hashlen should have a value in the 16..64 range")
        if otsbits < 4 or otsbits > 16:
            raise ValueError("hashlen should have a value in the 4..16 range")
        if len(levelsalt) != hashlen:
            raise ValueError("levelsalt should be hashlen long")
        if len(key) != _nacl2_kdf_KEYBYTES:
            raise ValueError("key has the wrong size for a key")
        if startno < 0:
            raise ValueError("startno should be non-negative")
        if startno.bit_length() > 64:
            raise ValueError("startno too big to fit in 64 bit unsigned")
        if (startno + 2 * _ots_pairs_per_signature(hashlen, otsbits)).bit_length() > 64:
            raise ValueError("startno would overflow beyond 64 bit unsigned")
        if isinstance(pubkey, bytes) and len(pubkey) != hashlen:
            raise ValueError("pubkey (if non-Null) should be hashlen long")
        self._hashlen = hashlen
        self._otsbits = otsbits
        self._levelsalt = levelsalt
        self._pubkey = pubkey
        self._loop = loop
        if loop is None:
            self._loop = asyncio.get_event_loop()
        self._privkey = []
        self._chopcount = _ots_pairs_per_signature(hashlen, otsbits)
        # We use up one chunk of entropy for a nonce. This nonce is basically the
        #  salt we use instead of the level salt when hashing the transaction, message
        #  or next-level level-key pubkey.
        self._nonce = _nacl2_key_derive(hashlen,
                                        startno,
                                        "SigNonce",
                                        key)
        # Derive the whole one-time-signing private key from the seeding key.
        for keyspace_index in range(startno + 1, startno + 1 + 2 * self._chopcount):
            self._privkey.append(
                    _nacl2_key_derive(hashlen,
                                      keyspace_index,
                                      "Signatur",
                                      key)
                    )
        self._pending = None

    def get_pubkey(self):
        """Get the binary public key, calculate if needed.

        Returns
        -------
        bytes
            The public key.
        """
        if self._pending is not None and self._pubkey is None:
            raise RuntimeError("Can't synchonously call get_pubkey on anounced and not required OTSK")
        if self._pubkey is None:
            self._pubkey = _calculate_pubkey(self._privkey, self._otsbits, self._hashlen, self._levelsalt)
        return self._pubkey

    def announce(self, executor):
        """Announce that we are expecting to use this key, schedule for pubkey calculation

        Parameters
        ----------
        executor: concurrent.futures.Executor
            execuror to use for calculating the pubkey.
        """
        if not isinstance(executor, Executor):
            raise TypeError("Invalid executor type")
        if self._pubkey is None and self._pending is None:
            self._pending = self._loop.run_in_executor(executor,
                                                       _calculate_pubkey,
                                                       self._privkey,
                                                       self._otsbits,
                                                       self._hashlen,
                                                       self._levelsalt)

    async def require(self):
        """Await any pending executor code for calculating the pubkey"""
        if self._pubkey is None and self._pending is not None:
            self._pubkey = await self._pending

    async def available(self):
        """Check if pubkey is available

        Returns
        -------
        bool
            True if pubkey available
        """
        if self._pubkey is not None:
            return True
        if self._pending is None:
            return False
        if self._pending.done():
            self._pubkey = await self._pending
            return True
        return False

    def sign_hash(self, digest):
        """Signature from hash

        Parameters
        ----------
        digest : bytes
            Hash of the data that needs signing

        Returns
        -------
        bytes
            The signature including nonce.

        Raises
        ------
        TypeError
            Thrown if digest has the wrong type
        ValueError
            Thrown if digest has the wrong length
        """
        if not isinstance(digest, bytes):
            raise TypeError("digest should be bytes")
        if len(digest) != self._hashlen:
            raise ValueError("sign_hash called with hash of inapropriate size")
        # Convert the input digest into an array of otsbits long numbers
        as_bigno = int.from_bytes(digest,
                                  byteorder='big',
                                  signed=True)
        as_int_list = []
        for _ in range(0, self._chopcount):
            as_int_list.append(as_bigno % (1 << self._otsbits))
            as_bigno = as_bigno >> self._otsbits
        as_int_list.reverse()
        # Make a convenience array, grouping the digest based numbers with the private key chunks
        my_sigparts = [
            [
                as_int_list[i//2],
                self._privkey[i],
                self._privkey[i+1]
            ] for i in range(0, len(self._privkey), 2)
        ]
        signature = b""
        for sigpart in my_sigparts:
            # Figure out the number of times the up and the down chain will need to repeat hashing
            # in order to create signature chunks.
            count1 = sigpart[0] + 1
            count2 = (1 << self._otsbits) - sigpart[0]
            # Hash the up-chain
            sig1 = sigpart[1]
            for _ in range(0, count1):
                sig1 = _nacl1_hash_function(
                           sig1,
                           digest_size=self._hashlen,
                           key=self._levelsalt,
                           encoder=_Nacl1RawEncoder)
            signature += sig1
            # Hash the down chain
            sig2 = sigpart[2]
            for _ in range(0, count2):
                sig2 = _nacl1_hash_function(
                        sig2,
                        digest_size=self._hashlen,
                        key=self._levelsalt,
                        encoder=_Nacl1RawEncoder)
            signature += sig2
        return signature

    def sign_data(self, data):
        """Signature from data

        Parameters
        ----------
        data : bytes
            Data that needs signing

        Returns
        -------
        bytes
            The signature including nonce.
        """
        if not isinstance(data, bytes):
            raise TypeError("data should be bytes")
        # Hash the data, using the nonce salt as a key.
        digest = _nacl1_hash_function(
                        data,
                        digest_size=self._hashlen,
                        key=self._nonce,
                        encoder=_Nacl1RawEncoder)
        # Prefix the signature with the nonce
        return self._nonce + self.sign_hash(digest)


class OneTimeValidator:
    """Validator for one-time signature"""
    def __init__(self, hashlen, otsbits, levelsalt, otpubkey):
        """Constructor"""
        if (not isinstance(hashlen, int) or
                not isinstance(otsbits, int) or
                not isinstance(levelsalt, bytes) or
                not isinstance(otpubkey, bytes)):
            raise TypeError("OneTimeValidator constructor argument type mismatch")
        if hashlen < 16 or hashlen > 64:
            raise ValueError("hashlen should have a value in the 16..64 range")
        if otsbits < 4 or otsbits > 16:
            raise ValueError("hashlen should have a value in the 4..16 range")
        if len(levelsalt) != hashlen:
            raise ValueError("levelsalt should be hashlen long")
        if len(otpubkey) != hashlen:
            raise ValueError("otpubkey should be hashlen long")
        self._hashlen = hashlen
        self._otsbits = otsbits
        self._levelsalt = levelsalt
        self._pubkey = otpubkey
        self._chopcount = _ots_pairs_per_signature(hashlen, otsbits)

    def validate_hash(self, digest, signature, merkle_mode=False):
        """Validate signature from signature

        Parameters
        ----------
        digest : bytes
                 Digest of the signed data
        signature : bytes
                      The signature including nonce, signing the data.

        Returns
        -------
        bool
            Boolean indicating if signature matches the pubkey/data combo

        Raises
        ------
        TypeError
            Thrown if digest, merkle_mode, or the signature has the wrong type
        ValueError
            Thrown if digest or the signature has the wrong length
        """
        if not isinstance(digest, bytes):
            raise TypeError("digest should be bytes")
        if not isinstance(signature, bytes):
            raise TypeError("signature should be bytes")
        if not  isinstance(merkle_mode, bool):
            raise TypeError("merkle_mode should be a bool")
        if len(digest) != self._hashlen:
            raise ValueError("sign_hash called with hash of inapropriate size")
        if len(signature) != self._hashlen * 2 * _ots_pairs_per_signature(
                self._hashlen,
                self._otsbits):
            raise ValueError("sign_hash called with signature of inapropriate size")
        # Chop up the signature into hashlen long chunks
        partials = [signature[i:i+self._hashlen] for i in range(0, len(signature), self._hashlen)]
        # Convert the input digest into an array of otsbits long numbers
        as_bigno = int.from_bytes(digest,
                                  byteorder='big',
                                  signed=True)
        as_int_list = []
        for _ in range(0, self._chopcount):
            as_int_list.append(as_bigno % (1 << self._otsbits))
            as_bigno = as_bigno >> self._otsbits
        as_int_list.reverse()
        # Make a convenience array, grouping the digest based numbers with the private key chunks
        my_sigparts = [
            [
                as_int_list[i//2],
                partials[i],
                partials[i+1]
            ] for i in range(0, len(partials), 2)
        ]
        # Complete the OTS chains to recover the full-sized OTS public key
        bigpubkey = b""
        for sigpart in my_sigparts:
            # Determine the amount of times we need to still hash to get at the pubkey chunk
            count1 = (1 << self._otsbits) - sigpart[0] - 1
            count2 = sigpart[0]
            # Complete the up-chain
            sig1 = sigpart[1]
            for _ in range(0, count1):
                sig1 = _nacl1_hash_function(
                           sig1,
                           digest_size=self._hashlen,
                           key=self._levelsalt,
                           encoder=_Nacl1RawEncoder)
            bigpubkey += sig1
            # Complete the down-chain
            sig2 = sigpart[2]
            for _ in range(0, count2):
                sig2 = _nacl1_hash_function(
                        sig2,
                        digest_size=self._hashlen,
                        key=self._levelsalt,
                        encoder=_Nacl1RawEncoder)
            bigpubkey += sig2
        # Convert the full-sized pubkey into the external pubkey.
        reconstructed_pubkey =  _nacl1_hash_function(
                                    bigpubkey,
                                    digest_size=self._hashlen,
                                    key=self._levelsalt,
                                    encoder=_Nacl1RawEncoder)
        # Check if the reconstructed pubkey matches the known pubkey
        if merkle_mode:
            return reconstructed_pubkey
        return self._pubkey == reconstructed_pubkey

    def validate_data(self, data, signature, merkle_mode=False):
        """Validate signature from data

        Parameters
        ----------
        data : bytes
                 The signed data
        signature : bytes
                      The signature including nonce, signing the data.

        Returns
        -------
        bool
            Boolean indicating if signature matches the pubkey/data combo
        """
        if not isinstance(data, bytes):
            raise TypeError("data should be bytes")
        if not isinstance(signature, bytes):
            raise TypeError("signature should be bytes")
        if not  isinstance(merkle_mode, bool):
            raise TypeError("merkle_mode should be a bool")
        if len(signature) != (1 +  2 * self._chopcount) * self._hashlen:
            raise ValueError("Signature has wrong length")
        # Extract the nonce from the signature
        nonce = signature[:self._hashlen]
        # Hash the data using the nonce
        digest = _nacl1_hash_function(
                        data,
                        digest_size=self._hashlen,
                        key=nonce,
                        encoder=_Nacl1RawEncoder)
        # Validate the resulting digest is indeed signed with the known OTS key.
        return self.validate_hash(digest, signature[self._hashlen:], merkle_mode)
