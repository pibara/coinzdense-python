"""Level-key signing keys and signature validation"""
import asyncio
from libnacl import crypto_kdf_derive_from_key as _nacl2_key_derive
from nacl.hash import blake2b as _nacl1_hash_function
from nacl.encoding import RawEncoder as _Nacl1RawEncoder
from .onetime import OneTimeSigningKey, OneTimeValidator

def _ots_pairs_per_signature(hashlen, otsbits):
    """Calculate the number of one-time-signature private-key up-down duos needed to
    sign a single digest"""
    return ((hashlen*8-1) // otsbits)+1

def _to_merkle_tree(pubkey_in, hashlen, salt):
    """Convert a list of one-time pubkley into a merkletree lookup structure"""
    mtree = {}
    if len(pubkey_in) > 2:
        mtree["0"] = _to_merkle_tree(pubkey_in[:len(pubkey_in)//2],
                                     hashlen,
                                     salt)
        mtree["1"] = _to_merkle_tree(pubkey_in[len(pubkey_in)//2:],
                                     hashlen,
                                     salt)
        mtree["node"] = _nacl1_hash_function(mtree["0"]["node"] + mtree["1"]["node"],
                                             digest_size=hashlen,
                                             key=salt,
                                             encoder=_Nacl1RawEncoder)
    else:
        mtree["0"] = {"node": pubkey_in[0]}
        mtree["1"] = {"node": pubkey_in[1]}
        mtree["node"] = _nacl1_hash_function(pubkey_in[0] + pubkey_in[1],
                                             digest_size=hashlen,
                                             key=salt,
                                             encoder=_Nacl1RawEncoder)
    return mtree

def _get_merkle_prefix(merkletree, height, index):
    """Extract a index based merkletree signature prefix"""
    fstring = "0" + str(height) + "b"
    as_binlist = list(format(index, fstring))
    header = []
    while len(as_binlist) > 0:
        subtree = merkletree
        for idx in as_binlist[:-1]:
            subtree = subtree[idx]
        inverse = str(1 - int(as_binlist[-1]))
        header.append(subtree[inverse]["node"])
        as_binlist = as_binlist[:-1]
    header.append(merkletree["node"])
    return b"".join(header)

# pylint: disable=too-many-arguments
def _validate_merkle_root(merkleheaders, merkleroot, hashlen, height, index, salt, levelpubkey):
    """Validate that a signature merklenode header and the fignature derived ots pubkey
       resolve into the provided merkletree root (also the levelkey pubkey"""
    fstring = "0" + str(height) + "b"
    as_binlist = list(format(index, fstring))
    as_binlist.reverse()
    result = levelpubkey
    for merkle_index in range(0, height):
        if as_binlist[merkle_index] == "0":
            concat = result + merkleheaders[merkle_index]
        else:
            concat = merkleheaders[merkle_index] + result
        result = _nacl1_hash_function(concat,
                                      digest_size=hashlen,
                                      key=salt,
                                      encoder=_Nacl1RawEncoder)
    return result == merkleroot
# pylint: enable=too-many-arguments

class LevelKey:
    """Single level signing key class, used to compose SigningKey"""
    # pylint: disable=too-many-arguments
    def __init__(self, seedkey, wen3index, hashlen, otsbits, height,
                 bigpubkey=None, loop=None):
        self._hashlen = hashlen
        self._height = height
        if loop is None:
            loop = asyncio.get_event_loop()
        self._levelsalt = _nacl2_key_derive(hashlen,
                                            wen3index,
                                            "levelslt",
                                            seedkey)
        self._keys = []
        self._nonces = []
        self.pubkey = None
        self._merkletree = None
        otscount = 1 << self._height
        entropy_per_signature = _ots_pairs_per_signature(hashlen,
                                                         otsbits) + 2
        next_index = wen3index + 1
        for _ in range(0, otscount):
            nonce = _nacl2_key_derive(hashlen, next_index, "levelslt", seedkey)
            self._nonces.append(nonce)
            next_index += entropy_per_signature
        if self.pubkey is None:
            next_index = wen3index + 1
            for _ in range(0, otscount):
                self._keys.append(OneTimeSigningKey(hashlen,
                                                    otsbits,
                                                    self._levelsalt,
                                                    seedkey,
                                                    next_index + 1,
                                                    None,
                                                    loop))
                next_index += entropy_per_signature
        else:
            next_index = wen3index + 1
            for indx in range(0, otscount):
                self._keys.append(OneTimeSigningKey(hashlen,
                                                    otsbits,
                                                    self._levelsalt,
                                                    seedkey,
                                                    next_index + 1,
                                                    bigpubkey[indx],
                                                    loop))
                next_index += entropy_per_signature
            self._merkletree = _to_merkle_tree(bigpubkey, self._hashlen, self._levelsalt)
            self.pubkey = self._merkletree["node"]

    def get_pubkey(self):
        """Get the pubkey for this level synchonicaly, no async calculation may be pending"""
        if self.pubkey is None:
            bigpubkey = []
            for otskey in self._keys:
                bigpubkey.append(otskey.get_pubkey())
            self._merkletree = _to_merkle_tree(bigpubkey, self._hashlen, self._levelsalt)
            self.pubkey = self._merkletree["node"]
        return self.pubkey

    def announce(self, executor):
        """Schedule background calculation of the pubkey"""
        if self.pubkey is None:
            for otskey in self._keys:
                otskey.announce(executor)

    async def require(self):
        """If needed, wait for background calculation to complete"""
        if self.pubkey is None:
            bigpubkey = []
            for otskey in self._keys:
                await otskey.require()
                bigpubkey.append(otskey.get_pubkey())
            self._merkletree = _to_merkle_tree(bigpubkey, self._hashlen, self._levelsalt)
            self.pubkey = self._merkletree["node"]

    async def available(self):
        """Check if the pubkey is already available"""
        if self.pubkey is None:
            for otskey in self._keys:
                if not otskey.available():
                    return False
        return True

    def sign_hash(self, digest, index):
        """Sign a hash"""
        bin_index = index.to_bytes(2,'big')
        merkle_prefix = _get_merkle_prefix(self._merkletree, self._height, index)
        return bin_index + self._levelsalt + merkle_prefix + self._keys[index].sign_hash(digest)

    def get_nonce(self, index):
        """Get a nonce that can be used with a given signature"""
        return self._nonces[index]

    def sign_data(self, data, index):
        """Sign a message"""
        bin_index = index.to_bytes(2,'big')
        merkle_prefix = _get_merkle_prefix(self._merkletree, self._height, index)
        return bin_index + self._levelsalt + merkle_prefix + self._keys[index].sign_data(data)


class _LevelSignature:
    """Single level signature validation"""
    def __init__(self, hashlen, otsbits, height, signature):
        self._height = height
        self._hashlen = hashlen
        bindex = signature[:2]
        remaining = signature[2:]
        self._level_salt = remaining[:hashlen]
        remaining = remaining[hashlen:]
        self._index = int.from_bytes(bindex,"big")
        self._merkle_nodes = []
        for _ in range(0, height+1):
            self._merkle_nodes.append(remaining[:hashlen])
            remaining = remaining[hashlen:]
        self._ots_signature = remaining
        self._validator = OneTimeValidator(hashlen,
                                           otsbits,
                                           self._level_salt,
                                           self._merkle_nodes[-1])

    def validate_data(self, data):
        """Validate a signature matches the data"""
        reconstructed_pubkey = self._validator.validate_data(data,
                                                             self._ots_signature,
                                                             merkle_mode=True)
        return _validate_merkle_root(self._merkle_nodes[:-1],
                                     self._merkle_nodes[-1],
                                     self._hashlen,
                                     self._height,
                                     self._index,
                                     self._level_salt,
                                     reconstructed_pubkey)

    def validate_hash(self, digest):
        """Validate that a signature matches a digest"""
        reconstructed_pubkey = self._validator.validate_hash(digest,
                                                             self._ots_signature,
                                                             merkle_mode=True)
        return _validate_merkle_root(self._merkle_nodes[:-1],
                                     self._merkle_nodes[-1],
                                     self._hashlen,
                                     self._height,
                                     self._index,
                                     self._level_salt,
                                     reconstructed_pubkey)

    def get_pubkey(self):
        """Get the level key pubkey pf the level key that created this signature"""
        return self._merkle_nodes[-1]

class LevelValidation:
    # pylint: disable=too-few-public-methods
    """Convenience class for constructing _LevelSignature objects"""
    def __init__(self, hashlen, otsbits, height):
        self._hashlen = hashlen
        self._otsbits = otsbits
        self._height = height

    def signature(self, level_signature):
        """Construct a signature object for a level signature"""
        return _LevelSignature(self._hashlen, self._otsbits, self._height, level_signature)
