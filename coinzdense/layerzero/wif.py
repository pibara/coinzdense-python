"""Encoding/decoding ECDSA, CoinZdense and OTS-Recovery keys"""
import hashlib
from hashlib import sha256
from binascii import hexlify
from enum import Enum
from ellipticcurve.publicKey import PublicKey
from base58 import b58encode, b58decode
from sympy.ntheory import sqrt_mod

class Keytype(Enum):
    """Enum class for key types"""
    QDRECOVERYPUBKEY = 1
    QDRECOVERYPRIVKEY = 2
    COINZDENSEPUBKEY = 3
    COINZDENSEPRIVKEY = 4
    ECDSACOMPRESSEDPUBKEY = 5
    ECDSAPRIVKEY = 6


class CheckSumType(Enum):
    """Enum class for checksum types"""
    DOUBLESHA256 = 1
    RIPEMD160 = 2


def binary_to_wif(binkey, keytype):
    """Convert a binary key to WIF, depending on key type

    Parameters
    ----------
    binkey : bytes
               Binary public or private key
    keytype : Keytype
               The type of the key (enum)

    Returns
    -------
    string
        Base58 WIF of the key
    """
    csmap = {
        Keytype.QDRECOVERYPUBKEY: CheckSumType.RIPEMD160,
        Keytype.QDRECOVERYPRIVKEY: CheckSumType.DOUBLESHA256,
        Keytype.COINZDENSEPUBKEY: CheckSumType.RIPEMD160,
        Keytype.COINZDENSEPRIVKEY: CheckSumType.DOUBLESHA256,
        Keytype.ECDSACOMPRESSEDPUBKEY: CheckSumType.RIPEMD160,
        Keytype.ECDSAPRIVKEY: CheckSumType.DOUBLESHA256
    }
    netmap = {
        Keytype.QDRECOVERYPUBKEY: b'',
        Keytype.QDRECOVERYPRIVKEY: b'\xbb',
        Keytype.COINZDENSEPUBKEY: b'',
        Keytype.COINZDENSEPRIVKEY: b'\xbd',
        Keytype.ECDSACOMPRESSEDPUBKEY: b'',
        Keytype.ECDSAPRIVKEY: b'\x80'
    }
    prefixmap = {
        Keytype.QDRECOVERYPUBKEY: 'QRK',
        Keytype.QDRECOVERYPRIVKEY: '',
        Keytype.COINZDENSEPUBKEY: 'CZD',
        Keytype.COINZDENSEPRIVKEY: '',
        Keytype.ECDSACOMPRESSEDPUBKEY: 'STM',
        Keytype.ECDSAPRIVKEY: ''
    }
    fullkey = netmap[keytype] + binkey
    if csmap[keytype] == CheckSumType.DOUBLESHA256:
        checksum = sha256(sha256(fullkey).digest()).digest()[:4]
    elif csmap[keytype] == CheckSumType.RIPEMD160:
        hash1 = hashlib.new('ripemd160')
        hash1.update(fullkey)
        checksum = hash1.digest()[:4]
    return prefixmap[keytype] + b58encode(fullkey + checksum).decode("ascii")

def wif_to_binary(wif, expectedtype):
    """Restore binary key from WIF

    Parameters
    ----------
    wif : string
        wif base58 encoded key
    expectedtype : Keytype
        expected type of Wif encoded key

    Returns
    -------
    bytes
        The binary key

    Raises
    ------
    RuntimeError
        Thrown if WIF not of right type.
    """
    prefixmap = {
        "QRK": Keytype.QDRECOVERYPUBKEY,
        "CZD": Keytype.COINZDENSEPUBKEY,
        "STM": Keytype.ECDSACOMPRESSEDPUBKEY
    }
    netmap = {
        b'\xbb': Keytype.QDRECOVERYPRIVKEY,
        b'\xbd': Keytype.COINZDENSEPRIVKEY,
        b'\x80': Keytype.ECDSAPRIVKEY
    }
    if wif[:3] in prefixmap:
        keytype = prefixmap[wif[:3]]
        binkey = b58decode(wif[3:])[:-4]
    else:
        binwif = b58decode(wif)
        binkey = binwif[1:-4]
        if binwif[0:1] in netmap:
            keytype = netmap[binwif[0:1]]
        else:
            print(wif, expectedtype, hexlify(binwif), binwif[0:1], netmap)
            raise RuntimeError("Invalid input WIF")
    if keytype != expectedtype:
        raise RuntimeError("WIF of incorrect type")
    recalculated = key_to_wif(binkey, keytype)
    if recalculated != wif:
        raise RuntimeError("Invalid input WIF")
    return binkey

def pubkey_to_compressed(pubkey):
    """Convert an ecdsa pubkey object to a compressed binary key

    Parameters
    ----------
    pubkey : ellipticcurve.PublicKey
               ECDSA pubkey object

    Returns
    -------
    bytes
            Binary compressed pubkey without WIF checksum
    """
    xval = pubkey.point.x.to_bytes(32, byteorder='big')
    yred = (2 + pubkey.point.y % 2).to_bytes(1, byteorder='big')
    return yred + xval

def compressed_to_pubkey(compressed):
    """Convert a compressed binary key to an ecdsa pubkey object

    Parameters
    ----------
    compressed : bytes
        Binary compressed pubkey without WIF checksum

    Returns
    -------
    ellipticcurve.PublicKey
        ECDSA pubkey object

    Raises
    ------
    RuntimeError
        Thrown if invalid formatted compressed pubkey
    """
    _p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
    switchbyte = compressed[:1]
    x_coord = int.from_bytes(compressed[1:], byteorder='big', signed=False)
    y_values = sqrt_mod( (x_coord**3 + 7) % _p, _p, True )
    if switchbyte == b'\x02':
        if y_values[0] % 2 == 0:
            y_coord = y_values[0]
        else:
            y_coord = y_values[1]
    elif switchbyte == b'\x03':
        if y_values[0] % 2 == 0:
            y_coord = y_values[1]
        else:
            y_coord = y_values[0]
    else:
        raise RuntimeError("Invalid SEC compressed format")
    uncompressed = hexlify(
                       compressed[1:] + y_coord.to_bytes(
                           32,
                           byteorder='big',
                           signed=False
                       )
                   )
    return PublicKey.fromString(uncompressed)

def key_from_creds(account, role, password):
    """Derive a key from the master password (HIVE-style)

    Parameters
    ----------
    account : string
               Account name
    role : string
             owner/active/posting/disaster
    password : string
                 Master password for HIVE account

    Returns
    -------
    bytes
            Binary key for the given role and account.
    """
    seed = account + role + password
    return sha256(seed.encode("latin1")).digest()
