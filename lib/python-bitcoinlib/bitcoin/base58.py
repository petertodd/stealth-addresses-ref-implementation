
#
# base58.py
# Original source: git://github.com/joric/brutus.git
# which was forked from git://github.com/samrushing/caesure.git
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
bchr = chr
bord = ord
if sys.version > '3':
        long = int
        bchr = lambda x: bytes([x])
        bord = lambda x: x

import binascii

import bitcoin.core

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

class Base58Error(Exception):
    pass

class InvalidBase58Error(Base58Error):
    pass

def encode(b):
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + binascii.hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod (n, 58)
        res.append(b58_digits[r])
    res = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    import sys
    czero = b'\x00'
    if sys.version > '3':
        # In Python3 indexing a bytes returns numbers, not characters.
        czero = 0
    pad = 0
    for c in b:
        if c == czero: pad += 1
        else: break
    return b58_digits[0] * pad + res

def decode(s):
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in b58_digits:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = b58_digits.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == b58_digits[0]: pad += 1
        else: break
    return b'\x00' * pad + res


class Base58ChecksumError(Base58Error):
    pass

class CBase58Data(bytes):
    def __new__(cls, s):
        k = decode(s)
        addrbyte, data, check0 = k[0:1], k[1:-4], k[-4:]
        check1 = bitcoin.core.Hash(addrbyte + data)[:4]
        if check0 != check1:
            raise Base58ChecksumError('Checksum mismatch: expected %r, calculated %r' % (check0, check1))
        return cls.from_bytes(data, ord(addrbyte))

    @classmethod
    def from_bytes(cls, data, nVersion):
        self = super(CBase58Data, cls).__new__(cls, data)
        self.nVersion = nVersion
        return self

    def to_bytes(self):
        return b'' + self

    def __str__(self):
        vs = bchr(self.nVersion) + self
        check = bitcoin.core.Hash(vs)[0:4]
        return encode(vs + check)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, str(self))
