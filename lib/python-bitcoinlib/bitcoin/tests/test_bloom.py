# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from __future__ import absolute_import, division, print_function, unicode_literals

import json
import os
import unittest

from binascii import unhexlify

import bitcoin.core
from bitcoin.bloom import *

class Test_MurmurHash3(unittest.TestCase):
    def test(self):
        def T(expected, seed, data):
            self.assertEqual(MurmurHash3(seed, unhexlify(data)), expected)

        T(0x00000000, 0x00000000, b"");
        T(0x6a396f08, 0xFBA4C795, b"");
        T(0x81f16f39, 0xffffffff, b"");

        T(0x514e28b7, 0x00000000, b"00");
        T(0xea3f0b17, 0xFBA4C795, b"00");
        T(0xfd6cf10d, 0x00000000, b"ff");

        T(0x16c6b7ab, 0x00000000, b"0011");
        T(0x8eb51c3d, 0x00000000, b"001122");
        T(0xb4471bf8, 0x00000000, b"00112233");
        T(0xe2301fa8, 0x00000000, b"0011223344");
        T(0xfc2e4a15, 0x00000000, b"001122334455");
        T(0xb074502c, 0x00000000, b"00112233445566");
        T(0x8034d2a0, 0x00000000, b"0011223344556677");
        T(0xb4698def, 0x00000000, b"001122334455667788");


class Test_CBloomFilter(unittest.TestCase):
    def test_create_insert_serialize(self):
        filter = CBloomFilter(3, 0.01, 0, CBloomFilter.UPDATE_ALL)

        def T(elem):
            """Filter contains elem"""
            elem = unhexlify(elem)
            filter.insert(elem)
            self.assertTrue(filter.contains(elem))

        def F(elem):
            """Filter does not contain elem"""
            elem = unhexlify(elem)
            self.assertFalse(filter.contains(elem))

        T(b'99108ad8ed9bb6274d3980bab5a85c048f0950c8')
        F(b'19108ad8ed9bb6274d3980bab5a85c048f0950c8')
        T(b'b5a2c786d9ef4658287ced5914b37a1b4aa32eee')
        T(b'b9300670b4c5366e95b2699e8b18bc75e5f729c5')

        self.assertEqual(filter.serialize(), unhexlify(b'03614e9b050000000000000001'))

    def test_create_insert_serialize_with_tweak(self):
        # Same test as bloom_create_insert_serialize, but we add a nTweak of 100
        filter = CBloomFilter(3, 0.01, 2147483649, CBloomFilter.UPDATE_ALL)

        def T(elem):
            """Filter contains elem"""
            elem = unhexlify(elem)
            filter.insert(elem)
            self.assertTrue(filter.contains(elem))

        def F(elem):
            """Filter does not contain elem"""
            elem = unhexlify(elem)
            self.assertFalse(filter.contains(elem))

        T(b'99108ad8ed9bb6274d3980bab5a85c048f0950c8')
        F(b'19108ad8ed9bb6274d3980bab5a85c048f0950c8')
        T(b'b5a2c786d9ef4658287ced5914b37a1b4aa32eee')
        T(b'b9300670b4c5366e95b2699e8b18bc75e5f729c5')

        self.assertEqual(filter.serialize(), unhexlify(b'03ce4299050000000100008001'))

    def test_bloom_create_insert_key(self):
        filter = CBloomFilter(2, 0.001, 0, CBloomFilter.UPDATE_ALL)

        pubkey = unhexlify(b'045B81F0017E2091E2EDCD5EECF10D5BDD120A5514CB3EE65B8447EC18BFC4575C6D5BF415E54E03B1067934A0F0BA76B01C6B9AB227142EE1D543764B69D901E0')
        pubkeyhash = bitcoin.core.Hash160(pubkey)

        filter.insert(pubkey)
        filter.insert(pubkeyhash)

        self.assertEqual(filter.serialize(), unhexlify(b'038fc16b080000000000000001'))
