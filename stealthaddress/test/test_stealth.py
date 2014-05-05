# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import json
import os
import unittest

import bitcoin.base58

from bitcoin.core import b2x,x
from bitcoin.core.key import CPubKey
from stealthaddress import StealthAddress, StealthAddressError

def load_test_vector(name):
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for testcase in json.load(fd):
            yield testcase

class Test_StealthAddress(unittest.TestCase):
    def test_invalid(self):
        for comment, expected_exception, invalid in load_test_vector('invalid.json'):
            try:
                StealthAddress(invalid)
            except StealthAddressError as err:
                self.assertEqual(str(err), expected_exception)
                continue
            self.fail('Should have raised %r' % expected_exception)

    def test_valid(self):
        for comment, valid, expected_attributes in load_test_vector('valid.json'):
            addr = StealthAddress(valid)

            scan_pubkey = x(expected_attributes['scan_pubkey'])
            spend_pubkeys = (x(spend_pubkey) for spend_pubkey in expected_attributes['spend_pubkeys'])
            all_spend_pubkeys = set(x(spend_pubkey) for spend_pubkey in expected_attributes['all_spend_pubkeys'])
            prefix_length = expected_attributes['prefix_length']
            prefix = x(expected_attributes['prefix'])
            m = expected_attributes['m']
            reuse_scan_for_spend = expected_attributes['reuse_scan_for_spend']

            self.assertEqual(addr.scan_pubkey, scan_pubkey)
            self.assertEqual(tuple(addr.spend_pubkeys), tuple(spend_pubkeys))
            self.assertEqual(addr.all_spend_pubkeys, all_spend_pubkeys)
            self.assertEqual(addr.prefix_length, prefix_length)
            self.assertEqual(addr.prefix, prefix)
            self.assertEqual(addr.m, m)
            self.assertEqual(addr.reuse_scan_for_spend, reuse_scan_for_spend)
