# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import unittest

import bitcoin.base58

from bitcoin.core import x
from bitcoin.core.key import CPubKey
from stealthaddress import StealthAddress, StealthAddressError


class Test_StealthAddress(unittest.TestCase):

    def test_invalid(self):
        invalids = (x(''),
                    x('00'),
                    x('00000000000000000000000000000000000000000000000000000000000000000000'),
                    )

        for invalid in invalids:
            invalid = str(bitcoin.base58.CBase58Data.from_bytes(invalid, StealthAddress.BASE58_PREFIX))
            with self.assertRaises(StealthAddressError, msg=repr(invalid)):
                StealthAddress(invalid)

    def test_valid_from_pubkeys(self):
        valid_addrs = (
                       (CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71')),
                        dict()),
                      )

        for scan_pubkey, additional_kwargs in valid_addrs:
            kwargs = dict(n = None, reuse_scan_for_spend=True)
            kwargs.update(additional_kwargs)
            actual_addr = StealthAddress.from_pubkeys(scan_pubkey, **kwargs)

            str_actual_addr = str(actual_addr)
            round_trip_addr = StealthAddress(str_actual_addr)

            self.assertEqual(actual_addr, round_trip_addr)

