# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import bitcoin.base58
import bitcoin.core
import bitcoin.core.key
import bitcoin.wallet

class StealthAddressError(ValueError):
    pass

class StealthAddress(bitcoin.wallet.CBitcoinAddress):
    """A Stealth Address"""

    BASE58_PREFIX = 255

    # Due to 520 byte limit on P2SH scriptPubKeys
    MAX_SPEND_PUBKEYS = 15
    REUSE_SCAN_FOR_SPEND_OPTION = 1 << 0

    @property
    def reuse_scan_for_spend(self):
        """Return True if the scan pubkey is reused as a spend pubkey"""
        return bool(self[0] & self.REUSE_SCAN_FOR_SPEND_OPTION)

    def __new__(cls, s):
        self = super(StealthAddress, cls).__new__(cls, s)

        if len(self) < 33:
            raise StealthAddressError('Stealth address truncated at scan pubkey')

        i = 1 # options is in index 0
        try:
            self.scan_pubkey = bitcoin.core.key.CPubKey(self[i:i+33])
            i += 33

            m = self[i]
            i += 1

            self.spend_pubkeys = []
            for j in range(m):
                self.spend_pubkeys.append(bitcoin.core.key.CPubKey(self[j:j+33]))
                i += 33

            self.n = self[i]
            i += 1
        except IndexError:
            raise StealthAddressError('Stealth address truncated')

        # Additional data at the end of an address *is* allowed for forwards
        # compatibility with new options.

        # Check pubkeys after reading all data; we want to display truncation
        # errors first.
        if not self.scan_pubkey.IsFullyValid():
            raise StealthAddressError('Invalid scan pubkey')

        for spend_pubkey in self.spend_pubkeys:
            if not spend_pubkey.IsFullyValid():
                raise StealthAddressError('Invalid spend pubkey %s' %
                                          bitcoin.core.b2x(spend_pubkey))

        # Check if spend_pubkeys were in sorted order; we don't want to make
        # stealth addresses mutable.
        if not sorted(self.spend_pubkeys) == self.spend_pubkeys:
            raise StealthAddressError('Spend pubkeys not in canonical sorted order')

        # Check for duplicates
        self.all_spend_pubkeys = set()
        if self.reuse_scan_for_spend:
            self.all_spend_pubkeys.add(self.scan_pubkey)

        for spend_pubkey in self.spend_pubkeys:
            if spend_pubkey in self.all_spend_pubkeys:
                raise StealthAddressError('Duplicate spend pubkey %s' % bitcoin.core.b2x(spend_pubkey))
            self.all_spend_pubkeys.add(spend_pubkey)

        if not self.all_spend_pubkeys:
            raise StealthAddressError('No spend pubkeys specified!')

        if len(self.all_spend_pubkeys) > cls.MAX_SPEND_PUBKEYS:
            raise StealthAddressError('Too many spend pubkeys; got %d, max allowed is %d' % \
                                      (len(self.all_spend_pubkeys), MAX_SPEND_PUBKEYS))

        if not (0 < self.n <= len(self.all_spend_pubkeys)):
            raise StealthAddressError('n must be 0 < n <= # of spend pubkeys (including scan pubkey, if reused as spend)')

        return self


    @classmethod
    def from_pubkeys(cls, scan_pubkey, spend_pubkeys=(), n=None, reuse_scan_for_spend=True):
        """Create stealth addres directly from pubkeys

        scan_pubkey          - Pubkey to scan for payments
        spend_pubkeys        - Iterable of pubkeys required to spend the payment
        n                    - # of spend pubkeys required, defaults to all of them
        reuse_scan_for_spend - Reuse the scan pubkey as a spend pubkey (default True)

        All pubkeys must be of the compressed type.
        """
        if not scan_pubkey.IsCompressed():
            raise StealthAddressError('scan_pubkey must be compressed')
        for spend_pubkey in spend_pubkeys:
            if not spend_pubkey.IsCompressed():
                raise StealthAddressError('All spend_pubkeys must be compressed')

        option_flags = cls.REUSE_SCAN_FOR_SPEND_OPTION if reuse_scan_for_spend else 0

        # The encoding can only encode up to 255 spend_pubkeys, on top of the
        # 15 pubkey limit, so just truncate it here and let __new__() handle
        # the error
        spend_pubkeys = spend_pubkeys[0:256]

        if n is None:
            n = len(spend_pubkeys)
        if reuse_scan_for_spend:
            n += 1
        if not (0 < n <= cls.MAX_SPEND_PUBKEYS):
            raise StealthAddressError('n must be in range 0 < n <= MAX_SPEND_PUBKEYS; got %d' % n)

        buf = (bytes([option_flags])
               + scan_pubkey
               + bytes([len(spend_pubkeys)])
               + b''.join(spend_pubkeys)
               + bytes([n]))

        return cls.from_bytes(buf, cls.BASE58_PREFIX)


    def to_scriptPubKey(self):
        raise NotImplementedError

    def pay(self, tx_template=None):
        pass


class StealthScanSecret(bitcoin.base58.CBase58Data):
    """Stealth address with the scan secret key used to find stealth payments"""
    BASE58_PREFIX = 254

    def __new__(cls, scan_secret, stealth_addr):
        self = cls.from_bytes(scan_secret + stealth_addr, BASE58_PREFIX)
        return self


def recover(tx, stealth_scan_secrets):
    """Recover payments to stealth addresses

    tx                   - candidate transaction
    stealth_scan_secrets - iterable of StealthScanSecret's

    Most efficient if the stealth_addresses all share the same scanpubkey.
    """

