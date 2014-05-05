# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import bitcoin.base58
import bitcoin.core
import bitcoin.core.key
import bitcoin.wallet

import bitcoin.core.script as script


class StealthAddressError(ValueError):
    pass

class StealthAddress(bitcoin.wallet.CBitcoinAddress):
    """A Stealth Address"""

    BASE58_PREFIX = 42

    # Due to 520 byte limit on P2SH scriptPubKeys
    MAX_SPEND_PUBKEYS = 15
    REUSE_SCAN_FOR_SPEND_OPTION = 1 << 0

    @property
    def reuse_scan_for_spend(self):
        """Return True if the scan pubkey is reused as a spend pubkey"""
        return bool(self[0] & self.REUSE_SCAN_FOR_SPEND_OPTION)

    @property
    def prefix_length_in_bytes(self):
        """Return prefix length in bytes

        That is, the number of bytes required to hold all the bits of the
        prefix.
        """
        return int(self.prefix_length / 8) + (1 if self.prefix_length % 8 else 0)

    def __init__(self, s):
        """Initialize from address string"""

        # Note that we don't actually have to do anything with our argument;
        # __new__() already did the heavy-lifting. We just need to take the
        # data encoded by the address and initialize the various instance
        # attributes.

        if len(self) < 1:
            raise StealthAddressError('Stealth address truncated at options')

        i = 1
        try:
            self.scan_pubkey = bitcoin.core.key.CPubKey(self[i:i+33])
            self.scan_pubkey[32] # force a failure if scan_pubkey is too short
        except IndexError:
            raise StealthAddressError('Stealth address truncated at scan_pubkey')

        i += 33

        try:
            n = self[i]
        except IndexError:
            raise StealthAddressError('Stealth address truncated at n')
        i += 1

        try:
            self.spend_pubkeys = []
            for j in range(n):
                self.spend_pubkeys.append(bitcoin.core.key.CPubKey(self[i:i+33]))
                self.spend_pubkeys[-1][32] # force a failure if spend_pubkey is too short
                i += 33

        except IndexError:
            raise StealthAddressError('Stealth address truncated at spend pubkeys')


        try:
            self.m = self[i]
            i += 1
        except IndexError:
            raise StealthAddressError('Stealth address truncated at m')

        try:
            self.prefix_length = self[i]
            i += 1
        except IndexError:
            raise StealthAddressError('Stealth address truncated at prefix_length')

        try:
            self.prefix = self[i:i+self.prefix_length_in_bytes]
            if self.prefix_length_in_bytes > 0:
                self.prefix[self.prefix_length_in_bytes-1]
            i += self.prefix_length_in_bytes
        except IndexError:
            raise StealthAddressError('Stealth address truncated at prefix')

        # Additional data at the end of an address *is* allowed for forwards
        # compatibility with new options.

        # Check pubkeys after reading all data; we want to display truncation
        # errors first.
        if not self.scan_pubkey.is_fullyvalid:
            raise StealthAddressError('Invalid scan pubkey')

        for spend_pubkey in self.spend_pubkeys:
            if not spend_pubkey.is_fullyvalid:
                raise StealthAddressError('Invalid spend pubkey %s' %
                                          bitcoin.core.b2x(spend_pubkey))

        # Check if spend_pubkeys were in sorted order; we don't want to make
        # stealth addresses mutable without a good reason.
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

        if len(self.all_spend_pubkeys) > self.MAX_SPEND_PUBKEYS:
            raise StealthAddressError('Too many spend pubkeys; got %d, max allowed is %d' % \
                                      (len(self.all_spend_pubkeys), self.MAX_SPEND_PUBKEYS))

        if not (0 < self.m <= len(self.all_spend_pubkeys)):
            raise StealthAddressError('m must be 0 < m <= # of spend pubkeys (including scan pubkey, if reused as spend)')


    @classmethod
    def from_pubkeys(cls, scan_pubkey, spend_pubkeys=(),
                     prefix_length=0, prefix=b'',
                     m=None, reuse_scan_for_spend=True):
        """Create stealth address directly from pubkeys

        scan_pubkey          - Pubkey to scan for payments
        spend_pubkeys        - Iterable of pubkeys required to spend the payment
        prefix_length        - Length of prefix, in bits. (default 0)
        prefix               - The prefix itself. (default b'')
        m                    - # of spend pubkeys required, defaults to all of them
        reuse_scan_for_spend - Reuse the scan pubkey as a spend pubkey (default True)

        All pubkeys must be of the compressed type.
        """
        if not (0 <= prefix_length <= 255):
            raise StealthAddressError('Invalid prefix length; must be between 0 and 255 inclusive; got %r' % prefix_length)

        if self.prefix_length_in_bytes != len(prefix):
            raise StealthAddressError('prefix_length does not match given prefix')

        self.prefix_length = prefix_length
        self.prefix = prefix

        if not scan_pubkey.is_compressed:
            raise StealthAddressError('scan_pubkey must be compressed')
        for spend_pubkey in spend_pubkeys:
            if not spend_pubkey.is_compressed:
                raise StealthAddressError('All spend_pubkeys must be compressed')

        option_flags = cls.REUSE_SCAN_FOR_SPEND_OPTION if reuse_scan_for_spend else 0

        # The encoding can only encode up to 255 spend_pubkeys, on top of the
        # 15 pubkey limit, so just truncate it here and let __new__() handle
        # the error
        spend_pubkeys = spend_pubkeys[0:256]

        # canonicalize order
        spend_pubkeys = sorted(spend_pubkeys)

        if m is None:
            m = len(spend_pubkeys)
            if reuse_scan_for_spend:
                m += 1
        if not (0 < m <= cls.MAX_SPEND_PUBKEYS):
            raise StealthAddressError('m must be in range 0 < m <= MAX_SPEND_PUBKEYS; got %d' % n)

        # As we're encoding the address data directly and passing it through
        # the usual machinery __init__() will be called, which has all the
        # validation and instance attribute initialization machinery.
        buf = (bytes([option_flags])
               + scan_pubkey
               + bytes([len(spend_pubkeys)])
               + b''.join(spend_pubkeys)
               + bytes([m]))

        return cls.from_bytes(buf, cls.BASE58_PREFIX)


    def to_scriptPubKey(self):
        raise NotImplementedError("You can not turn a StealthAddress directly into a scriptPubKey")


    @staticmethod
    def derive_pubkey(spend_pubkey, shared_secret):
        """Derive a pubkey from a spend pubkey and the shared secret"""
        # FIXME: Need to implement ECC addition
        return bitcoin.core.key.CPubKey(spend_pubkey)

    def make_payee_scriptPubKey(self, shared_secret):
        """Make the payee's scriptPubKey based on the shared secret

        Returns (scriptPubKey, redeemScript). If P2SH is not used, redeemScript
        will be set to None.
        """

        if len(self.all_spend_pubkeys) == 1:
            spend_pubkey = list(self.all_spend_pubkeys)[0]
            derived_pubkey = self.derive_pubkey(spend_pubkey, shared_secret)

            scriptPubKey = script.CScript([script.OP_DUP, script.OP_HASH160,
                                           bitcoin.core.Hash160(derived_pubkey),
                                           script.OP_EQUALVERIFY, script.OP_CHECKSIG])

            return (scriptPubKey, None)

        elif len(self.all_spend_pubkeys) > 1:
            derived_pubkeys = sorted([self.derive_pubkey(spend_pubkey, shared_secret)
                                        for spend_pubkey in self.all_spend_pubkeys])

            redeemScript = script.CScript([self.n]
                                          + derived_pubkeys
                                          + [len(derived_pubkeys), script.OP_CHECKMULTISIG])

            scriptPubKey = redeemScript.to_p2sh_scriptPubKey()
            return (scriptPubKey, redeemScript)

        else:
            assert False


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

