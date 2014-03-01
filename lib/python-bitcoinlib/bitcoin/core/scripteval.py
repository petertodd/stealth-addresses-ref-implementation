
#
# scripteval.py
#
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

"""Script evaluation

Be warned that there are highly likely to be consensus bugs in this code; it is
unlikely to match Satoshi Bitcoin exactly. Think carefully before using this
module.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
bord = ord
if sys.version > '3':
    long = int
    bord = lambda x: x

import copy
import hashlib

import bitcoin.core
import bitcoin.core.key
import bitcoin.core.serialize

from bitcoin.core.script import *

nMaxNumSize = 4
MAX_SCRIPT_SIZE = 10000
MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_SCRIPT_OPCODES = 201
MAX_STACK_ITEMS = 1000

SCRIPT_VERIFY_P2SH = object()
SCRIPT_VERIFY_STRICTENC = object()
SCRIPT_VERIFY_EVEN_S = object()
SCRIPT_VERIFY_NOCACHE = object()

# Invalid even when occuring in an unexecuted OP_IF branch due to either being
# disabled, or never implemented.
disabled_opcodes = set((OP_VERIF, OP_VERNOTIF,
                        OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND,
                        OP_OR, OP_XOR, OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD,
                        OP_LSHIFT, OP_RSHIFT))

class EvalScriptError(bitcoin.core.ValidationError):
    """Base class for exceptions raised when a script fails during EvalScript()

    The execution state just prior the opcode raising the is saved. (if
    available)
    """
    def __init__(self,
                 msg,
                 sop=None, sop_data=None, sop_pc=None,
                 stack=None, scriptIn=None, txTo=None, inIdx=None, flags=None,
                 altstack=None, vfExec=None, pbegincodehash=None, nOpCount=None):
        super(EvalScriptError, self).__init__('EvalScript: %s' % msg)

        sop = sop
        sop_data = sop_data
        sop_pc = sop_pc
        stack = stack
        scriptIn = scriptIn
        txTo = txTo
        inIdx = inIdx
        flags = flags
        altstack = altstack
        vfExec = vfExec
        pbegincodehash = pbegincodehash
        nOpCount = nOpCount


class MissingOpArgumentsError(EvalScriptError):
    """Missing arguments"""
    def __init__(self, opcode, s, n, **kwargs):
        super(MissingOpArgumentsError, self).__init__(
                'missing arguments for %s; need %d items, but only %d on stack' %
                                   (OPCODE_NAMES[opcode], n, len(s)),
                **kwargs)

class ArgumentsInvalidError(EvalScriptError):
    """Arguments are invalid"""
    def __init__(self, opcode, msg, **kwargs):
        super(MissingOpArgumentsError, self).__init__(
                '%s args invalid: %s' % (OPCODE_NAMES[opcode], msg),
                **kwargs)


class VerifyOpFailedError(EvalScriptError):
    """A VERIFY opcode failed"""
    def __init__(self, opcode, **kwargs):
        super(VerifyOpFailedError, self).__init__('%s failed' % OPCODE_NAMES[opcode],
                                                  **kwargs)

def _CastToBigNum(s, err_raiser):
    v = bitcoin.core.bignum.vch2bn(s)
    if len(s) > nMaxNumSize:
        raise err_raiser(EvalScriptError, 'CastToBigNum() : overflow')
    return v

def _CastToBool(s):
    for i in range(len(s)):
        sv = bord(s[i])
        if sv != 0:
            if (i == (len(s) - 1)) and (sv == 0x80):
                return False
            return True

    return False


def _FindAndDelete(script, sig):
    # Since the Satoshi CScript.FindAndDelete() works on a binary level we have
    # to do that too. Notably FindAndDelete() will not delete if the PUSHDATA
    # used in the script is non-standard.
    sig_bytes = bytes(CScript([sig]))
    script_bytes = bytes(script)
    script_bytes = script_bytes.replace(sig_bytes, b'')
    return CScript(script_bytes)


def _CheckSig(sig, pubkey, script, txTo, inIdx, err_raiser):
    key = bitcoin.core.key.CKey()
    key.set_pubkey(pubkey)

    if len(sig) == 0:
        return False
    hashtype = bord(sig[-1])
    sig = sig[:-1]

    # Raw signature hash due to the SIGHASH_SINGLE bug
    #
    # Note that we never raise an exception if RawSignatureHash() returns an
    # error code. However the first error code case, where inIdx >=
    # len(txTo.vin), shouldn't ever happen during EvalScript() as that would
    # imply the scriptSig being checked doesn't correspond to a valid txout -
    # that should cause other validation machinery to fail long before we ever
    # got here.
    (h, err) = RawSignatureHash(script, txTo, inIdx, hashtype)
    return key.verify(h, sig)


def _CheckMultiSig(opcode, script, stack, txTo, inIdx, err_raiser):
    i = 1
    if len(stack) < i:
        err_raiser(MissingOpArgumentsError, opcode, stack, i)

    keys_count = _CastToBigNum(stack[-i], err_raiser)
    if keys_count < 0 or keys_count > 20:
        err_raiser(ArgumentsInvalidError, opcode, "keys count invalid")
    i += 1
    ikey = i
    i += keys_count
    if len(stack) < i:
        err_raiser(ArgumentsInvalidError, opcode, "not enough keys on stack")

    sigs_count = _CastToBigNum(stack[-i], err_raiser)
    if sigs_count < 0 or sigs_count > keys_count:
        err_raiser(ArgumentsInvalidError, opcode, "sigs count invalid")

    i += 1
    isig = i
    i += sigs_count
    if len(stack) < i:
        raise err_raiser(ArgumentsInvalidError, opcode, "not enough sigs on stack")

    # Drop the signature, since there's no way for a signature to sign itself
    #
    # Of course, this can only come up in very contrived cases now that
    # scriptSig and scriptPubKey are processed separately.
    for k in range(sigs_count):
        sig = stack[-isig-k]
        script = _FindAndDelete(script, sig)

    success = True

    while success and sigs_count > 0:
        sig = stack[-isig]
        pubkey = stack[-ikey]

        if _CheckSig(sig, pubkey, script, txTo, inIdx, err_raiser):
            isig += 1
            sigs_count -= 1

        ikey += 1
        keys_count -= 1

        if sigs_count > keys_count:
            success = False

            # with VERIFY bail now before we modify the stack
            if opcode == OP_CHECKMULTISIGVERIFY:
                err_raiser(VerifyOpFailedError, opcode)

    while i > 0:
        stack.pop()
        i -= 1

    assert opcode == OP_CHECKMULTISIG

    if success:
        stack.append(b"\x01")
    else:
        stack.append(b"\x00")


# OP_2MUL and OP_2DIV are *not* included in this list as they are disabled
ISA_UNOP = {
    OP_1ADD,
    OP_1SUB,
    OP_NEGATE,
    OP_ABS,
    OP_NOT,
    OP_0NOTEQUAL,
}

def _UnaryOp(opcode, stack, err_raiser):
    if len(stack) < 1:
        err_raiser(MissingOpArgumentsError, opcode, stack, 1)
    bn = _CastToBigNum(stack[-1], err_raiser)
    stack.pop()

    if opcode == OP_1ADD:
        bn += 1

    elif opcode == OP_1SUB:
        bn -= 1

    elif opcode == OP_NEGATE:
        bn = -bn

    elif opcode == OP_ABS:
        if bn < 0:
            bn = -bn

    elif opcode == OP_NOT:
        bn = long(bn == 0)

    elif opcode == OP_0NOTEQUAL:
        bn = long(bn != 0)

    else:
        raise AssertionError("Unknown unary opcode encountered; this should not happen")

    stack.append(bitcoin.core.bignum.bn2vch(bn))


# OP_LSHIFT and OP_RSHIFT are *not* included in this list as they are disabled
ISA_BINOP = {
    OP_ADD,
    OP_SUB,
    OP_BOOLAND,
    OP_BOOLOR,
    OP_NUMEQUAL,
    OP_NUMEQUALVERIFY,
    OP_NUMNOTEQUAL,
    OP_LESSTHAN,
    OP_GREATERTHAN,
    OP_LESSTHANOREQUAL,
    OP_GREATERTHANOREQUAL,
    OP_MIN,
    OP_MAX,
}

def _BinOp(opcode, stack, err_raiser):
    if len(stack) < 2:
        err_raiser(MissingOpArgumentsError, opcode, stack, 2)

    bn2 = _CastToBigNum(stack[-1], err_raiser)
    bn1 = _CastToBigNum(stack[-2], err_raiser)

    # We don't pop the stack yet so that OP_NUMEQUALVERIFY can raise
    # VerifyOpFailedError with a correct stack.

    if opcode == OP_ADD:
        bn = bn1 + bn2

    elif opcode == OP_SUB:
        bn = bn1 - bn2

    elif opcode == OP_BOOLAND:
        bn = long(bn1 != 0 and bn2 != 0)

    elif opcode == OP_BOOLOR:
        bn = long(bn1 != 0 or bn2 != 0)

    elif opcode == OP_NUMEQUAL:
        bn = long(bn1 == bn2)

    elif opcode == OP_NUMEQUALVERIFY:
        bn = long(bn1 == bn2)
        if not bn:
            err_raiser(VerifyOpFailedError, opcode)
        else:
            # No exception, so time to pop the stack
            stack.pop()
            stack.pop()
            return

    elif opcode == OP_NUMNOTEQUAL:
        bn = long(bn1 != bn2)

    elif opcode == OP_LESSTHAN:
        bn = long(bn1 < bn2)

    elif opcode == OP_GREATERTHAN:
        bn = long(bn1 > bn2)

    elif opcode == OP_LESSTHANOREQUAL:
        bn = long(bn1 <= bn2)

    elif opcode == OP_GREATERTHANOREQUAL:
        bn = long(bn1 >= bn2)

    elif opcode == OP_MIN:
        if bn1 < bn2:
            bn = bn1
        else:
            bn = bn2

    elif opcode == OP_MAX:
        if bn1 > bn2:
            bn = bn1
        else:
            bn = bn2

    else:
        raise AssertionError("Unknown binop opcode encountered; this should not happen")

    stack.pop()
    stack.pop()
    stack.append(bitcoin.core.bignum.bn2vch(bn))


def _CheckExec(vfExec):
    for b in vfExec:
        if not b:
            return False
    return True


def _EvalScript(stack, scriptIn, txTo, inIdx, flags=()):
    """Evaluate a script

    """
    if len(scriptIn) > MAX_SCRIPT_SIZE:
        raise EvalScriptError('script too large; got %d bytes; maximum %d bytes' %
                                        (len(scriptIn), MAX_SCRIPT_SIZE),
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)

    altstack = []
    vfExec = []
    pbegincodehash = 0
    nOpCount = 0
    for (sop, sop_data, sop_pc) in scriptIn.raw_iter():
        fExec = _CheckExec(vfExec)

        def err_raiser(cls, *args):
            """Helper function for raising EvalScriptError exceptions

            cls   - subclass you want to raise
            *args - arguments

            Fills in the state of execution for you.
            """
            raise cls(*args,
                    sop=sop,
                    sop_data=sop_data,
                    sop_pc=sop_pc,
                    stack=stack, scriptIn=scriptIn, txTo=txTo, inIdx=inIdx, flags=flags,
                    altstack=altstack, vfExec=vfExec, pbegincodehash=pbegincodehash, nOpCount=nOpCount)


        if sop in disabled_opcodes:
            err_raiser(EvalScriptError, 'opcode %s is disabled' % OPCODE_NAMES[sop])

        if sop > OP_16:
            nOpCount += 1
            if nOpCount > MAX_SCRIPT_OPCODES:
                err_raiser(EvalScriptError, 'max opcode count exceeded')

        def check_args(n):
            if len(stack) < n:
                err_raiser(MissingOpArgumentsError, sop, stack, n)


        if sop <= OP_PUSHDATA4:
            if len(sop_data) > MAX_SCRIPT_ELEMENT_SIZE:
                err_raiser(EvalScriptError,
                           'PUSHDATA of length %d; maximum allowed is %d' %
                                (len(sop_data), MAX_SCRIPT_ELEMENT_SIZE))

            elif fExec:
                stack.append(sop_data)
                continue

        elif fExec and (sop == OP_1NEGATE or ((sop >= OP_1) and (sop <= OP_16))):
            v = sop - (OP_1 - 1)
            stack.append(bitcoin.core.bignum.bn2vch(v))

        elif fExec and sop in ISA_BINOP:
            _BinOp(sop, stack, err_raiser)

        elif fExec and sop in ISA_UNOP:
            _UnaryOp(sop, stack, err_raiser)

        elif fExec and sop == OP_2DROP:
            check_args(2)
            stack.pop()
            stack.pop()

        elif fExec and sop == OP_2DUP:
            check_args(2)
            v1 = stack[-2]
            v2 = stack[-1]
            stack.append(v1)
            stack.append(v2)

        elif fExec and sop == OP_2OVER:
            check_args(4)
            v1 = stack[-4]
            v2 = stack[-3]
            stack.append(v1)
            stack.append(v2)

        elif fExec and sop == OP_2ROT:
            check_args(6)
            v1 = stack[-6]
            v2 = stack[-5]
            del stack[-6]
            del stack[-5]
            stack.append(v1)
            stack.append(v2)

        elif fExec and sop == OP_2SWAP:
            check_args(4)
            tmp = stack[-4]
            stack[-4] = stack[-2]
            stack[-2] = tmp

            tmp = stack[-3]
            stack[-3] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop == OP_3DUP:
            check_args(3)
            v1 = stack[-3]
            v2 = stack[-2]
            v3 = stack[-1]
            stack.append(v1)
            stack.append(v2)
            stack.append(v3)

        elif fExec and sop == OP_CHECKMULTISIG or sop == OP_CHECKMULTISIGVERIFY:
            tmpScript = CScript(scriptIn[pbegincodehash:])
            _CheckMultiSig(sop, tmpScript, stack, txTo, inIdx, err_raiser)

        elif fExec and sop == OP_CHECKSIG or sop == OP_CHECKSIGVERIFY:
            check_args(2)
            vchPubKey = stack[-1]
            vchSig = stack[-2]
            tmpScript = CScript(scriptIn[pbegincodehash:])

            # Drop the signature, since there's no way for a signature to sign itself
            #
            # Of course, this can only come up in very contrived cases now that
            # scriptSig and scriptPubKey are processed separately.
            tmpScript = _FindAndDelete(tmpScript, vchSig)

            ok = _CheckSig(vchSig, vchPubKey, tmpScript, txTo, inIdx,
                           err_raiser)
            if not ok and sop == OP_CHECKSIGVERIFY:
                err_raiser(VerifyOpFailedError, sop)

            else:
                stack.pop()
                stack.pop()

                if ok:
                    if sop != OP_CHECKSIGVERIFY:
                        stack.append(b"\x01")
                else:
                    stack.append(b"\x00")

        elif fExec and sop == OP_CODESEPARATOR:
            pbegincodehash = sop_pc

        elif fExec and sop == OP_DEPTH:
            bn = len(stack)
            stack.append(bitcoin.core.bignum.bn2vch(bn))

        elif fExec and sop == OP_DROP:
            check_args(1)
            stack.pop()

        elif fExec and sop == OP_DUP:
            check_args(1)
            v = stack[-1]
            stack.append(v)

        elif sop == OP_ELSE:
            if len(vfExec) == 0:
                err_raiser(EvalScriptError, 'ELSE found without prior IF')
            vfExec[-1] = not vfExec[-1]

        elif sop == OP_ENDIF:
            if len(vfExec) == 0:
                err_raiser(EvalScriptError, 'ENDIF found without prior IF')
            vfExec.pop()

        elif fExec and sop == OP_EQUAL:
            check_args(2)
            v1 = stack.pop()
            v2 = stack.pop()

            if v1 == v2:
                stack.append(b"\x01")
            else:
                stack.append(b"\x00")

        elif fExec and sop == OP_EQUALVERIFY:
            check_args(2)
            v1 = stack[-1]
            v2 = stack[-2]

            if v1 == v2:
                stack.pop()
                stack.pop()
            else:
                err_raiser(VerifyOpFailedError, sop)

        elif fExec and sop == OP_FROMALTSTACK:
            if len(altstack) < 1:
                err_raiser(MissingOpArgumentsError, sop, altstack, 1)
            v = altstack.pop()
            stack.append(v)

        elif fExec and sop == OP_HASH160:
            check_args(1)
            stack.append(bitcoin.core.serialize.Hash160(stack.pop()))

        elif fExec and sop == OP_HASH256:
            check_args(1)
            stack.append(bitcoin.core.serialize.Hash(stack.pop()))

        elif sop == OP_IF or sop == OP_NOTIF:
            val = False

            if fExec:
                check_args(1)
                vch = stack.pop()
                val = _CastToBool(vch)
                if sop == OP_NOTIF:
                    val = not val

            vfExec.append(val)


        elif fExec and sop == OP_IFDUP:
            check_args(1)
            vch = stack[-1]
            if _CastToBool(vch):
                stack.append(vch)

        elif fExec and sop == OP_NIP:
            check_args(2)
            del stack[-2]

        elif fExec and sop == OP_NOP or (sop >= OP_NOP1 and sop <= OP_NOP10):
            pass

        elif fExec and sop == OP_OVER:
            check_args(2)
            vch = stack[-2]
            stack.append(vch)

        elif fExec and sop == OP_PICK or sop == OP_ROLL:
            check_args(2)
            n = _CastToBigNum(stack.pop(), err_raiser)
            if n < 0 or n >= len(stack):
                err_raiser(EvalScriptError, "Argument for %s out of bounds" % OPCODE_NAMES[sop])
            vch = stack[-n-1]
            if sop == OP_ROLL:
                del stack[-n-1]
            stack.append(vch)

        elif fExec and sop == OP_RETURN:
            err_raiser(EvalScriptError, "OP_RETURN called")

        elif fExec and sop == OP_RIPEMD160:
            check_args(1)

            h = hashlib.new('ripemd160')
            h.update(stack.pop())
            stack.append(h.digest())

        elif fExec and sop == OP_ROT:
            check_args(3)
            tmp = stack[-3]
            stack[-3] = stack[-2]
            stack[-2] = tmp

            tmp = stack[-2]
            stack[-2] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop == OP_SIZE:
            check_args(1)
            bn = len(stack[-1])
            stack.append(bitcoin.core.bignum.bn2vch(bn))

        elif fExec and sop == OP_SHA1:
            check_args(1)
            stack.append(hashlib.sha1(stack.pop()).digest())

        elif fExec and sop == OP_SHA256:
            check_args(1)
            stack.append(hashlib.sha256(stack.pop()).digest())

        elif fExec and sop == OP_SWAP:
            check_args(2)
            tmp = stack[-2]
            stack[-2] = stack[-1]
            stack[-1] = tmp

        elif fExec and sop == OP_TOALTSTACK:
            check_args(1)
            v = stack.pop()
            altstack.append(v)

        elif fExec and sop == OP_TUCK:
            check_args(2)
            vch = stack[-1]
            stack.insert(len(stack) - 2, vch)

        elif fExec and sop == OP_VERIFY:
            check_args(1)
            v = _CastToBool(stack[-1])
            if v:
                stack.pop()
            else:
                raise err_raiser(VerifyOpFailedError, sop)

        elif fExec and sop == OP_WITHIN:
            check_args(3)
            bn3 = _CastToBigNum(stack[-1], err_raiser)
            bn2 = _CastToBigNum(stack[-2], err_raiser)
            bn1 = _CastToBigNum(stack[-3], err_raiser)
            stack.pop()
            stack.pop()
            stack.pop()
            v = (bn2 <= bn1) and (bn1 < bn3)
            if v:
                stack.append(b"\x01")
            else:
                stack.append(b"\x00")

        elif fExec:
            err_raiser(EvalScriptError, 'unsupported opcode 0x%x' % sop)

        # size limits
        if len(stack) + len(altstack) > MAX_STACK_ITEMS:
            err_raiser(EvalScriptError, 'max stack items limit reached')

    # Unterminated IF/NOTIF/ELSE block
    if len(vfExec):
        raise EvalScriptError('Unterminated IF/ELSE block',
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)


def EvalScript(stack, scriptIn, txTo, inIdx, flags=()):
    """Evaluate a script

    stack    - Initial stack
    scriptIn - Script
    txTo     - Transaction the script is a part of
    inIdx    - txin index of the scriptSig
    flags    - SCRIPT_VERIFY_* flags to apply
    """

    try:
        _EvalScript(stack, scriptIn, txTo, inIdx, flags=flags)
    except CScriptInvalidError as err:
        raise EvalScriptError(repr(err),
                              stack=stack,
                              scriptIn=scriptIn,
                              txTo=txTo,
                              inIdx=inIdx,
                              flags=flags)

class VerifyScriptError(bitcoin.core.ValidationError):
    pass

def VerifyScript(scriptSig, scriptPubKey, txTo, inIdx, flags=()):
    """Verify a scriptSig satisfies a scriptPubKey

    scriptSig    - Signature
    scriptPubKey - PubKey
    txTo         - Spending transaction
    inIdx        - Index of the transaction input containing scriptSig

    Raises a ValidationError subclass if the validation fails.
    """
    stack = []
    EvalScript(stack, scriptSig, txTo, inIdx, flags=flags)
    if SCRIPT_VERIFY_P2SH in flags:
        stackCopy = list(stack)
    EvalScript(stack, scriptPubKey, txTo, inIdx, flags=flags)
    if len(stack) == 0:
        raise VerifyScriptError("scriptPubKey left an empty stack")
    if not _CastToBool(stack[-1]):
        raise VerifyScriptError("scriptPubKey returned false")

    # Additional validation for spend-to-script-hash transactions
    if SCRIPT_VERIFY_P2SH in flags and scriptPubKey.is_p2sh():
        if not scriptSig.is_push_only():
            raise VerifyScriptError("P2SH scriptSig not is_push_only()")

        # stackCopy cannot be empty here, because if it was the
        # P2SH  HASH <> EQUAL  scriptPubKey would be evaluated with
        # an empty stack and the EvalScript above would return false.
        assert len(stackCopy)

        pubKey2 = CScript(stackCopy.pop())

        EvalScript(stackCopy, pubKey2, txTo, inIdx, flags=flags)

        if not len(stackCopy):
            raise VerifyScriptError("P2SH inner scriptPubKey left an empty stack")

        if not _CastToBool(stackCopy[-1]):
            raise VerifyScriptError("P2SH inner scriptPubKey returned false")


class VerifySignatureError(bitcoin.core.ValidationError):
    pass

def VerifySignature(txFrom, txTo, inIdx):
    """Verify a scriptSig signature can spend a txout

    Verifies that the scriptSig in txTo.vin[inIdx] is a valid scriptSig for the
    corresponding COutPoint in transaction txFrom.
    """
    if inIdx < 0:
        raise VerifySignatureError("inIdx negative")
    if inIdx >= len(txTo.vin):
        raise VerifySignatureError("inIdx >= len(txTo.vin)")
    txin = txTo.vin[inIdx]

    if txin.prevout.n < 0:
        raise VerifySignatureError("txin prevout.n negative")
    if txin.prevout.n >= len(txFrom.vout):
        raise VerifySignatureError("txin prevout.n >= len(txFrom.vout)")
    txout = txFrom.vout[txin.prevout.n]

    if txin.prevout.hash != bitcoin.core.serialize.Hash(txFrom.serialize()):
        raise VerifySignatureError("prevout hash does not match txFrom")

    VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, inIdx)
