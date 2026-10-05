#!/usr/bin/env python3
"""Test vectors for bech32.py (official vectors from BIP173 and BIP350)."""

import sys
sys.path.insert(0, ".")
from bech32 import decode, segwit_encode, segwit_decode  # noqa: E402

# BIP173 valid addresses (Bech32)
BIP173_VALID = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11" + "q" * 82 + "c8247j",  # exactly 90 chars, the max length
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]

# BIP350 valid addresses (Bech32m)
BIP350_VALID = [
    "A1LQFN3A",
    "a1lqfn3a",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]

# Official segwit addresses: (hrp, witness version, program hex, address)
SEGWIT = [
    ("bc", 0, "751e76e8199196d454941c45d1b3a323f1433bd6",
     "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),                     # BIP173 P2WPKH
    ("tb", 0, "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
     "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"),  # BIP173 P2WSH (testnet)
    ("bc", 1, "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
     "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),     # verified mainnet taproot address
]

# Official INVALID segwit addresses (BIP173) — all must fail
SEGWIT_INVALID = [
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",     # invalid HRP
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",     # invalid checksum
    "bc1rw5uspcuh",                                  # invalid program length
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",          # v0 program not 20/32 bytes
]

passed = failed = 0


def check(name: str, ok: bool) -> None:
    global passed, failed
    if ok:
        passed += 1
    else:
        failed += 1
        print("FAIL:", name)


for a in BIP173_VALID:
    dec = decode(a)
    check(f"BIP173 valid {a}", dec is not None and dec[2] == 1)
for a in BIP350_VALID:
    dec = decode(a)
    check(f"BIP350 valid {a}", dec is not None and dec[2] == 0x2BC830A3)
for hrp, ver, prog_hex, expected in SEGWIT:
    prog = list(bytes.fromhex(prog_hex))
    check(f"encode {expected}", segwit_encode(hrp, ver, prog) == expected)
    check(f"decode {expected}", segwit_decode(hrp, expected) == (ver, prog))
# bech32/bech32m cross-checksum must not be accepted as the other variant
check("bech32 not decoded as bech32m",
      decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw")[2] != 0x2BC830A3)
check("bech32m not decoded as bech32",
      decode("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx")[2] != 1)
for a in SEGWIT_INVALID:
    hrp = "tb" if a.startswith("tc") else "bc"
    check(f"invalid rejected {a}", segwit_decode(hrp, a) is None)
from bech32 import encode, convertbits  # noqa: E402
m_enc = encode("bc", [0] + (convertbits(list(bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")), 8, 5) or []), 0x2BC830A3)
check("v0 + bech32m rejected", segwit_decode("bc", m_enc) is None)
# mixed case rejected
check("mixed case rejected", decode("A12uEl5l") is None)
# single-character tampering must fail the checksum
dec_ok = decode("A12UEL5L")
tampered = "A12UEL5M"
check("tampered checksum rejected", decode(tampered) is None)

print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
