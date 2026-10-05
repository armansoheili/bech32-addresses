#!/usr/bin/env python3
"""Bech32 / Bech32m address encoding and decoding in pure Python.

Implements the reference algorithms from:
- BIP173  (Bech32,  segwit v0  address encoding, checksum constant 1)
- BIP350  (Bech32m, segwit v1+ address encoding, checksum constant 0x2bc830a3)

Zero dependencies — only the standard library.
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _hrp_expand(hrp: str) -> list[int]:
    """Expand a human-readable part into values for checksum computation."""
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _polymod(values: list[int]) -> int:
    """Internal BCH checksum function."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= generator[i] if ((b >> i) & 1) else 0
    return chk


def _create_checksum(hrp: str, data: list[int], spec: int) -> list[int]:
    """Create a 6-character checksum (spec 1 = Bech32, 0x2BC830A3 = Bech32m)."""
    pm = _polymod(_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]) ^ spec
    return [(pm >> 5 * (5 - i)) & 31 for i in range(6)]


def encode(hrp: str, data: list[int], spec: int = 1) -> str:
    """Encode data as a Bech32 (spec=1) or Bech32m (spec=0x2BC830A3) address."""
    if not all(0 <= d < 32 for d in data):
        raise ValueError("data values must be 5-bit")
    combined = data + _create_checksum(hrp, data, spec)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def decode(bech: str) -> tuple[str, list[int], int] | None:
    """Decode a Bech32/Bech32m string.

    Returns (hrp, data, spec) on success, or None when the checksum is invalid
    (note: BIP350 requires the length of valid segwit programs, but this
    decoder stays format-agnostic and just reports the checksum spec).
    """
    if bech.lower() != bech and bech.upper() != bech:
        return None  # mixed case
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None
    hrp = bech[:pos]
    if not all(33 <= ord(c) <= 126 for c in bech[pos + 1:]):
        return None
    data = [CHARSET.find(c) for c in bech[pos + 1:]]
    if any(d == -1 for d in data):
        return None
    pm = _polymod(_hrp_expand(hrp) + data)
    if pm == 1:
        return hrp, data[:-6], 1
    if pm == 0x2BC830A3:
        return hrp, data[:-6], 0x2BC830A3
    return None


def convertbits(data: list[int], frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
    """General power-of-2 base conversion (BIP173 reference implementation)."""
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def segwit_encode(hrp: str, witver: int, witprog: list[int]) -> str | None:
    """Encode a segwit program (BIP173 for v0, BIP350 for v1+)."""
    if not (0 <= witver <= 16):
        return None
    if not (2 <= len(witprog) <= 40):
        return None
    if witver == 0 and len(witprog) not in (20, 32):
        return None
    spec = 1 if witver == 0 else 0x2BC830A3
    data = [witver] + (convertbits(witprog, 8, 5) or [])
    return encode(hrp, data, spec)


def segwit_decode(hrp: str, addr: str) -> tuple[int, list[int]] | None:
    """Decode a segwit address; returns (witness version, witness program)."""
    dec = decode(addr)
    if dec is None or dec[0] != hrp or len(dec[1]) < 1:
        return None
    witver, payload = dec[1][0], dec[1][1:]
    prog = convertbits(payload, 5, 8, False)
    if prog is None or len(prog) < 2 or len(prog) > 40:
        return None
    if witver > 16:
        return None
    if witver == 0 and len(prog) not in (20, 32):
        return None
    if witver == 0 and dec[2] != 1:
        return None  # v0 must be Bech32, not Bech32m
    if witver != 0 and dec[2] != 0x2BC830A3:
        return None  # v1+ must be Bech32m
    return witver, prog


if __name__ == "__main__":
    # BIP173 P2WPKH example: hash160 of a public key on mainnet
    witprog = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
    addr = segwit_encode("bc", 0, list(witprog))
    print("encoded :", addr)
    print("decoded :", segwit_decode("bc", addr))
    # Bech32m P2TR example from BIP350
    addr_m = segwit_encode("bc", 1, [0x51] * 32)
    print("bech32m :", addr_m)
    print("roundtrip:", segwit_decode("bc", addr_m) == (1, [0x51] * 32))
    # tampered string must fail
    print("tamper  :", decode(addr[:-1] + ("q" if addr[-1] != "q" else "p")))
