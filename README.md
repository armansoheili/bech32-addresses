# bech32-addresses

Bech32 and Bech32m address encoding/decoding in pure Python —
[BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)
and
[BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki),
the encoding behind Bitcoin's `bc1q...` (segwit v0) and `bc1p...`
(taproot / segwit v1+) addresses. Zero dependencies, standard library only.

## What it does

- `bech32.py` — reference algorithms: `encode` / `decode` (auto-detects
  Bech32 vs Bech32m by checksum constant), `convertbits` base conversion,
  plus segwit convenience helpers:
  - `segwit_encode(hrp, witver, witprog)` — encodes a witness program;
    uses the Bech32 checksum for version 0 and Bech32m for versions 1–16,
    exactly as BIP350 mandates.
  - `segwit_decode(hrp, addr)` — returns `(witness_version, witness_program)`
    or `None` for anything invalid, enforcing the v0↔Bech32 / v1+↔Bech32m rule.
- `test_vectors.py` — the official valid-address vectors from BIP173 and
  BIP350, plus the BIP173 P2WPKH/P2WSH segwit program vectors, run as a
  simple self-check.

## Run

```bash
python3 bech32.py        # quick demo: encode a P2WPKH address and round-trip it
python3 test_vectors.py  # verify against the official BIP test vectors
```

## Example

```python
from bech32 import segwit_encode, segwit_decode

# P2WPKH: hash160 of a public key
witprog = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
addr = segwit_encode("bc", 0, list(witprog))
# bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

segwit_decode("bc", addr)   # (0, [117, 30, 118, ...])
segwit_decode("bc", "bc1p...tampered...")  # None
```

## Why the checksums differ

Bech32's checksum constant `1` works for segwit v0, but a v0 program
encoded with a v1 checksum (or vice versa) can be silently accepted by
software written before BIP350. Bech32m's new constant `0x2BC830A3` for
versions ≥ 1 makes such mix-ups undecodable — the two encodings are
mutually detectable, protecting taproot addresses from being sent to
pre-taproot wallets without warning.
