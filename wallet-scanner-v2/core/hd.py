"""BIP-32 / BIP-44 HD key derivation + ETH address (pure hashlib/coincurve)."""
from __future__ import annotations

import hashlib
import struct

import coincurve

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HMAC_KEY = b"Bitcoin seed"


def _ser2p(i: int) -> bytes:
    return b"\x00" + struct.pack(">I", i)


def _ckd_priv(key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = key + struct.pack(">I", index)
    else:
        data = coincurve.PrivateKey(key).public_key.format(compressed=True) + struct.pack(">I", index)
    I = hmac_sha512(chain_code, data)
    il, ir = I[:32], I[32:]
    k = (int.from_bytes(il, "big") + int.from_bytes(key, "big")) % CURVE_ORDER
    if 0 <= k == 0 or k >= CURVE_ORDER:
        raise ValueError("invalid derived key")
    return k.to_bytes(32, "big"), ir


def hmac_sha512(key: bytes, msg: bytes) -> bytes:
    import hmac
    return hmac.new(key, msg, hashlib.sha512).digest()


def master_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    I = hmac_sha512(HMAC_KEY, seed)
    return I[:32], I[32:]


def derive_path(seed: bytes, path: str) -> tuple[bytes, bytes]:
    key, cc = master_from_seed(seed)
    parts = path.replace("m/", "").split("/")
    for p in parts:
        hardened = p.endswith("'")
        idx = int(p[:-1]) + 0x80000000 if hardened else int(p)
        key, cc = _ckd_priv(key, cc, idx)
    return key, cc


def eth_address(priv: bytes) -> str:
    pub = coincurve.PrivateKey(priv).public_key.format(compressed=False)[1:]
    digest = _keccak(pub)
    return "0x" + digest[-20:].hex()


try:
    from Crypto.Hash import keccak as _pykeccak

    def _keccak(data: bytes) -> bytes:
        h = _pykeccak.new(digest_bits=256)
        h.update(data)
        return h.digest()
except ImportError:
    try:
        import sha3 as _sha3  # pysha3

        def _keccak(data: bytes) -> bytes:
            return _sha3.keccak_256(data).digest()
    except ImportError:
        # pure-python keccak fallback
        _RC = [0x01, 0x80, 0x8082, 0x8000, 0x808B, 0x80008089, 0x8000008B, 0x8000808B,
               0x0080008B, 0x8000008B, 0x8000808A, 0x8000008A, 0x80008081, 0x80008081,
               0x0000008A, 0x0000808A]

        def _keccak(data: bytes) -> bytes:  # noqa: F811
            rate = 136  # 1088 bits
            state = [[0] * 5 for _ in range(5)]
            padded = bytearray(data)
            padded.append(0x01)
            while len(padded) % rate != 0:
                padded.append(0)
            padded[-1] |= 0x80
            for blk_start in range(0, len(padded), rate):
                block = padded[blk_start:blk_start + rate]
                for i in range(rate // 8):
                    x, y = i % 5, i // 5
                    state[x][y] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
                _permute(state)
            out = bytearray()
            for i in range(4):
                x, y = i % 5, i // 5
                out += state[x][y].to_bytes(8, "little")
            return bytes(out[:32])

        _ROTC = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
                 [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
        _SHIF = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
                 [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]

        def _rotl(x, n):
            return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF

        def _permute(state):
            for rnd in range(24):
                C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
                D = [C[(x + 4) % 5] ^ _rotl(C[(x + 1) % 5], 1) for x in range(5)]
                for x in range(5):
                    for y in range(5):
                        state[x][y] ^= D[x]
                B = [[0] * 5 for _ in range(5)]
                for x in range(5):
                    for y in range(5):
                        B[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _ROTC[x][y])
                for x in range(5):
                    for y in range(5):
                        state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y] & 0xFFFFFFFFFFFFFFFF) & B[(x + 2) % 5][y])
                state[0][0] ^= _RC[rnd]
