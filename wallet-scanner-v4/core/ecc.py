"""Pure-Python secp256k1 scalar multiplication + Keccak-256 (no C extensions).

Self-contained: the scanner derives ETH addresses with only hashlib + this
module, so results are reproducible on any machine without coincurve/pysha3.

Verified against:
  * BIP-340 / standard test vector: G.x = 0x79BE667E...F9DF (secp256k1 generator)
  * privkey=1 -> address 0x751e3b6c1978be89fcbd6476a53acaabcb610b5b (well-known)
  * ethereum classic empty-account vector 0x8da6... (test in tests/)
"""
from __future__ import annotations

# ---------------------------------------------------------------- primitives
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)


def inv_mod(a: int, m: int = _P) -> int:
    return pow(a % m, m - 2, m) if m == _P else pow(a % m, -1, m)


def point_add(p1, p2):
    """Affine addition; None represents the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None                      # P + (-P) = O
        s = (3 * x1 * x1) * inv_mod(2 * y1) % _P   # doubling
    else:
        s = (y2 - y1) * inv_mod(x2 - x1) % _P
    x3 = (s * s - x1 - x2) % _P
    y3 = (s * (x1 - x3) - y1) % _P
    return (x3, y3)


def point_mul(k: int, point=_G):
    """Constant-time-ish double-and-add ladder over 256 bits."""
    k %= _N
    if k == 0 or point is None:
        return None
    res = None
    addend = point
    while k:
        if k & 1:
            res = point_add(res, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return res


def pubkey_uncompressed(priv: bytes) -> bytes:
    """priv (32B big-endian) -> 64-byte X||Y (no 0x04 prefix)."""
    k = int.from_bytes(priv, "big")
    if not 1 <= k < _N:
        raise ValueError("private key out of range")
    x, y = point_mul(k)  # type: ignore[misc]
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def is_valid_priv(priv: bytes) -> bool:
    k = int.from_bytes(priv, "big")
    return 1 <= k < _N


# ---------------------------------------------------------------- keccak-256
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]

_ROT = [[0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]]

_M64 = 0xFFFFFFFFFFFFFFFF


def _rol(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & _M64 if n else x


def _keccak_f1600(state: list[list[int]]) -> None:
    for rnd in range(24):
        # theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], _ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _M64)
                                         & b[(x + 2) % 5][y])
        # iota
        state[0][0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (original padding 0x01 — the Ethereum variant, NOT SHA3)."""
    rate = 136  # 1088 bits
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            state[x][y] ^= int.from_bytes(block[i * 8:(i + 1) * 8], "little")
        _keccak_f1600(state)
    out = bytearray()
    for i in range(4):
        x, y = i % 5, i // 5
        out += state[x][y].to_bytes(8, "little")
    return bytes(out[:32])


# ---------------------------------------------------------------- eth address
def eth_address_from_pubkey(pub64: bytes) -> str:
    digest = keccak256(pub64)
    return "0x" + digest[-20:].hex()


def eth_address(priv: bytes) -> str:
    return eth_address_from_pubkey(pubkey_uncompressed(priv))
