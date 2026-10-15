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

# Jacobian projective coordinates (X : Y : Z), affine point = (X/Z^2, Y/Z^3).
# Chosen because affine add/double needs a full modular INVERSION per step
# (pow(a, p-2, p)); the projective ladder inverts only ONCE at the end —
# measured ~10x faster for pubkey derivation, which dominates scan cost.


def inv_mod(a: int, m: int = _P) -> int:
    return pow(a % m, -1, m)


def _jdouble(P_):
    """Jacobian doubling, standard formula for a = 0 (secp256k1).

    Reference (Hal Finney / djb-style derivation, affine slope λ = 3X²/2YZ... ):
        YY = Y²;  S = 4·X·YY
        M  = 3·X² + a·Z⁴   →   3·X²          (a = 0)
        X' = M² − 2S
        Y' = M·(S − X') − 8·YY²
        Z' = 2·Y·Z
    NOTE: this is the NON-halves variant where M carries no Z² factor because
    we work with (X,Y,Z) such that affine = (X/Z², Y/Z³); consistency was
    verified against an independent affine oracle (tests/test_correctness.py T5).
    An earlier draft mixed s = 4·X²·Y² or m = 3·X⁴ variants and produced wrong
    points for every k ≥ 2 — caught by conformance testing, never shipped.
    """
    X, Y, Z = P_
    if Y == 0 or Z == 0:
        return (0, 0, 0)                      # point at infinity
    yy = (Y * Y) % _P
    yyyy = (yy * yy) % _P
    s = (4 * X * yy) % _P
    m = (3 * X * X) % _P                      # a = 0
    x2 = (m * m - 2 * s) % _P
    y2 = (m * (s - x2) - 8 * yyyy) % _P
    z2 = (2 * Y * Z) % _P
    return (x2, y2, z2)


def _jadd(P_, Q_):
    """Jacobian + Jacobian, general case (a = 0).

    The classic hkc/`i,j,v` formulation is ASYMMETRIC: it assumes Z2 == 1.
    Used inside the double-and-add ladder with a projective `addend` (Z2 != 1)
    it silently returned wrong points for every k with ≥2 set bits — caught by
    the independent affine oracle in tests/test_correctness.py (T5). The fully
    symmetric version below is correct for arbitrary Z1, Z2.
    """
    X1, Y1, Z1 = P_
    X2, Y2, Z2 = Q_
    if Z1 == 0:
        return Q_
    if Z2 == 0:
        return P_
    z1z1 = (Z1 * Z1) % _P
    z2z2 = (Z2 * Z2) % _P
    u1 = (X1 * z2z2) % _P
    u2 = (X2 * z1z1) % _P
    s1 = (Y1 * Z2 % _P * z2z2) % _P
    s2 = (Y2 * Z1 % _P * z1z1) % _P
    h = (u2 - u1) % _P
    r = (s2 - s1) % _P
    if h == 0:
        return _jdouble(Q_) if r == 0 else (0, 0, 0)   # equal / inverse points
    hh = (h * h) % _P
    hhh = (h * hh) % _P
    x3 = (r * r - hhh - 2 * u1 * hh) % _P
    y3 = (r * (u1 * hh - x3) - s1 * hhh) % _P
    z3 = (Z1 * Z2 % _P * h) % _P
    return (x3, y3, z3)


def point_mul(k: int, point=_G):
    """Jacobian double-and-add ladder over 256 bits; returns affine (x, y)."""
    k %= _N
    if k == 0 or point is None:
        return None
    px, py = point
    res = (0, 0, 0)                           # infinity
    addend = (px, py, 1)                      # Jacobian with Z=1
    while k:
        if k & 1:
            res = _jadd(res, addend)
        addend = _jdouble(addend)
        k >>= 1
    z = res[2]
    zi = inv_mod(z)
    zi2 = (zi * zi) % _P
    return ((res[0] * zi2) % _P, (res[1] * zi * zi2) % _P)


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
