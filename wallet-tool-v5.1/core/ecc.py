"""Pure-Python secp256k1 + Keccak-256 + RIPEMD-160 helpers (no C extensions).

Self-contained: address derivation for every supported chain runs with only
hashlib + this module, so results are reproducible on any machine (including
Windows hosts without compiled dependencies like coincurve/pysha3).

Verified against standard vectors (see tests/test_v5.py):
  * privkey=1 -> ETH 0x751e3b6c1978be89fcbd6476a53acaabcb610b5b
  * privkey=1 -> BTC Legacy P2PKH 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
  * BIP-340 generator x = 0x79BE667E...F9DF
"""
from __future__ import annotations

import hashlib

# ---------------------------------------------------------------- primitives
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)


def inv_mod(a: int, m: int = _P) -> int:
    return pow(a % m, -1, m)


def _jdouble(P_):
    """Jacobian doubling for y² = x³ + 7 (a = 0), d3b8 (Hankerson Alg. 3.21).

    BUGFIX (v5.1): the previous line was
        m = 3X² + 7·Z⁴
    which is the generic a≠0 formula with the curve coefficient *substituted*
    for `a`. For secp256k1, a = 0: the slope numerator is exactly M = 3X² and
    the Z⁴ term only enters through the homogeneous invariant
    Y²Z⁴ = X³ + 7Z⁶ — never as "+7·Z⁴" in M. The wrong M produced off-curve
    points for every multiplication containing a doubling step (2G, m/0', …).
    """
    X, Y, Z = P_
    if Y == 0 or Z == 0:
        return (0, 0, 0)                      # point at infinity
    yy = (Y * Y) % _P
    yyyy = (yy * yy) % _P
    s = (4 * X * yy) % _P
    m = (3 * X * X) % _P                       # a = 0 -> M = 3X²  (no 7Z⁴!)
    x2 = (m * m - 2 * s) % _P
    y2 = (m * (s - x2) - 8 * yyyy) % _P
    z2 = (2 * Y * Z) % _P
    return (x2, y2, z2)


def _jadd(P_, Q_):
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
        return _jdouble(Q_) if r == 0 else (0, 0, 0)
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
    addend = (px, py, 1)
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


def compressed_pub(priv: bytes) -> bytes:
    k = int.from_bytes(priv, "big")
    x, y = point_mul(k)  # type: ignore[misc]
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def is_valid_priv(priv: bytes) -> bool:
    k = int.from_bytes(priv, "big")
    return 1 <= k < _N


CURVE_ORDER = _N

# ---------------------------------------------------------------- keccak-256
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
       0x0000000000000088, 0x0000000080008089, 0x000000008000000A,
       0x800000008000808B, 0x800000008000000B, 0x8000000000008089,
       0x8000000000008003, 0x8000000080000002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000080008080, 0x0000000000008008, 0x8000000080000001]

_ROT = [[0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]]

_M64 = 0xFFFFFFFFFFFFFFFF


def _rol(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & _M64 if n else x


def _keccak_f1600(state):
    """Keccak-f[1600]; state is a 5x5 list-of-lists indexed [x][y]."""
    for rnd in range(24):
        # theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
             for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            dx = d[x]
            for y in range(5):
                state[x][y] ^= dx
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


# ---------------------------------------------------------------- hash160
def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 via hashlib (OpenSSL) with a pure-python fallback flag."""
    try:
        return hashlib.new("ripemd160", data).digest()
    except Exception:
        return _ripemd160_pure(data)


def hash160(data: bytes) -> bytes:
    """Bitcoin HASH160 = RIPEMD160(SHA256(data))."""
    return ripemd160(hashlib.sha256(data).digest())


# ---------------------------------------------------------------- base58check
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        num = num * 58 + _B58_ALPHABET.index(ch)
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def b58check_encode(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


def b58check_decode(addr: str) -> bytes:
    raw = b58decode(addr)
    payload, chk = raw[:-4], raw[-4:]
    expect = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if chk != expect:
        raise ValueError("bad base58check checksum")
    return payload


def to_cashaddr(data: bytes, prefix: str) -> str:
    """CashAddr encoding (Zcash transparent t-addresses)."""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def polymod(values):
        GEN = [0x98f2bc8e61, 0x7fb064d74e, 0x7eea7e7fe0, 0xbf2f9fcf04,
               0xae7e9f500a, 0x9e467b2de8, 0x8361eae58c, 0x7fa133c7ae,
               0x7b9ab4561e, 0xa0df35aec]
        c = 1
        for value in values:
            c0 = c >> 35
            c = ((c & 0x7ffffffff) << 5) ^ value
            if c0 & 0x01:
                c ^= GEN[0]
            if c0 & 0x02:
                c ^= GEN[1]
            if c0 & 0x04:
                c ^= GEN[2]
            if c0 & 0x08:
                c ^= GEN[3]
            if c0 & 0x10:
                c ^= GEN[4]
            if c0 & 0x20:
                c ^= GEN[5]
            if c0 & 0x40:
                c ^= GEN[6]
            if c0 & 0x80:
                c ^= GEN[7]
            if c0 & 0x100:
                c ^= GEN[8]
            if c0 & 0x200:
                c ^= GEN[9]
        return c ^ 1

    def hrp_expand(hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    def convertbits(buf, frombits, tobits, pad=True):
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for value in buf:
            acc = (acc << frombits) | value
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)
        return ret

    payload = convertbits(data, 8, 5)
    values = hrp_expand(prefix) + [0] + payload
    mod = polymod(values)
    checksum = [(mod >> 5 * (7 - i)) & 31 for i in range(8)]
    return prefix + ":" + "".join(CHARSET[d] for d in payload + checksum)


# ---------------------------------------------------------------- eth address
def eth_address_from_pubkey(pub64: bytes) -> str:
    digest = keccak256(pub64)
    return "0x" + digest[-20:].hex()


def eth_address(priv: bytes) -> str:
    return eth_address_from_pubkey(pubkey_uncompressed(priv))


# ---------------------------------------------------------------- ripemd fallback
_RL = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
       [14, 12, 10, 8, 6, 4, 2, 0, 9, 7, 5, 3, 1, 15, 13, 11],
       [19, 5, 11, 17, 3, 9, 15, 1, 7, 13, 19, 5, 11, 17, 3, 11],
       [17, 0, 11, 7, 16, 2, 12, 6, 15, 10, 3, 14, 8, 12, 4, 9],
       [13, 8, 15, 10, 6, 0, 11, 14, 3, 5, 12, 1, 7, 9, 11, 2]]
_RR = [[15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
       [15, 5, 9, 11, 2, 8, 12, 0, 4, 13, 6, 1, 10, 14, 7, 3],
       [9, 13, 5, 1, 8, 11, 3, 15, 0, 7, 12, 2, 4, 10, 14, 6],
       [15, 7, 1, 9, 11, 14, 2, 8, 13, 6, 4, 0, 10, 12, 3, 5],
       [2, 11, 7, 15, 13, 14, 8, 3, 0, 6, 1, 12, 4, 10, 9, 5]]
_SL = [[11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
       [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
       [7, 14, 9, 11, 13, 6, 15, 4, 0, 5, 9, 12, 2, 10, 14, 12],
       [6, 13, 2, 13, 11, 5, 4, 11, 13, 15, 5, 6, 9, 12, 8, 11],
       [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5]]
_SR = [[8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
       [9, 13, 15, 7, 12, 8, 7, 11, 7, 7, 12, 7, 6, 15, 13, 11],
       [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
       [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
       [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]]


def _ripemd160_pure(msg: bytes) -> bytes:
    """RIPEMD-160 reference implementation (used when OpenSSL drops the algo)."""
    M = 0xFFFFFFFF

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & M if n else x

    def f(j, x, y, z):
        if j < 16:   return x ^ y ^ z
        if j < 32:   return (x & y) | (~x & z)
        if j < 48:   return (x | ~y) ^ z
        if j < 64:   return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    KR = [0x50A28BE6, 0x5C4DD124, 0x6D703038, 0x7470AD86, 0x00000000]
    h0, h1, h2, h3, h4 = (0x67452301, 0xEFCDAB89, 0x98BADCFE,
                          0x10325476, 0xC3D2E1F0)
    padded = bytearray(msg) + b"\x80"
    while len(padded) % 64 != 56:
        padded.append(0)
    padded += (len(msg) * 8).to_bytes(8, "little")
    for off in range(0, len(padded), 64):
        X = [int.from_bytes(padded[off + 4 * i: off + 4 * i + 4], "little")
             for i in range(16)]
        al, ar = [h0, h1, h2, h3, h4], [h0, h1, h2, h3, h4]
        for j in range(80):
            rnd = j // 16
            idx = j % 16
            t = (al[0] + f(j, al[1], al[2], al[3]) + X[_RL[rnd][idx]] + KL[rnd]) & M
            t = (rol(t, _SL[rnd][idx]) + al[4]) & M
            al = [t, al[4], rol(al[1], 10), al[2], al[3]]
            t = (ar[0] + f(79 - j, ar[1], ar[2], ar[3]) + X[_RR[rnd][idx]] + KR[rnd]) & M
            t = (rol(t, _SR[rnd][idx]) + ar[4]) & M
            ar = [t, ar[4], rol(ar[1], 10), ar[2], ar[3]]
        t = (h1 + al[2] + ar[3]) & M
        h0, h1, h2, h3, h4 = (t, (h2 + al[3] + ar[4]) & M,
                              (h3 + al[4] + ar[0]) & M,
                              (h4 + al[0] + ar[1]) & M,
                              (h0 + al[1] + ar[2]) & M)
    return b"".join(x.to_bytes(4, "little") for x in (h0, h1, h2, h3, h4))
