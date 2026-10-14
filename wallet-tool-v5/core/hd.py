"""HD key derivation + legacy wallet paths + multi-coin addresses (V5).

Pure-python (hashlib + core.ecc) so it runs anywhere — no compiled deps.

Covered:
  * BIP-32 master from seed (HMAC-SHA512 "Bitcoin seed") and CKDpriv, incl.
    hardened steps — used for the HISTORICAL (pre-BIP44) paths:
        Bitcoin Core old      m/0'/0/0
        Electrum v1           m/0'/0/0 , m/0'/i/0 style derivations
        Blockchain.info       m/44'/0'/0'   (their account-0 root)
        MultiBit              m/0'/0'/0'
        BitcoinJS 'shared'    m/0'/0'
    plus standard BIP-44/49/84 first receiving addresses per coin.
  * Direct private-key wallets (the Randstorm era mostly produced raw
    secp256k1 keys, NOT mnemonics): privkey -> address on every chain.
  * Compressed AND uncompressed public keys.
  * Address formats:
        BTC Legacy P2PKH / P2SH-P2WPKH / Native SegWit bech32 (bc1…)
        LTC  legacy 'L' / segwit 'ltc1'
        DOGE 'D'/'A' (P2PKH/P2SH version bytes)
        ZEC  transparent t-address (t4 + hash160, base58check w/ ZCASH T-prefix)
  * WIF export (compressed & uncompressed) per chain version byte.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import ecc

SECP_N = ecc.CURVE_ORDER


# --------------------------------------------------------------------- BIP32
def _hmac512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def bip32_master(seed: bytes) -> Tuple[bytes, bytes]:
    I = _hmac512(b"Bitcoin seed", seed)
    return I[:32], I[32:]                       # (priv, chain code)


def ckd_priv(k: bytes, c: bytes, index: int) -> Tuple[bytes, bytes]:
    """One BIP-32 child step; index >= 2^31 => hardened."""
    if index >= 0x80000000:
        data = b"\x00" + k + index.to_bytes(4, "big")
    else:
        pub = ecc.compressed_pub(k)
        data = pub + index.to_bytes(4, "big")
    I = _hmac512(c, data)
    il, ir = I[:32], I[32:]
    ki = (int.from_bytes(il, "big") + int.from_bytes(k, "big")) % SECP_N
    if ki == 0 or int.from_bytes(il, "big") >= SECP_N:      # invalid, rare
        raise ValueError("invalid child (retry next)")
    return ki.to_bytes(32, "big"), ir


def parse_path(path: str) -> List[int]:
    parts = path.strip().split("/")
    assert parts[0] in ("m", "M"), path
    out = []
    for p in parts[1:]:
        hard = p.endswith("'") or p.endswith("h")
        idx = int(p.rstrip("'h"))
        out.append(idx + 0x80000000 if hard else idx)
    return out


def derive_priv(seed: bytes, path: str) -> bytes:
    k, c = bip32_master(seed)
    for idx in parse_path(path):
        k, c = ckd_priv(k, c, idx)
    return k


# -------------------------------------------------------------- chain params
@dataclass(frozen=True)
class Chain:
    name: str
    p2pkh_version: int            # base58check version byte
    p2sh_version: int
    bech32_hrp: Optional[str]     # None -> no segwit family
    wif_version: int


CHAINS: Dict[str, Chain] = {
    "btc":  Chain("BTC",  0x00, 0x05, "bc",  0x80),
    "ltc":  Chain("LTC",  0x30, 0x32, "ltc", 0xB0),
    "doge": Chain("DOGE", 0x1E, 0x16, None,  0x9E),
    "zec":  Chain("ZEC",  0x1CAB, 0x1C7D, None, 0x80),   # t1pub/t1addr prefixes
}

# Historical derivation paths (label -> path template)
LEGACY_PATHS: Dict[str, Dict[str, str]] = {
    "btc": {
        "bitcoincore_old": "m/0'/0/0",
        "electrum_v1":     "m/0'/0/0",
        "blockchain_info": "m/44'/0'/0'",
        "multibit":        "m/0'/0'/0'",
        "bip44":           "m/44'/0'/0'/0/0",
        "bip49":           "m/49'/0'/0'/0/0",
        "bip84":           "m/84'/0'/0'/0/0",
    },
    "ltc": {"bip44": "m/44'/2'/0'/0/0", "bip49": "m/49'/2'/0'/0/0",
            "bip84": "m/84'/2'/0'/0/0", "bitcoincore_old": "m/0'/0/0"},
    "doge": {"bip44": "m/44'/3'/0'/0/0", "bitcoincore_old": "m/0'/0/0"},
    "zec": {"bip32_legacy": "m/0'/0/0"},
}


# ---------------------------------------------------------------- addresses
def _b58check(payload: bytes) -> str:
    return ecc.b58check_encode(payload)


def p2pkh_address(pub: bytes, chain: Chain) -> str:
    h = ecc.hash160(pub)
    if chain.name == "ZEC":                      # transparent v2: 0x1c 0xab
        return _b58check(chain.p2pkh_version.to_bytes(2, "big") + h)
    return _b58check(bytes([chain.p2pkh_version]) + h)


def p2sh_address(script: bytes, chain: Chain) -> str:
    h = ecc.hash160(script)
    ver = chain.p2sh_version
    if chain.name == "ZEC":
        return _b58check(ver.to_bytes(2, "big") + h)
    return _b58check(bytes([ver]) + h)


def p2wpkh_segwit_address(pub: bytes, hrp: str, witver: int = 0) -> str:
    """Native segwit bech32 (BIP-173) — pure python encoder."""
    prog = ecc.hash160(pub)
    data = [witver] + _convertbits(prog, 8, 5, True)
    return _bech32_encode(hrp, data)


_BECH_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values):
    GEN = [0x3B6A57B2, 0x2606DCED, 0x1DE1A9F7, 0x5E659CE7, 0x1FA7F2B7]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data + [0] * 6
    polymod = _bech32_polymod(values) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _bech32_encode(hrp, data):
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH_CHARSET[d] for d in combined)


def _convertbits(data: bytes, frm: int, to: int, pad: bool):
    acc, bits, ret = 0, 0, []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    return ret


def p2sh_p2wpkh_address(pub: bytes, chain: Chain) -> Optional[str]:
    """BIP-49 nesting: P2SH of 0x0014{hash160(pub)} witness script."""
    if chain.p2sh_version is None:
        return None
    inner = b"\x00\x14" + ecc.hash160(pub)
    return p2sh_address(inner, chain)


def wif(priv: bytes, chain: Chain, compressed: bool = True) -> str:
    payload = bytes([chain.wif_version]) + priv + (b"\x01" if compressed else b"")
    return _b58check(payload)


# ------------------------------------------------------------------ wallet
@dataclass
class AddressSet:
    """All observable addresses generated by one private key."""
    priv_hex: str
    compressed: bool
    uncompressed: bool
    btc_legacy: str
    btc_uncompressed: str
    btc_p2sh_segwit: Optional[str]
    btc_native_segwit: Optional[str]
    ltc_legacy: str
    ltc_native_segwit: Optional[str]
    doge_legacy: str
    zec_transparent: str
    wif_compressed: str
    wif_uncompressed: str

    def all_addresses(self) -> List[Tuple[str, str]]:
        """[(chain_tag, address), …] — what the balance checker must probe."""
        out = [("btc", self.btc_legacy), ("btc-uncomp", self.btc_uncompressed),
               ("ltc", self.ltc_legacy), ("doge", self.doge_legacy),
               ("zec", self.zec_transparent),
               ("btc-p2sh", self.btc_p2sh_segwit),
               ("btc-bech32", self.btc_native_segwit),
               ("ltc-bech32", self.ltc_native_segwit)]
        return [(t, a) for t, a in out if a]


def address_set_from_priv(priv: bytes) -> AddressSet:
    if not ecc.is_valid_priv(priv):
        raise ValueError("private key out of range")
    pc = ecc.compressed_pub(priv)                 # 33 bytes
    pu = ecc.pubkey_uncompressed(priv)            # 65 bytes 0x04||X||Y
    btc, ltc, doge, zec = (CHAINS[c] for c in ("btc", "ltc", "doge", "zec"))
    return AddressSet(
        priv_hex=priv.hex(),
        compressed=True, uncompressed=True,
        btc_legacy=p2pkh_address(pc, btc),
        btc_uncompressed=p2pkh_address(pu, btc),
        btc_p2sh_segwit=p2sh_p2wpkh_address(pc, btc),
        btc_native_segwit=p2wpkh_segwit_address(pc, "bc"),
        ltc_legacy=p2pkh_address(pc, ltc),
        ltc_native_segwit=p2wpkh_segwit_address(pc, "ltc"),
        doge_legacy=p2pkh_address(pc, doge),
        zec_transparent=p2pkh_address(pc, zec),
        wif_compressed=wif(priv, btc, True),
        wif_uncompressed=wif(priv, btc, False),
    )


def address_set_from_mnemonic(mnemonic: str, passphrase: str = "",
                              path: str = "m/44'/0'/0'/0/0") -> AddressSet:
    import bip39
    seed = bip39.mnemonic_to_seed(mnemonic, passphrase)
    return address_set_from_priv(derive_priv(seed, path))
