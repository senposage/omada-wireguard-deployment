from __future__ import annotations

import base64
import secrets

_P = 2**255 - 19
_A24 = 121665


def _x25519(scalar_bytes: bytes, u_bytes: bytes = bytes([9]) + bytes(31)) -> bytes:
    if len(scalar_bytes) != 32 or len(u_bytes) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    scalar = bytearray(scalar_bytes)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    k = int.from_bytes(scalar, "little")
    x1 = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for bit_index in range(254, -1, -1):
        bit = (k >> bit_index) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * ((da - cb) ** 2) % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, "little")


def generate_keypair() -> tuple[str, str]:
    private = bytearray(secrets.token_bytes(32))
    private[0] &= 248
    private[31] &= 127
    private[31] |= 64
    public = _x25519(bytes(private))
    return base64.b64encode(bytes(private)).decode("ascii"), base64.b64encode(public).decode("ascii")

