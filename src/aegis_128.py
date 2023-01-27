from pwn import xor

from aes.aes import aes_round

BLOCK_SIZE = 16


def _split_into_blocks(b: bytes, size: int) -> list[bytes]:
    return [b[i:i + size] for i in range(0, len(b), size)]


def _b_and(a: bytes, b: bytes) -> bytes:
    return bytes(map(lambda _a, _b: _a & _b, a, b))


def _state_update_128(s: bytes, m: bytes) -> bytes:
    s = _split_into_blocks(s, BLOCK_SIZE)

    s_next = \
        aes_round(s[4], xor(s[0], m)) + \
        aes_round(s[0], s[1]) + \
        aes_round(s[1], s[2]) + \
        aes_round(s[2], s[3]) + \
        aes_round(s[3], s[4])

    return s_next


def _initialize(k: bytes, iv: bytes) -> bytes:
    const_0 = bytes.fromhex('000101020305080d1522375990e97962')
    const_1 = bytes.fromhex('db3d18556dc22ff12011314273b528dd')

    s = xor(k, iv) + const_1 + const_0 + xor(k, const_0) + xor(k, const_1)

    for i in range(-10, 0):
        m = k if i % 2 == 0 else xor(k, iv)
        s = _state_update_128(s, m)

    return s


def _process_ad(s: bytes, ad: bytes) -> bytes:
    if len(ad) == 0:
        return s

    ad = _split_into_blocks(ad, BLOCK_SIZE)
    ad[-1] = ad[-1].ljust(BLOCK_SIZE, b'\x00')

    for i in range(0, len(ad)):
        s = _state_update_128(s, ad[i])

    return s


def _encrypt_msg(s: bytes, p: bytes) -> (bytes, bytes):
    if len(p) == 0:
        return s, b''

    p = _split_into_blocks(p, BLOCK_SIZE)
    c = b''

    for i in range(0, len(p)):
        sb = _split_into_blocks(s, BLOCK_SIZE)

        c += xor(p[i], sb[1], sb[4], _b_and(sb[2], sb[3]))[:len(p[i])]

        if i == len(p) - 1:
            p[i] = p[i].ljust(BLOCK_SIZE, b'\x00')

        s = _state_update_128(s, p[i])

    return s, c


def _decrypt_msg(s: bytes, c: bytes) -> (bytes, bytes):
    if len(c) == 0:
        return s, b''

    c = _split_into_blocks(c, BLOCK_SIZE)
    p = b''

    for i in range(0, len(c)):
        sb = _split_into_blocks(s, BLOCK_SIZE)

        p_i = xor(c[i], sb[1], sb[4], _b_and(sb[2], sb[3]))[:len(c[i])]

        p += p_i

        if i == len(c) - 1:
            p_i = p_i.ljust(BLOCK_SIZE, b'\x00')

        s = _state_update_128(s, p_i)

    return s, p


def _finalize(s: bytes, ad: bytes, p: bytes) -> bytes:
    sb = _split_into_blocks(s, BLOCK_SIZE)

    adlen = (len(ad) * 8).to_bytes(8, byteorder='little')
    msglen = (len(p) * 8).to_bytes(8, byteorder='little')

    tmp = xor(sb[3], adlen + msglen)

    for i in range(0, 7):
        s = _state_update_128(s, tmp)

    full_tag = xor(*_split_into_blocks(s, BLOCK_SIZE))
    tag = full_tag[:BLOCK_SIZE]

    return tag


def check_params(params):
    for key in params:
        if len(params[key]) != BLOCK_SIZE:
            raise ValueError(f'{key} must have a length of {BLOCK_SIZE} bytes')


def encrypt(k: str, iv: str, ad: str, p: str) -> (str, str):
    k = bytes.fromhex(k)
    iv = bytes.fromhex(iv)
    ad = bytes.fromhex(ad)
    p = bytes.fromhex(p)

    check_params({'key': k, 'iv': iv})

    s = _initialize(k, iv)
    s = _process_ad(s, ad)
    s, c = _encrypt_msg(s, p)
    t = _finalize(s, ad, p)

    return c.hex(), t.hex()


def decrypt(k: str, iv: str, ad: str, c: str, tag: str) -> str:
    k = bytes.fromhex(k)
    iv = bytes.fromhex(iv)
    ad = bytes.fromhex(ad)
    c = bytes.fromhex(c)
    tag = bytes.fromhex(tag)

    check_params({'key': k, 'iv': iv})

    s = _initialize(k, iv)
    s = _process_ad(s, ad)
    s, p = _decrypt_msg(s, c)
    t = _finalize(s, ad, p)

    if t != tag:
        return ''

    return p.hex()
