import numpy as np
from pwn import xor

from aes._s_box import s_box


# Utils


def flatten(source):
    return [item for sublist in source for item in sublist]


def group_list(source, step):
    return [source[i:i + step] for i in range(0, len(source), step)]


def shift_list(source, n):
    return source[n:] + source[:n]


def transpose(matrix):
    return np.transpose(np.array(matrix)).tolist()


# Crypto


def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i + 4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return b''.join([i.to_bytes(1, 'big') for i in flatten(matrix)])


def transpose_key(key):
    return transpose([group_list(col, 1) for col in key])


def add_round_key(key, x):
    return bytes2matrix(xor(transpose_key(key), x))


def sub_bytes(matrix):
    return [[s_box[byte] for byte in row] for row in matrix]


def shift_rows(s):
    return [s[0], shift_list(s[1], 1), shift_list(s[2], 2), shift_list(s[3], 3)]


def xtime(a):
    # learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    return [
        a[0] ^ t ^ xtime(a[0] ^ a[1]),
        a[1] ^ t ^ xtime(a[1] ^ a[2]),
        a[2] ^ t ^ xtime(a[2] ^ a[3]),
        a[3] ^ t ^ xtime(a[3] ^ a[0])
    ]


def mix_columns(s):
    return transpose([mix_single_column(col) for col in transpose(s)])
