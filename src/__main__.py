import argparse
import json
import os

from aegis_128 import encrypt, decrypt


def path_from_here(path: str) -> str:
    return os.path.join(os.path.dirname(__file__), path)


def print_test_debug(label: str, expected: str, received: str) -> None:
    print(label)
    print(f"Expected: {expected}")
    print(f"Received: {received}")


def run_tests():
    with open(path_from_here('../test-vectors.json')) as fp:
        vectors = json.load(fp)

    for i, v in enumerate(vectors):
        print(f'Running test #{i}...')

        k = v['k']
        iv = v['iv']
        ad = v.get('ad', '')
        pt = v.get('pt', '')
        e_ct = v.get('ct', '')
        e_tag = v['tag']

        ct, tag = encrypt(k, iv, ad, pt)
        d_pt = decrypt(k, iv, ad, ct, tag)

        try:
            assert e_ct == ct
            assert e_tag == tag
            assert pt == d_pt
        except AssertionError as err:
            print_test_debug('ciphertext', e_ct, ct)
            print_test_debug('tag', e_tag, tag)
            print_test_debug('decrypted pt', pt, d_pt)
            raise err

    print(f'All {len(vectors)} tests passed!')


def parse_arg(val):
    return (val or '').encode("utf-8").hex()


def run_encrypt(args):
    ct, tag = encrypt(*map(lambda x: parse_arg(vars(args)[x]), ['key', 'iv', 'ad', 'text']))
    print(json.dumps({'ct': ct, 'tag': tag}))


def run_decrypt(args):
    pt = decrypt(*map(lambda x: parse_arg(vars(args)[x]), ['key', 'iv', 'ad']),
                 *map(lambda x: vars(args)[x] or '', ['text', 'tag']))
    print(bytes.fromhex(pt).decode())


def main():
    parser = argparse.ArgumentParser(description='Test and play with AEGIS-128')
    parser.add_argument('-m', '--mode', choices=['t', 'e', 'd'], required=True, help='test, encrypt or decrypt')
    parser.add_argument('--key', help='key')
    parser.add_argument('--iv', help='initializing vector')
    parser.add_argument('--ad', help='associated data')
    parser.add_argument('--text', help='plaintext or ciphertext')
    parser.add_argument('--tag', help='verification tag')

    args = parser.parse_args()

    mode = args.mode
    if mode == 't':
        return run_tests()
    if mode == 'e':
        return run_encrypt(args)
    if mode == 'd':
        return run_decrypt(args)
    return parser.print_help()


if __name__ == '__main__':
    main()
