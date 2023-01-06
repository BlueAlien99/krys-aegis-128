import json
import os

from aegis_128 import encrypt, decrypt


def path_from_here(path: str) -> str:
    return os.path.join(os.path.dirname(__file__), path)


def print_test_debug(label: str, expected: str, received: str) -> None:
    print(label)
    print(f"Expected: {expected}")
    print(f"Received: {received}")


def main():
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


if __name__ == '__main__':
    main()
