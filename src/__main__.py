import json
import os

from aegis_128 import encrypt


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

        try:
            assert e_ct == ct
            assert e_tag == tag
        except AssertionError as err:
            print_test_debug('ciphertext', e_ct, ct)
            print_test_debug('tag', e_tag, tag)
            raise err


if __name__ == '__main__':
    main()
