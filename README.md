# \[KRYS\] AEGIS-128

```
$ python ./src -m e --key my_secret_key_12 --iv my_secret_vector --ad xd1337 --text "this is super secret message"
{"ct": "4e6f8ebe5e211283aab686a2e6365f21353058c795556c680c6679e4", "tag": "b495d121a81e44b77f44c2954fa2ff1a"}

$ python ./src -m d --key my_secret_key_12 --iv my_secret_vector --ad xd1337 --text 4e6f8ebe5e211283aab686a2e6365f21353058c795556c680c6679e4 --tag b495d121a81e44b77f44c2954fa2ff1a
this is super secret message
```

**Packages**

* pwntools --- `xor`
* numpy --- `transpose`


**Test data**

https://github.com/Yawning/aegis/blob/master/testdata/test-vectors.json


**Working AES (just in case)**

https://github.com/x13a/py-aegis/blob/main/aegis/aes.py

```py
def aes_round(state, key):
    x = Block.from_bytes(state).encrypt(Block.from_bytes(key)).to_bytes()

    return x
```
