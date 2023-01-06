# \[KRYS\] AEGIS-128


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
