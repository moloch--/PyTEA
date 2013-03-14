PyTEA
=====

A Python implementation of the [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm), this is NOT a secure cipher, do not use it for anything important - it's just a fun toy.  Can be used as a library, or via a cli.

TEA has a few weaknesses. Most notably, it suffers from equivalent keys—each key is equivalent to three others, which means that the effective key size is only 126 bits. As a result, TEA is especially bad as a cryptographic hash function. This weakness led to a method for hacking Microsoft's Xbox game console (where I first encountered it), where the cipher was used as a hash function. TEA is also susceptible to a related-key attack which requires 2^23 chosen plaintexts under a related-key pair, with 2^32 time complexity.

TODO
======
* Does not pad input data (all input data must be mod 4 in length)
* Does not currently implement CBC

CLI Usage
==========
```
usage: tea.py [-h] [--encrypt EPATH] [--decrypt DPATH] [--verbose]

Python implementation of the TEA cipher

optional arguments:
  -h, --help            show this help message and exit
  --encrypt EPATH, -e EPATH
                        encrypt a file
  --decrypt DPATH, -d DPATH
                        decrypt a file
  --verbose             display verbose output
```

Library Usage
==============
```
from tea import *

cipher_text = tea.encrypt('somedata', '128_bit_key_1234')
plaint_text = tea.decrypt(cipher_text, '128_bit_key_1234')
```


