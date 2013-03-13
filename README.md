PyTEA
=====

A Python implementation of the [Tiny Encryption Algorithm](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm)
This is NOT a secure cipher, do not use it for anything important - it's just a fun toy.

TEA has a few weaknesses. Most notably, it suffers from equivalent keys—each key is equivalent to three others, which means that the effective key size is only 126 bits. As a result, TEA is especially bad as a cryptographic hash function. This weakness led to a method for hacking Microsoft's Xbox game console (where I first encountered it), where the cipher was used as a hash function. TEA is also susceptible to a related-key attack which requires 2^23 chosen plaintexts under a related-key pair, with 2^32 time complexity.
