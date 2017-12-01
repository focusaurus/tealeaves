# Notes on ssh keys

## OpenSSH

OpenSSH supports the following key types

- ed25519
  - private key is PEM plus openssh-key-v1
  - public key is SSLEAY format with ssh-ed25519 label
- rsa
  - private key is PEM plus ??
  - public key is SSLEAY format with ssh-rsa label
- ecdsa
  - private key is PEM plus openssh-key-v1
  - public key is SSLEAY format with ecdsa-sha2-nistp256 label
- dsa
  - private key is PEM plus ??
  - public key is SSLEAY format with ssh-dss label


## ed25519 private key file format (no passphrase)

```
# ASCII magic "openssh-key-v1" plus null byte
6f70656e7373682d6b65792d7631 00
00000004 int length = 4
6e6f6e65 string cipher = none
00000004 int length = 4
6e6f6e65 string kdfname = none
00000000 int length = 0
# zero-length kdfoptions placeholder here
00000001 int number of public keys = 1
00000033 int length first public key = 51 (4 + 11 + 4 + 32)
0000000b int length = 11
7373682d65643235353139 string key type = ssh-ed25519
00000020 int length = 32
# public key payload32 bytes
# probably encoding a point on the ed25519 curve
3cfe2afb025f46582e502b97f7dfa5a0
8dea09f87abfa8d5bfcaabf29fbb3695

00000090 int length = 144 size of remaining payload
# 8 + 4 + 11 + 4 + 32 + 4 + 64 + 4 + 10 + 3
a2224bbaa2224bba iv/salt? (Not sure about these 8 bytes)

# Here's a repeat of the public key (part of the private key pair)
0000000b int length = 11
7373682d656432353531 39 string key type = ssh-ed25519
00000020  int length = 32
# public key payload32 bytes
# probably encoding a point on the ed25519 curve
3cfe2afb025f46582e502b97f7dfa5a0
8dea09f87abfa8d5bfcaabf29fbb3695

00000040 int length = 64
# 64 bytes private key payload 1
02a1965d1a2684d50d29f2be0efd8e2f
ae3c5bb013d06f7818416333955271a5
3cfe2afb025f46582e502b97f7dfa5a0
8dea09f87abfa8d5bfcaabf29fbb3695

0000000a int length = 10
706c796f6e7340617669 private key payload 2
010203 padding 3 bytes incrementing integers
```

## ed25519 private key file format with passphrase


```
#ASCII magic "openssh-key-v1" plus null byte
6f70656e7373682d6b65792d7631 00
0000000a int length = 10
6165733235362d636263 string cipher = aes256-cbc
00000006 int length = 6
626372797074 string kdfname = bcrypt
00000018 int length = 24 (kdfoptions)
00000010 int length = 16
d08f6b8fd17593f246db4ac6c45a1193 salt/iv for bcrypt
00000010 int work factor = 16
00000001 int number of public keys = 1
00000033 int length = 51 public key 1 size (4 + 11 + 4 + 32)

# Public key 1
0000000b int length = 11
7373682d65643235353139 string key type = ssh-ed25519
00000020 int length = 32
# public key payload32 bytes
# probably encoding a point on the ed25519 curve
62837be86c63712896b8e0e7543e367c
3abd0c0b5ad3e764ea0e4f8ddd7d00ef

00000090 int length = 144 encryptedaes256-cbc output (16x9)
1e60c56ef30d0ff02e07b57bf1464507
6c32c86c88ecad545ca28424e4739aff
5895bebd6778e70b6c54b309b9fdb0c9
4102bf8cef5b97d3d75636967e67e4b9
c1ee72ae81074b0ce0f7e540e051d569
05da263af3e383342cc75b3145242abb
75257586a119c9d3673dfb7eabe46963
50904e7c7af3cd77f28bea10374e15bc
6536c2e1029438fdd3930beebbc5ac30
```

## References

- [RFC 4716](https://tools.ietf.org/html/rfc4716) supposedly the ssh public key file format, but my ssh-keygen on macOS 10.13 does not generate this format by default.
- PKCS8
- https://lionet.info/asn1c/basics.html
- https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
- https://github.com/golang/crypto/blob/master/bcrypt/bcrypt.go
- https://tools.ietf.org/html/rfc4253#section-6.6
- https://peterlyons.com/problog/2017/12/openssh-ed25519-private-key-file-format

## Stream of consciousness notes to organize later
- `brew install asn1c`
  - that gives you the `unber` CLI
- https://tools.ietf.org/html/rfc4648#section-3.1
- Nope: an ancient powerpc app: https://sites.google.com/site/aramperez/home/berviewer
- http://www.alvestrand.no/objectid/
- Download and save this https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.c
- Download and save this in /usr/local/bin https://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
- compile with `gcc dumpasn1.c -o dumpasn1`
  - `mv dumpasn1 /usr/local/bin`
- `grep -v '-' ./local/test_files/test-ssh-ed25519-1.privatekey | base64 -D > local/raw-der`
