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


## References

- [RFC 4716](https://tools.ietf.org/html/rfc4716) supposedly the ssh public key file format, but my ssh-keygen on macOS 10.13 does not generate this format by default.
- PKCS8
- https://lionet.info/asn1c/basics.html
- https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
- https://github.com/golang/crypto/blob/master/bcrypt/bcrypt.go
- https://tools.ietf.org/html/rfc4253#section-6.6

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
- https://tools.ietf.org/html/rfc4253#section-6.6
- byteorder crate
```
0000000 6f 70 65 6e 73 73 68 2d 6b 65 79 2d 76 31 00 00
0000010 00 00 04 6e 6f 6e 65 00 00 00 04 6e 6f 6e 65 00

14 bytes ascii "openssh-key-v1"
1 null byte
4 byte length prefix, 6 bytes string for 3 fields
4 byte number of keys
4 byte key string length
N bytes key1...

	byte[]	AUTH_MAGIC
	string	ciphername
	string	kdfname
	string	kdfoptions
	int	number of keys N
	string	publickey1
	string	publickey2
- by_ref


```
. openssh-key-v1                          . null byte
6f 70 65 6e 73 73 68 2d 6b 65 79 2d 76 31 00
00 00 00 04 int length
6e 6f 6e 65 "none" cipher name
00 00 00 04 int length
6e 6f 6e 65 "none" cipher name
00 00 00 00 int length
kdfoptions is zero
00 00 00 01 int number of keys
00 00 00 33 00 00 00 0b 73
0000030 73 68 2d 65 64 32 35 35 31 39 00 00 00 20 36 59
0000040 2f b1 61 50 02 b9 39 b2 c5 00 c1 c8 57 c3 e6 d4
0000050 5f 64 59 f1 ab 4d e5 d3 8f ad 60 fc 44 c6 00 00
0000060 00 a8 fe 2f 86 b3 fe 2f 86 b3 00 00 00 0b 73 73
0000070 68 2d 65 64 32 35 35 31 39 00 00 00 20 36 59 2f
0000080 b1 61 50 02 b9 39 b2 c5 00 c1 c8 57 c3 e6 d4 5f
0000090 64 59 f1 ab 4d e5 d3 8f ad 60 fc 44 c6 00 00 00
00000a0 40 48 86 03 4e 97 33 e7 1f 77 00 ba 5e 52 d1 54
00000b0 ab 9e 2a dd 56 be 93 54 32 f6 81 50 d7 20 4b ba
00000c0 15 36 59 2f b1 61 50 02 b9 39 b2 c5 00 c1 c8 57
00000d0 c3 e6 d4 5f 64 59 f1 ab 4d e5 d3 8f ad 60 fc 44
00000e0 c6 00 00 00 1f 54 65 61 6c 65 76 65 73 20 74 65
00000f0 73 74 20 45 44 32 35 35 31 39 20 53 53 48 20 4b
0000100 65 79 20 31 01 02 03 04 05 06                  


```
dump-ssh-private-key ssh-01-ed25519-private-key.pem
magic plus null byte
6f 70 65 6e 73 73 68 2d 6b 65 79 2d 76 31 00
00 00 00 04 int length = 4
6e 6f 6e 65 string cipher name "none"
00 00 00 04 int length = 4
6e 6f 6e 65 string kdf name "none"
00 00 00 00 int length = 0
(zero bytes for the kdf options)
00 00 00 01 int number of keys 1
00 00 00 33 = 51 int lenth
00 00 00 0b int length = 11
73 73 68 2d 65 64 32 35 35 31 39 = ssh-ed25519

00 00 00 20 int length = 32
36 59 2f b1 61 50 02 b9 39 b2 c5 00 c1 c8 57 c3 (16)
e6 d4 5f 64 59 f1 ab 4d e5 d3 8f ad 60 fc 44 c6 (16)  = maybe a curve point on the ed25519 curve

00 00 00 a8 int length = 168

fe 2f 86 b3 fe 2f 86 b3 = ?? (8 bytes)
# here's the public key again (inside the private/key-pair)
00 00 00 0b int length = 11
73 73 68 2d 65 64 32 35 35 31 39 = ssh-ed25519
00 00 00 20 int length = 32
36 59 2f b1 61 50 02 b9 39 b2 c5 00 c1 c8 57 c3 (16)
e6 d4 5f 64 59 f1 ab 4d e5 d3 8f ad 60 fc 44 c6 (16)

00 00 00 40 = 64 (4 bytes) = private key
48 86 03 4e 97 33 e7 1f 77 00 ba 5e 52 d1 54 ab
9e 2a dd 56 be 93 54 32 f6 81 50 d7 20 4b ba 15
36 59 2f b1 61 50 02 b9 39 b2 c5 00 c1 c8 57 c3
e6 d4 5f 64 59 f1 ab 4d e5 d3 8f ad 60 fc 44 c6

00 00 00 1f int length = 31
54 65 61 6c 65 76 65 73 20 74 65 73 74 20 45 44 = maybe X coord on curve
32 35 35 31 39 20 53 53 48 20 4b 65 79 20 31  (there's a Y sign bit somewhere too)

01 02 03 04 05 06 (6 bytes padding)







dump-ssh-private-key ssh-03-ed25519-passphrase-private-key.pem
magic plus null byte
6f 70 65 6e 73 73 68 2d 6b 65 79 2d 76 31 00
int length
00 00 00 0a = 10
61 65 73 32 35 36 2d 63 62 63 = aes256-cbc

int length
00 00 00 06 = 6
62 63 72 79 70 74 = bcrypt

00 00 00 18 int length = 24

00 00 00 10 int length = 16
d9 3b fe b4 54 93 c8 05 a7 77 21 7d 1c a5 69 1d = salt/iv for bcrypt
00 00 00 10 = work factor = 16

00 00 00 01 int num keys = 1

00 00 00 33 int length = 51
    00 00 00 0b int length = 11
    73 73 68 2d 65 64 32 35 35 31 39 = ssh-ed25519

    00 00 00 20 int length = 32
    2e 40 78 7a 53 e2 89 d8 8f 54 9d 4b a3 3e 56 58
    85 c7 1d 52 2e 7d 78 4e 9b e3 a5 89 1b 61 79 2a

    00 00 00 90 int length = 144


68 c8 c3 da e6 6b cd d2 2f 4a 74 ad e9 7b 75 6a = AES CBC output ciphertext
a6 8f d1 6d 24 86 fa 1e b1 77 25 0c e3 fa 30 6d
da 7c 72 11 be ac 98 0e b0 7b 7d 85 87 aa d1 49
c7 97 0a b4 5f 6e 61 5d 10 7c cd 55 c5 38 45 e8
4c b8 2d 23 67 7b 23 18 97 06 7a 9d 0d bc 69 d1
88 73 ba 34 8e 39 4e 50 01 cc 36 a7 c8 8b 58 57
e9 c5 f4 b0 eb 79 ab 1b e6 64 a0 78 59 a6 2b 05
03 00 57 bb 7b d4 19 ed 62 98 b1 db 4e 51 27 8e
b7 7e f8 e2 42 d0 18 01 99 b6 c2 30 ad 9c 33 9e
```


- AWS parameter store
