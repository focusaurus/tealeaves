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

## rsa private key no passphrase
- PEM wrapper (header, base64 payload, footer)
- base64 payload is ASN.1

Sample of ASN.1 dump

```
grep -v - files/ssh-05-rsa-private-key.pem| base64 -D| dumpasn1 -
Warning: Input is non-seekable, some functionality has been disabled.
   0 1188: SEQUENCE {
   4    1:   INTEGER 0
   7  257:   INTEGER
         :     00 B0 5B 1F 8C 86 96 A3 BF 79 EF 56 CF EF 83 AF
         :     B7 A8 DE 4A 43 E0 C2 F1 FC E7 A6 B1 F0 FE C2 AA
         :     07 88 0C 46 CD F1 44 27 8D BD E6 0F 59 7A ED 4F
         :     97 F5 0A BE B8 5A DD D1 EE DF 57 6C B2 12 77 B8
         :     38 BE C2 7D 39 EE 58 1B 75 AC C8 CD F3 FC B1 AA
         :     9D EC B2 08 10 C5 85 0C D3 3D 25 1E B7 71 8D 3E
         :     AA 71 6D A9 29 36 36 22 78 95 44 6C 31 C4 86 A5
         :     BF 4B 0A E8 4C 6F AE 6B 9E 20 99 62 E7 03 75 0B
         :             [ Another 129 bytes skipped ]
 268    3:   INTEGER 65537
 273  257:   INTEGER
         :     00 AF 98 2B 93 9A 36 C7 98 51 6A B3 BF 9A B6 3D
         :     F1 DA 9C 6A C9 A7 33 B4 0A A3 04 E1 4C 19 FD ED
         :     9A 4E 26 1B 21 D7 46 8B 33 A0 8F 3F 5D 52 FE 93
         :     2F B4 77 1C 6B 27 5E 92 37 0B FE 5A 65 FB E9 64
         :     6E 6B D1 EF 2A 0D 5D 81 09 EC 1E 8C A2 91 4A BD
         :     9D 3D 1E 0E D5 D4 35 A4 0D 78 66 4B 6D 50 0C D9
         :     06 90 A6 25 B6 B9 19 B1 BC EA B3 14 1F 81 94 A7
         :     D8 0E 7A 2F CE 5B AD 09 CE 8A 9A EF 55 21 A6 1B
         :             [ Another 129 bytes skipped ]
 534  129:   INTEGER
         :     00 E1 B1 D5 EF 22 AA BE 06 41 8B 1D 45 1E 2B 6E
         :     C9 12 A9 B2 58 DC EC 96 2D 2B F4 99 0C 24 8B 82
         :     AA 83 0E DE 34 6B 0F 20 F6 C8 3A CA E4 1E 82 4C
         :     2E 6B 41 DE 35 82 E0 ED 22 EB 10 B3 AD FB 8A BA
         :     B3 80 84 E6 D5 62 F0 8F EA BC 64 A3 A0 2A 3F 89
         :     DA 46 19 E5 08 88 EB D2 F9 B5 1A CC 2A 53 FF D1
         :     07 33 D4 4C D5 A5 B5 3A EE 09 E8 37 FA DC 7E 41
         :     F4 E1 A2 9D 0A 9E 52 E5 93 CC 5E 75 E0 45 0B 8E
         :     BD
 666  129:   INTEGER
         :     00 C8 09 49 E9 0F 03 11 2A 5A 68 05 27 24 C0 34
         :     EE 76 74 50 71 5F C0 30 16 A9 1F FF 2C F9 18 1C
         :     BF D1 48 91 71 F3 E7 30 52 1B E0 27 79 22 E5 7B
         :     DA E2 85 EB E0 45 10 73 6C 5D 05 D2 D7 92 E3 35
         :     5E 9F 68 A9 DB 1E 64 A3 42 B4 25 65 AC A2 07 10
         :     FD A5 1B 51 60 32 1C 87 5B 63 72 56 08 3E 58 75
         :     5F 03 95 6A 4A DF 0C D0 B8 61 11 46 93 E0 96 F7
         :     09 2D 37 EB 09 7B 3D C6 79 68 ED 9B 00 F0 20 04
         :     19
 798  128:   INTEGER
         :     0A 9A 77 49 97 E0 5B B3 21 8B 2E A1 DB AC 00 B5
         :     73 AA 03 56 07 73 1A 0F 1F 3C 8B A0 35 6B 54 85
         :     3C 49 0B 89 7C EA 26 0B 52 16 E9 07 54 A3 9C 7E
         :     A5 CD 5F 6A 36 2E E9 15 35 E3 FF FD 11 8F 4F FC
         :     34 F2 89 81 C6 F7 34 5B BB E4 22 87 D8 D4 49 5E
         :     B6 E2 6A 8F 3F 17 8D 3E EC 12 49 3B 47 DD 01 EE
         :     0B B2 52 B5 CA E6 3B D1 89 27 9E D1 AB 60 47 2B
         :     01 1A C9 B4 01 02 36 04 FE 9A 05 81 B6 DC B7 25
 929  128:   INTEGER
         :     5E 12 E8 3C 7F BF DC 81 C3 94 A9 DF B7 CB E0 D8
         :     C8 C2 78 D6 68 C6 74 97 23 A0 95 9C 2B E5 68 17
         :     D9 AF BC 1F 10 2A 88 B2 04 C4 0D 2C 4D FA 08 9E
         :     6E EB B6 7B 79 5F 7C 38 D9 22 94 FE A6 E8 CD BF
         :     9B 4E 58 9B 61 16 C9 24 E4 9D B5 CC 53 42 E9 7D
         :     AF F9 41 F2 F0 7E 34 36 09 75 CA FA 03 80 0C 6A
         :     CB BF A8 06 60 11 A1 D3 24 6B 40 7A E9 23 76 38
         :     4D 98 BF A3 6C DF 27 89 0F 8C B6 D9 E1 13 DD 79
1060  129:   INTEGER
         :     00 C1 9A 5E E5 24 5F B0 90 1A 1C EB 72 24 61 09
         :     6B B0 EB F6 2D 00 D8 FC E3 D9 65 C1 7D 8C 49 94
         :     5D 4B 71 B9 57 8A 7F 81 5B D4 F2 72 E9 B5 31 0A
         :     98 C9 E7 5F 8A 08 48 9E FA 2E 1E F9 93 36 4B 1E
         :     DA 45 C0 A7 79 B5 CA BD DB 9A EE C6 6B C3 1B CE
         :     BF 04 5C D0 5E 87 5B 52 DA B1 74 C7 E0 A0 5E F6
         :     D4 D5 2B 7F 67 17 C7 7A 10 18 79 10 AD 10 51 34
         :     E5 93 AD E4 3E BD 78 4D 66 81 51 89 BF 42 7E FF
         :     B3
         :   }

0 warnings, 0 errors.
```

## References

- [RFC 4716](https://tools.ietf.org/html/rfc4716) supposedly the ssh public key file format, but my ssh-keygen on macOS 10.13 does not generate this format by default.
- PKCS8
- https://lionet.info/asn1c/basics.html
- https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/
- https://github.com/golang/crypto/blob/master/bcrypt/bcrypt.go
- https://tools.ietf.org/html/rfc4253#section-6.6
- https://peterlyons.com/problog/2017/12/openssh-ed25519-private-key-file-format
- https://etherhack.co.uk/asymmetric/docs/rsa_key_breakdown.html

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
