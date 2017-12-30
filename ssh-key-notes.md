# Notes on ssh keys

## OpenSSH

OpenSSH supports the following key types

- ed25519
  - private key is PEM(openssh-key-v1)
  - public key is openssh-key-v1 format with ssh-ed25519 label
- rsa
  - private key is PEM(ASN.1) or PEM(openssh-key-v1) (with `-o`)
  - public key is openssh-key-v1 format with ssh-rsa label
- ecdsa
  - private key is PEM(ASN.1) or PEM(openssh-key-v1) (with `-o`)
  - public key is openssh-key-v1 format with ecdsa-sha2-nistp* label
- dsa
  - private key is PEM(ASN.1) or PEM(openssh-key-v1) (with `-o`)
  - public key is openssh-key-v1 format with ssh-dss label


## ed25519 private key file format (no passphrase)

- PEM wrapper with "OPENSSH PRIVATE KEY" tag around a base64 payload

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

- PEM wrapper with "OPENSSH PRIVATE KEY" tag around a base64 payload


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

## rsa private key no passphrase (PEM)

- PEM wrapper (header, base64 payload, footer) with `RSA PRIVATE KEY` tag
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

## rsa private key no passphrase openssh-key-v1

- PEM wrapper (header, base64 payload, footer) with `OPENSSH PRIVATE KEY` tag

```
6f70656e7373682d6b65792d763100 openssh-key-v1 and null byte
00000004 int length = 4
6e6f6e65 string cipher name = "none"
00000004 int length = 4
6e6f6e65 string kdfname = "none"
00000000 int length = 0 (kdf options)
00000001 int number of keys
00000097 int length of remaining payload
00000007 int length = 7
7373682d727361 string algorithm = "ssh-rsa"
00000003 int length = 3
010001 int exponent = 65537
00000081 int length = 129
00b2f7f6c3b05306fa916eef80979b
defc959fd3b62aef43dee6b04a12da5b
18305f760db7cb4bc19c11a7823f3592
0cfd62b764f2f3572fb5e90b7c4f9047
c902c04aae2463fbfabaf45fe44349c1
8a690b2d28397c26b7f21a71e8ffddda
3e4e52b7c3bd70da7be272c55e2393ed
e2a8d35bd28c2ff4d51193540a676b65
680f0000020867f00c7967f00c790000
00077373682d727361
00000081
00b2f7f6c3b05306fa916eef80979bdefc959f
d3b62aef43dee6b04a12da5b18305f76
0db7cb4bc19c11a7823f35920cfd62b7
64f2f3572fb5e90b7c4f9047c902c04a
ae2463fbfabaf45fe44349c18a690b2d
28397c26b7f21a71e8ffddda3e4e52b7
c3bd70da7be272c55e2393ede2a8d35b
d28c2ff4d51193540a676b65680f0000
0003010001
00000081
009ba24755a5e0
8e1118a8005f3378b951ae4c6f2fdbe6
767f40ddcd8cd796a05270b198fc5c2e
650ff3ca57d9e01c426f978924a0a23d
0fa082291ad19606d725b8efb83c2847
d4def077adb7acaf293f135136d39b56
a461e93953382decd3e5459184eaaa82
53a8d04922340da1d21660f9441f44b3
f9f1b96b8f4cb434c901000000410092
8ec7e47fe0a89903f4262c744cce2f6f
8f6895959fd4b21fff2e4d3d281d5f2d
ebcda10ee8c6fcc72dc2125bff27bc8a
f079cfd74d60d5c99516c4cabe419400
00004100db39b5975df1635a2b97e213
4525ba9db1ef73fb85fb79638c953361
be9095a443f085ed479ca385438d3044
afb87c56332d04b97b173d681d629cb5
dfbe3c35
00000041
00d0fd7d2b4747fb
1a53f69699faa8efed92f37d2b0cd56e
e30307fdb23d9821e62b914ac44e1fcf
d5553ad3c23755e2d60fcc51cf379502
9419acae8e06aff3b3
0000000a
706c79
6f6e734061766901020304050607
```

## rsa public key

`cat files/ssh-rsa-2048-b-public-key | cut -d " " -f 2 | base64 -D | xxd -p`

```
00000007 int length = 7
7373682d727361 string = "ssh-rsa"
00000003 int length = 3
010001 int public exponent = 65537
00000101 int length = 257 (1 null byte then 256)
00bef1e1ad8a4b855ea2
d770612afda8694fc5c7951d0e552453
4430cf04caf5fc59d8d98c2b3f5a9e96
bdc9c729b322ee16c1a98d6d3c166f05
b8aa55a56d9354d3211fa7ec7b6de346
06048e81d936ef65dc69f7cd388c613d
33c038cad07f96ccd52b394909579cab
cae6bf5db9cc4bdc1ed27b026c000393
4aeb7a073c9b36471b9bdd8e79948db1
021fb5b4757381d8f8c28fbf8a360cd5
dec8db1689a9d9a5b68d42a36ef7ff67
ff818d3658dd6be2abf251ef251fb71b
2f078b2c07e0190c4873b0b0483b8532
e1a8bf232180be9e5b51f54e24eca54a
c28514b120f2cb10b46af37196ea48c6
ce0942f820374b9af0879ecb385900a2
bd830748863e65
```

## dsa private key

- PEM wrapper (header, base64 payload, footer) with `DSA PRIVATE KEY` tag
- ASN.1 payload
```
  0 442: SEQUENCE {
  4   1:   INTEGER 0
  7 129:   INTEGER
       :     00 BD 04 0D 45 22 2C 81 63 3A A1 E3 BC 9F 1B 33
       :     9F 6C 1D 95 AD 2C 69 50 A1 5D 37 DA C8 63 96 C4
       :     BF 85 09 6E C7 CB 64 26 34 4C 87 B5 56 15 4B 7D
       :     90 E5 6A 7D E4 DC 84 A1 1D 19 51 8F B4 A6 F4 88
       :     C7 3F 80 66 82 B9 25 FA 3D 04 39 35 24 53 58 30
       :     23 3E 87 E9 AF 3D 8B 02 2F 59 C1 64 A1 F2 8E EC
       :     FA C7 E8 64 1E FC 24 43 BC 3D 06 AF EE 41 27 17
       :     15 89 67 59 F4 D9 DE 0D E0 11 DA 92 FE D0 EB 61
       :     C9
139  21:   INTEGER 00 C6 44 1F 38 B5 4F 56 D3 91 19 0F 0C EF 79 5B 5B C8 48 99 49
162 128:   INTEGER
       :     70 23 6F AB D6 A4 D3 20 82 A0 9A B9 0D E3 30 E1
       :     61 BF 19 8F A2 88 68 8C 29 14 11 56 53 4A 31 6D
       :     49 BA 17 AF 40 CE 63 84 67 5F 47 69 23 A1 92 DB
       :     3C 15 7F 57 D0 18 92 C0 B8 6B B0 C2 A1 D1 7A B7
       :     B8 B6 7A 4C CE 7C B1 44 E6 23 AE B6 9B 8C 62 11
       :     E9 F4 0A 56 21 E1 AB 60 2B CF DD 77 85 6D 81 EC
       :     CB A2 8D 90 55 A9 5C C7 02 CD 06 7E 41 5E 04 FE
       :     42 0F 41 F7 ED F7 F4 02 99 D4 B7 89 C7 23 58 E8
293 128:   INTEGER
       :     75 8E 32 AC A3 F4 1A ED 64 7C 0C 5F 12 9B C7 1A
       :     FD 28 67 BC 1C AC BB 02 0F 9F FA 1A 4B 48 AC F5
       :     76 99 24 6C 2B 9D 2C CC D1 5A 62 13 E1 18 F1 65
       :     B9 09 15 56 D3 A5 70 0E 7E 27 90 51 5B B3 4B C7
       :     77 A2 40 AA 15 06 9A 0C 85 D4 E2 EA 72 FC F0 72
       :     5E F2 B9 B4 82 82 05 21 E8 4C 33 6C 34 A6 3C 73
       :     BD BF F8 50 A7 5E 4B 6D C7 53 27 D8 9E A7 84 6D
       :     5E 76 39 38 7E 13 48 D1 2B 46 8B 89 68 9C 3C BD
424  20:   INTEGER 66 D5 97 A1 4D D5 DB 58 8D 95 FB 6B E9 AA C4 50 92 4C EA C3
       :   }
```

```
3082 ASN.1 SEQUENCE
01ba length = 442
02 ASN.1 INTEGER
01 length = 1
00 = 0
02
8181
00bd040d45222c81633aa1e3bc9f1b339f6c1d95
ad2c6950a15d37dac86396c4bf85096ec7cb6426344c87b556154b7d90e5
6a7de4dc84a11d19518fb4a6f488c73f806682b925fa3d04393524535830
233e87e9af3d8b022f59c164a1f28eecfac7e8641efc2443bc3d06afee41
271715896759f4d9de0de011da92fed0eb
61c90215
00c6441f38b54f56d3
91190f0cef795b5bc848994902818070236fabd6a4d32082a09ab90de330
e161bf198fa288688c29141156534a316d49ba17af40ce6384675f476923
a192db3c157f57d01892c0b86bb0c2a1d17ab7b8b67a4cce7cb144e623ae
b69b8c6211e9f40a5621e1ab602bcfdd77856d81eccba28d9055a95cc702
cd067e415e04fe420f41f7edf7f40299d4b789c72358e8028180758e32ac
a3f41aed647c0c5f129bc71afd2867bc1cacbb020f9ffa1a4b48acf57699
246c2b9d2cccd15a6213e118f165b9091556d3a5700e7e2790515bb34bc7
77a240aa15069a0c85d4e2ea72fcf0725ef2b9b482820521e84c336c34a6
3c73bdbff850a75e4b6dc75327d89ea7846d5e7639387e1348d12b468b89
689c3cbd021466d597a14dd5db588d95fb6be9aac450924ceac3
```

## dsa public key
- openssh-key-v1 space-delimited format

```
00000007 int length = 7
7373682d647373 string = ssh-dss
00000081 int length = 129
00bd040d45222c81633aa1e3bc9f1b33
9f6c1d95ad2c6950a15d37dac86396c4
bf85096ec7cb6426344c87b556154b7d
90e56a7de4dc84a11d19518fb4a6f488
c73f806682b925fa3d04393524535830
233e87e9af3d8b022f59c164a1f28eec
fac7e8641efc2443bc3d06afee412717
15896759f4d9de0de011da92fed0eb61
c9

00000015 int length = 21

00c6441f38b54f56d391190f0cef795b
5bc8489949

00000080 int length = 128

70236fabd6a4d32082a09ab90de330e1
61bf198fa288688c29141156534a316d
49ba17af40ce6384675f476923a192db
3c157f57d01892c0b86bb0c2a1d17ab7
b8b67a4cce7cb144e623aeb69b8c6211
e9f40a5621e1ab602bcfdd77856d81ec
cba28d9055a95cc702cd067e415e04fe
420f41f7edf7f40299d4b789c72358e8

00000080 int length = 128

758e32aca3f41aed647c0c5f129bc71a
fd2867bc1cacbb020f9ffa1a4b48acf5
7699246c2b9d2cccd15a6213e118f165
b9091556d3a5700e7e2790515bb34bc7
77a240aa15069a0c85d4e2ea72fcf072
5ef2b9b482820521e84c336c34a63c73
bdbff850a75e4b6dc75327d89ea7846d
5e7639387e1348d12b468b89689c3cbd
```
## ecdsa private key

- PEM wrapper (header, base64 payload, footer) with `RSA PRIVATE KEY` tag
- ASN.1 payload

```
  0 119: SEQUENCE {
  2   1:   INTEGER 1
  5  32:   OCTET STRING
       :     CE EE 48 65 6A B4 F6 A2 FE F4 3D DB D1 7C 99 06
       :     4A E6 3B 52 D0 72 4C 30 A9 BA E4 76 3E 26 FE C1
 39  10:   [0] {
 41   8:     OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       :     }
 51  68:   [1] {
 53  66:     BIT STRING
       :       04 B0 A4 CA 7F 39 24 83 78 2C 38 91 F6 23 36 0C
       :       B8 AF EE 7F 86 55 96 C2 01 1B 36 8F 91 02 F0 5E
       :       B1 7D 69 E2 14 8C E0 51 45 55 14 8B 43 5B 95 4E
       :       06 90 DA 7D CB DF 79 26 9A 8F B9 B0 FF 49 FE 40
       :       C0
       :     }
       :   }
```

```
30 ASN.1 SEQUENCE
77 length = 119
02 ASN.1 INTEGER
01 length = 1
01 = 1
04 = ASN.1 OCTET STRING
20 length = 32
ceee48656ab4f6a2fef43ddbd17c99064ae63b52d0724c30a9bae4763e26fec1
a0 tagged 0
0a length = 10
06 OID
08 length = 8
2a8648ce3d 03 01 07 prime256v1 OID (1 2 840 10045 3 1 7)
a1 tagged 1
44 length = 68
03 BIT STRING
42 length = 66
0004b0a4ca7f392483782c3891f62336
0cb8afee7f865596c2011b368f9102f0
5eb17d69e2148ce0514555148b435b95
4e0690da7dcbdf79269a8fb9b0ff49fe
40c0
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
- https://crypto.stackexchange.com/a/21104
- https://security.stackexchange.com/a/46781/67167
- https://tools.ietf.org/html/rfc1421
- https://tools.ietf.org/html/rfc1422
- https://tools.ietf.org/html/rfc1423
- https://tools.ietf.org/html/rfc2045
- https://fly.io/articles/how-rsa-works-tls-foundations/
- https://www.royalfork.org/2014/09/04/ecc/

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

- ssh ed25519 public key format is
- ascii ssh-ed25519
- space
- base64 data
  - int length
  - ssh-ed25519 ascii
  - int length
  - 32 bytes payload, which should match the private key
- space
- comment


- infineon USB key fob vulnerability with predictable keys
- maybe yubikeys too
- matching of ascii name and name in base64 portion to detect tampering
- matching of PEM tag ascii and info in base64 to detect PEM tag tampering

dump-ssh-key files/ssh-01-ed25519-private-key.pem | tr -d '\n' | fold -w 32
