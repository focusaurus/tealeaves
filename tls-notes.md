# Notes on TLS Files

## Certificate Signing Request

- PEM wrapper with `CERTIFICATE REQUEST` tag
- payload is ASN.1

```
  0 705: SEQUENCE {
  4 425:   SEQUENCE {
  8   1:     INTEGER 0
 11 124:     SEQUENCE {
 13  11:       SET {
 15   9:         SEQUENCE {
 17   3:           OBJECT IDENTIFIER countryName (2 5 4 6)
 22   2:           PrintableString 'US'
       :           }
       :         }
 26  11:       SET {
 28   9:         SEQUENCE {
 30   3:           OBJECT IDENTIFIER stateOrProvinceName (2 5 4 8)
 35   2:           UTF8String 'AL'
       :           }
       :         }
 39  18:       SET {
 41  16:         SEQUENCE {
 43   3:           OBJECT IDENTIFIER localityName (2 5 4 7)
 48   9:           UTF8String 'Fairbanks'
       :           }
       :         }
 59  30:       SET {
 61  28:         SEQUENCE {
 63   3:           OBJECT IDENTIFIER organizationName (2 5 4 10)
 68  21:           UTF8String 'Tealeaves Development'
       :           }
       :         }
 91  18:       SET {
 93  16:         SEQUENCE {
 95   3:           OBJECT IDENTIFIER organizationalUnitName (2 5 4 11)
100   9:           UTF8String 'Tealeaves'
       :           }
       :         }
111  24:       SET {
113  22:         SEQUENCE {
115   3:           OBJECT IDENTIFIER commonName (2 5 4 3)
120  15:           UTF8String 'tealeaves.local'
       :           }
       :         }
       :       }
137 290:     SEQUENCE {
141  13:       SEQUENCE {
143   9:         OBJECT IDENTIFIER rsaEncryption (1 2 840 113549 1 1 1)
154   0:         NULL
       :         }
156 271:       BIT STRING
       :         30 82 01 0A 02 82 01 01 00 B6 43 C4 19 7C 31 D3
       :         D2 77 74 C7 AA C3 5E 5D 96 56 24 71 3F B1 C9 3B
       :         BF DA 0F BD 12 02 22 7F 5D 1D 65 46 B8 1D 38 D8
       :         D3 DA 7E 60 A4 C9 75 73 D7 7C ED 77 2B FF 9C AC
       :         FB E5 32 55 37 DE 2C 7B 99 71 E0 64 72 4F E5 24
       :         AA 4E 5F 1A F8 15 AF 95 F3 5F 96 25 B8 2F 37 85
       :         93 B1 EF EC 3E E9 A5 C4 E1 BF EA 3C 97 41 96 B9
       :         58 E0 DA 0E FD 7B ED 0D 1C D8 8E E6 9C 86 69 8A
       :                 [ Another 142 bytes skipped ]
       :       }
431   0:     [0]
       :       Error: Object has zero length.
       :     }
433  13:   SEQUENCE {
435   9:     OBJECT IDENTIFIER sha256WithRSAEncryption (1 2 840 113549 1 1 11)
446   0:     NULL
       :     }
448 257:   BIT STRING
       :     51 85 1D 0F C1 29 35 E7 56 F8 E6 E0 C3 78 8C D5
       :     43 4C DE 15 AD 0A E5 33 F2 60 9B 8B B5 99 7C D2
       :     84 4F 7C 3D 55 78 88 E3 61 EB C9 08 87 EB EE 09
       :     63 D7 96 5C A8 03 89 82 56 37 3C 64 45 19 9F 38
       :     7A 5A 18 46 94 62 C0 2D 66 E0 95 37 16 FF 55 9B
       :     DD B0 97 C4 2B 04 5A 1B 3E D6 8B 89 11 E3 7A A6
       :     79 CA 06 3A BA C3 BD A1 E7 1A 1E 81 96 5F 63 46
       :     00 5D 3B 28 D3 A0 C4 EC 4E 51 78 4C 71 4E 3B E3
       :             [ Another 128 bytes skipped ]
       :   }

```

```
openssl asn1parse -in files/csr-sha256.pem
    0:d=0  hl=4 l= 705 cons: SEQUENCE
    4:d=1  hl=4 l= 425 cons: SEQUENCE
    8:d=2  hl=2 l=   1 prim: INTEGER           :00
   11:d=2  hl=2 l= 124 cons: SEQUENCE
   13:d=3  hl=2 l=  11 cons: SET
   15:d=4  hl=2 l=   9 cons: SEQUENCE
   17:d=5  hl=2 l=   3 prim: OBJECT            :countryName
   22:d=5  hl=2 l=   2 prim: PRINTABLESTRING   :US
   26:d=3  hl=2 l=  11 cons: SET
   28:d=4  hl=2 l=   9 cons: SEQUENCE
   30:d=5  hl=2 l=   3 prim: OBJECT            :stateOrProvinceName
   35:d=5  hl=2 l=   2 prim: UTF8STRING        :AL
   39:d=3  hl=2 l=  18 cons: SET
   41:d=4  hl=2 l=  16 cons: SEQUENCE
   43:d=5  hl=2 l=   3 prim: OBJECT            :localityName
   48:d=5  hl=2 l=   9 prim: UTF8STRING        :Fairbanks
   59:d=3  hl=2 l=  30 cons: SET
   61:d=4  hl=2 l=  28 cons: SEQUENCE
   63:d=5  hl=2 l=   3 prim: OBJECT            :organizationName
   68:d=5  hl=2 l=  21 prim: UTF8STRING        :Tealeaves Development
   91:d=3  hl=2 l=  18 cons: SET
   93:d=4  hl=2 l=  16 cons: SEQUENCE
   95:d=5  hl=2 l=   3 prim: OBJECT            :organizationalUnitName
  100:d=5  hl=2 l=   9 prim: UTF8STRING        :Tealeaves
  111:d=3  hl=2 l=  24 cons: SET
  113:d=4  hl=2 l=  22 cons: SEQUENCE
  115:d=5  hl=2 l=   3 prim: OBJECT            :commonName
  120:d=5  hl=2 l=  15 prim: UTF8STRING        :tealeaves.local
  137:d=2  hl=4 l= 290 cons: SEQUENCE
  141:d=3  hl=2 l=  13 cons: SEQUENCE
  143:d=4  hl=2 l=   9 prim: OBJECT            :rsaEncryption
  154:d=4  hl=2 l=   0 prim: NULL
  156:d=3  hl=4 l= 271 prim: BIT STRING
  431:d=2  hl=2 l=   0 cons: cont [ 0 ]
  433:d=1  hl=2 l=  13 cons: SEQUENCE
  435:d=2  hl=2 l=   9 prim: OBJECT            :sha256WithRSAEncryption
  446:d=2  hl=2 l=   0 prim: NULL
  448:d=1  hl=4 l= 257 prim: BIT STRING
```

```
3082 ASN.1 SEQUENCE
02c1 length = 705
3082 ASN.1 SEQUENCE
01a9 length = 425
02 ASN.1 Integer
01 length = 1
00 zero
30 ASN.1 SET
7c length = 124
31 ASN.1 SET
0b length = 11
30 ASN.1 SEQUENCE
09 length = 9
06 ASN.1 OBJECT
03 length = 3
550406 OID 2 4 6 countryName
13 ASN.1 PRINTABLESTRING
02 length = 2
5553 printable string = "US"
31 ASN.1 SET
0b length = 11
30 ASN.1 SEQUENCE
09 length = 9
06 ASN.1 OBJECT
03 length = 3
550408 5 4 8 stateOrProvinceName
0c ASN.1 UTF8STRING
02 length = 2
414c "AL"
31 ASN.1 SET
12 length = 18
30 ASN.1 SEQUENCE
10 length = 16
06 ASN.1 OBJECT
03 length = 3
550407 organizationName 5 4 7
0c ASN.1 UTF8STRING
09 length = 9
4661697262616e6b73 "Fairbanks"
31 ASN.1 SET
1e length = 30
30 ASN1. SEQUENCE
1c length = 28
06 ASN.1 OBJECT
03 length = 3
55040a organizationName = 5 4 9
0c ASN.1 UTF8STRING
15 length = 21
5465616c656176657320446576656c6f706d656e74 = "Tealeaves Development"
31
12
30
10
06
0355040b0c095465616c656176657331
18301606035504030c0f7465616c6561
7665732e6c6f63616c
3082 ASN.1 SEQUENCE
0122 length = 290
30
0d06
092a864886f70d01010105000
3820 ASN.1 SEQUENCE
10f length =
00
3082 ASN.1 SEQUENCE
010a
0282010100b643c4197c31
d3d27774c7aac35e5d965624713fb1c9
3bbfda0fbd1202227f5d1d6546b81d38
d8d3da7e60a4c97573d77ced772bff9c
acfbe5325537de2c7b9971e064724fe5
24aa4e5f1af815af95f35f9625b82f37
8593b1efec3ee9a5c4e1bfea3c974196
b958e0da0efd7bed0d1cd88ee69c8669
8a52d178661a941cda0c039e05e6d9ff
65549243ecefb821eafb188c78f4ab0f
807a56e0595465299f21b25af5c2c235
70f7474e893e6f3de80aec9580f0bf35
3e4dabc54f280cda9efada7850bacf44
7a9482d9a82d77da05c5ab6628740805
2aabe4c56e65a8f902dd6c8c1e80c10b
7e26f0c460e01259e4f32e1bd87b8125
afd40751fbf404fded0f0203010001a0
00300d06092a864886f70d01010b0500
038201010051851d0fc12935e756f8e6
e0c3788cd5434cde15ad0ae533f2609b
8bb5997cd2844f7c3d557888e361ebc9
0887ebee0963d7965ca803898256373c
6445199f387a5a18469462c02d66e095
3716ff559bddb097c42b045a1b3ed68b
8911e37aa679ca063abac3bda1e71a1e
81965f6346005d3b28d3a0c4ec4e5178
4c714e3be3ec40effd23455db5ca5ad3
ac8d0e03dee11fabe7bf0ec40483c945
10177c4135400ca890e564ff7b65776d
795ad8ec415bdea2b0cebe531058c23a
acb6997a27a27d0c2597d553ef15c210
70017bc8d4557090cd6e8709dfd4b031
667afdca40a9be0e5d19e965275c49ff
bfbe81d8c55b8c55530cfcbdfb531c9e
bf3deaeced
```
