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
