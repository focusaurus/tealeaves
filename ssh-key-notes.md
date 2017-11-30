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
