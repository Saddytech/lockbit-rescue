# This fork

This fork adds stream-reuse.c for POC of the keystream bug


# LOCKIT V3 LINUX DECRYPTOR

This tool decrypts LOCKBIT v3 encrypted files with provided RSA key. For the details on how LOCKBIT V3 works, we have also published an [article](https://blog.calif.io/p/dissecting-lockbit-v3-ransomware) about it.
  
## BUILD

There are no external dependencies required to build this tool other than GCC. The ***FILE_OFFSET_BITS*** flag is added for the code to handle large file.

```
gcc -o frank frank.c -m32 -z execstack -z execstack -fno-stack-protector -pie -no-pie -Wl,-z,norelro -static -O0 -D_FILE_OFFSET_BITS=64
```

or

```
make
```

The tested build environment is **amd64 Ubuntu 22.04**. A prebuilt binary is also included.

## USAGE

```
frank -i <InputFile> -r <RSAKeyFile> [OPTIONS]
      -i: Encrypted file.
      -r: RSA private key file used with -d. Note: Must be exactly 256 bytes long, with RAW RSA d (128 bytes) & n (128 bytes).
      -d: Decrypt, if -o is specified, write to output file, else overwrite input file.
      -o: Output file, used in -d. Note: Overwrite input file is significantly faster.
      -c: Calculate checksum, not decrypt, do not use with -d."
      -v: Verbose.
```

**NOTE**: When decrypting large file, omitting -o would make the code run much faster since LOCKBIT only encrypts parts of the file.
