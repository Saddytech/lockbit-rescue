#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <getopt.h>
#include <stddef.h>
#include "frank.h"
#include "aplib.h"
#include <iconv.h>

#define STAT_CHECKSUM_OK            0x01
#define STAT_GENERIC_OK             0x00
#define ERROR_GENERIC               0xFFFFFFFF
#define ERROR_CHECKSUM              0xFFFFFFFE

#define OFFSET_KEY_ENCRYPTION_INFO  0x86
#define MAX_FILENAME_SIZE           0x1000

// global arguments
char           *prog_name = 0;
uint8_t         verbose;
uint8_t         will_decrypt;
uint8_t         checksum_only;
char           *encrypted = NULL;
char           *decrypted = NULL;
char           *rsakey    = NULL;

uint32_t        rdaddr = 0;                         // used to fix absolute address reference in checksm tasklet
uint32_t        rdaddraddr = 0;                     // used to fix absolute address reference in checksm tasklet
RSA_dn          dn = { 0 };                         // rsa private key
unsigned char   filename[MAX_FILENAME_SIZE * 2] = { 0 };       // to track decompressed filename -- not used in decryption


typedef uint32_t (__attribute__((stdcall)) *FUNC_CHECKSUM_tasklet)(void *, uint32_t, uint32_t);
typedef void     (__attribute__((stdcall)) *FUNC_RSA_decrypt)(void *, void *, void *);
typedef void     (__attribute__((stdcall)) *FUNC_SALSA20_decrypt)(uint32_t, void *, void *);
typedef void     (__attribute__((stdcall)) *FUNC_APLib_decompress)(void *, void *);

FUNC_CHECKSUM_tasklet   CHECKSUM_tasklet_func = NULL;
FUNC_RSA_decrypt        RSA_decrypt_func      = NULL;
FUNC_SALSA20_decrypt    SALSA20_decrypt_func  = NULL;
FUNC_APLib_decompress   APLib_decompress_func = NULL;

void prepare_shell_funcs() {
    void *CHECKSUM_tasklet_mmap = mmap(NULL, checksum_tasklet_len,
                                  PROT_EXEC | PROT_WRITE | PROT_READ,
                                  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(CHECKSUM_tasklet_mmap, checksum_tasklet, checksum_tasklet_len);

    // modify address for rd - 32bit only
    rdaddr = (uint32_t)&dn;
    rdaddraddr = (uint32_t)&rdaddr;

    // patch the shellcode to fix absolute address references
    memcpy(CHECKSUM_tasklet_mmap + checksum_tasklet_RSAd_addr_code_offset, &rdaddraddr, sizeof(uint32_t));
    CHECKSUM_tasklet_func = (FUNC_CHECKSUM_tasklet)CHECKSUM_tasklet_mmap;

    void *rsa_decrypt_mmap = mmap(NULL, rsa_decrypt_len,
                             PROT_EXEC | PROT_WRITE | PROT_READ,
                             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(rsa_decrypt_mmap, rsa_decrypt, rsa_decrypt_len);
    RSA_decrypt_func = (FUNC_RSA_decrypt)rsa_decrypt_mmap;

    void *salsa_mmap = mmap(NULL, salsa_crypt_len,
                            PROT_EXEC | PROT_WRITE | PROT_READ,
                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(salsa_mmap, salsa_crypt, salsa_crypt_len);
    SALSA20_decrypt_func = (FUNC_SALSA20_decrypt)salsa_mmap;

    void *apdecompress_mmap = mmap(NULL, apdecompress_bin_len,
                              PROT_EXEC | PROT_WRITE | PROT_READ,
                              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(apdecompress_mmap, apdecompress_bin, apdecompress_bin_len);
    APLib_decompress_func = (FUNC_APLib_decompress)apdecompress_mmap;
}

void cleanup_shell_funcs() {
    if (NULL != CHECKSUM_tasklet_func) {
        munmap(CHECKSUM_tasklet_func, checksum_tasklet_len);
        CHECKSUM_tasklet_func = NULL;
    }

    if (NULL != RSA_decrypt_func) {
        munmap(RSA_decrypt_func, rsa_decrypt_len);
        RSA_decrypt_func = NULL;
    }

    if (NULL != SALSA20_decrypt_func) {
        munmap(SALSA20_decrypt_func, salsa_crypt_len);
        SALSA20_decrypt_func = NULL;
    }

    if (NULL != APLib_decompress_func) {
        munmap(APLib_decompress_func, apdecompress_bin_len);
        APLib_decompress_func = NULL;
    }

}

uint32_t calculate_checksum(void *buffer, unsigned int size) {
    uint32_t m = 0;
    uint32_t n = 0;

    if ((size != 0) && (buffer != 0x0)) {
        m = CHECKSUM_tasklet_func(buffer, size,0xd6917a);
        m = CHECKSUM_tasklet_func(buffer, size,(m >> 0x18 | (m & 0xff0000) >> 8 | (m & 0xff00) << 8 | m << 0x18));
        m = CHECKSUM_tasklet_func(buffer, size,(m >> 0x18 | (m & 0xff0000) >> 8 | (m & 0xff00) << 8 | m << 0x18));
        n = m >> 0x18 | (m & 0xff0000) >> 8 | (m & 0xff00) << 8 | m << 0x18;
    }

    return n;
}

int verify_checksum(void *data, size_t size, uint32_t checksum) {
    uint32_t mychecksum = calculate_checksum(data, size);
    if (verbose) {
        printf("+ Calculated checksum: 0x%x\n", mychecksum);
    }

    if (mychecksum != checksum) {
        printf("- Checksum verification failed\n");
        return ERROR_CHECKSUM;
    }
    if (verbose) {
        printf("+ Checksum verification OK\n");
    }
    return STAT_CHECKSUM_OK;
}

int load_file(const char *fname, void *buffer, size_t *size) {
    int rc = -1;
    if (NULL == fname || NULL == buffer || NULL == size || *size < 1) {
        printf("- Invalid input\n");
        return rc;
    }

    FILE *f = fopen(fname, "r");
    if (NULL == f) {
        printf("- Failed to open file %s: ", fname);
        perror("");
        return rc;
    }

    fseeko(f, 0L, SEEK_END);
    off_t sz = ftello(f);
    fseek(f, 0L, SEEK_SET);

    if (sz > *size) {
        printf("- File size 0x%llx (%lld) is too big for buffer size 0x%lx (0x%ld)\n", sz, sz, *size, *size);
    } else {
        size_t nbytes = fread(buffer, 1, sz, f);
        if (nbytes != sz) {
            printf("- Failed to read\n");
            memset(buffer, 0, *size);
        } else {
            rc = 0;
            *size = sz;
        }
    }
    fclose(f);
    return rc;
}

int load_key_encryption_info(FILE *f, footer_no_filename *fnfn) {
    int rc = -1;
    if (NULL == f || NULL == fnfn) {
        printf("- Invalid input!\n");
        return rc;
    }

    fseeko(f, -OFFSET_KEY_ENCRYPTION_INFO, SEEK_END);   // negative seek from the end
    off_t cur = ftello(f);
    fread(&(fnfn->kei), 1, sizeof(key_encryption_info), f);
    if (verbose) {
        printf("+ key_encryption_info is at 0x%llx\n", cur);
        printf("+ file_encryption_info_length is at 0x%llx, value:0x%x (%d)\n",
                cur,
                fnfn->kei.file_encryption_info_length,
                fnfn->kei.file_encryption_info_length);
        printf("+ checksum is at 0x%llx, value: 0x%x (%d)\n",
                cur + offsetof(key_encryption_info, file_encryption_info_length),
                fnfn->kei.checksum, fnfn->kei.checksum);
        printf("+ encrypted_file_encryption_key is is at 0x%llx, first few bytes: %x %x %x %x\n",
                cur + offsetof(key_encryption_info, key_blob),
                fnfn->kei.key_blob.encrypted_key_encryption_key[0],
                fnfn->kei.key_blob.encrypted_key_encryption_key[1],
                fnfn->kei.key_blob.encrypted_key_encryption_key[2],
                fnfn->kei.key_blob.encrypted_key_encryption_key[3]);
    }

    // checksum
    rc = verify_checksum(&(fnfn->kei.key_blob), sizeof(fnfn->kei.key_blob), fnfn->kei.checksum);
    if (rc != STAT_CHECKSUM_OK) {      
        return rc;
    }

    // Decrypt the key_encryption_key.key_blob to get the SALSA20 key for file_encryption_info
    if (verbose) {
        rc = write_file("key_blob.encrypted.check", &(fnfn->kei.key_blob), SIZE);
    }
    RSA_decrypt_func(&(fnfn->kei.key_blob), &(dn.d), &(dn.n));
    if (verbose) {
        rc = write_file("key_blob.decrypted.check", &(fnfn->kei.key_blob), SIZE);
        printf("+ encrypted_file_encryption_key is is at 0x%llx, first few bytes: %x %x %x %x\n",
            cur + offsetof(key_encryption_info, key_blob),
            fnfn->kei.key_blob.decrypted.key_encryption_key[0],
            fnfn->kei.key_blob.decrypted.key_encryption_key[1],
            fnfn->kei.key_blob.decrypted.key_encryption_key[2],
            fnfn->kei.key_blob.decrypted.key_encryption_key[3]);
    }

    return rc;
}

int load_file_encryption_info(FILE *f, footer_no_filename *fnfn) {
    int rc = -1;
    if (NULL == f || NULL == fnfn ) {
        printf("- Invalid input\n");
        return rc;
    }

    fseeko(f, 0, SEEK_END);
    off_t end = ftello(f);
    off_t footer_offset = end - OFFSET_KEY_ENCRYPTION_INFO - fnfn->kei.file_encryption_info_length;
    if (verbose) {
        printf("+ footer starts at offset 0x%llx\n", footer_offset);
    }

    // this footer structure also contains the original filename
    long footer_size = sizeof(key_encryption_info) + fnfn->kei.file_encryption_info_length;
    void *footer = malloc(footer_size);
    memset(footer, 0, footer_size);
    fseeko(f, footer_offset, SEEK_SET);
    fread(footer, 1, footer_size, f);

    // decrypt file_encryption_info structure starting at the footer
    SALSA20_decrypt_func(fnfn->kei.file_encryption_info_length, (void  *)footer, &(fnfn->kei.key_blob));

    if (verbose) {
        rc = write_file("file_encryption_info.check", footer, fnfn->kei.file_encryption_info_length);
        rc = write_file("footer.check", footer, footer_size);
    }

    long file_encryption_info_no_filename_offset = footer_size - sizeof(file_encryption_info_no_filename) - sizeof(key_encryption_info);
    if (verbose) {
        printf("+ file_encryption_info_no_filename_offset = 0x%x\n", (uint32_t)file_encryption_info_no_filename_offset);
    }
    memcpy(&(fnfn->fei), footer + file_encryption_info_no_filename_offset, sizeof(file_encryption_info_no_filename));

    if (verbose) {
        printf("+ filename_size = 0x%x\n", fnfn->fei.filename_size);
    }

    if (fnfn->fei.filename_size > MAX_FILENAME_SIZE) {
        printf("- Error: Filename may be too large for the buffer\n");
        return rc;
    }

    APLib_decompress_func((void *)footer, (void *)filename);
    free(footer);       // don't need the footer anymore
    rc = 0;
    if (verbose) {
        rc = write_file("filename.check", filename, fnfn->fei.filename_size);
        rc = write_file("salsa.key.1.check", &(fnfn->fei.file_encryption_key), SALSA_KEY_SIZE);
    }
    return rc;
}

int load_footer(const char *fname, footer_no_filename *fnfn) {
    int rc = -1;
    if (NULL == fname || NULL == fnfn ) {
        printf("- Invalid input!\n");
        return rc;
    }
    FILE *f = fopen(fname, "r");
    if (NULL == f) {
        printf("- Failed to open %s: ", fname);
        perror("");
        return rc;
    }

    // Loading footer.key_encryption_info. This may fail with a checksum error
    rc = load_key_encryption_info(f, fnfn);
    if (0 != rc) {
        printf("- Failed to load key_encryption_info structure\n");
        return rc;
    }

    if (checksum_only) {
        fclose(f);               // we don't need f anymore
        return STAT_CHECKSUM_OK;
    }
    
    // Loading footer.file_encryption_info_no_filename structure
    rc = load_file_encryption_info(f, fnfn);
    fclose(f);
    return rc;
}

int write_file(const char *fname, void *buffer, long size) {
    int rc = -1;
    if (NULL == fname || NULL == buffer) {
        return rc;
    }

    FILE *f = fopen(fname, "w");
    if (NULL == f) {
        printf("- Failed to create %s: ", fname);
        perror("");
        return rc;
    }

    size_t count = fwrite(buffer, 1, size, f);
    if (count != size) {
        perror("- Failed to write data: ");
    } else {
        rc = 0;
    }
    fclose(f);
    return rc;
}

#define CHUNK_SIZE 0x20000

int do_decrypt(FILE *ifile, FILE *ofile, footer_no_filename *fnfn, off_t end, bool is_same_file) {
    bool is_skip = false;
    unsigned char chunk[CHUNK_SIZE] = { 0 };
    
    if (NULL == ifile || NULL == ofile || NULL == fnfn) {
        printf("- Invalid input\n");
        return -1;
    }

    fseeko(ifile, 0, SEEK_SET);
    fseeko(ofile, 0, SEEK_SET);
    off_t cur = ftello(ifile);
    uint32_t decrypt_chunk_count = fnfn->fei.before_chunk_count;

    while (end > cur) {
        if (is_skip) {
            printf("+ SKIPPING 0x%llx bytes at 0x%llx\n", fnfn->fei.skipped_bytes, cur);    
            if (is_same_file) {
                fseeko(ifile, fnfn->fei.skipped_bytes - CHUNK_SIZE, SEEK_CUR);
                fseeko(ofile, fnfn->fei.skipped_bytes - CHUNK_SIZE, SEEK_CUR);
            } else {
                size_t toskip = fnfn->fei.skipped_bytes;
                while (toskip > 0) {
                    size_t nbytes = fread(chunk, 1, CHUNK_SIZE, ifile);
                    nbytes = fwrite(chunk, 1, CHUNK_SIZE, ofile);
                    toskip -= nbytes;
                }
            }
            cur = ftello(ifile);
            printf("+ SKIPPED to 0x%llx\n", cur);
            is_skip = false;
            decrypt_chunk_count = fnfn->fei.after_chunk_count;
        } else {
            printf("+ DECRYPTING a chunk at 0x%llx\n", cur);
            size_t nbytes = fread(chunk, 1, CHUNK_SIZE, ifile);
            SALSA20_decrypt_func(nbytes, chunk, &(fnfn->fei.file_encryption_key));
            nbytes = fwrite(chunk, 1, CHUNK_SIZE, ofile);

            if (decrypt_chunk_count == 0) {
                is_skip = true;
            } else {
                decrypt_chunk_count -= 1;
            }
        }
        cur = ftello(ifile);
    }
    ftruncate(fileno(ofile), end);
    
    return 0;
}

int decrypt(footer_no_filename *fnfn) {
    int rc = -1;
    if (NULL == fnfn) {
        printf("- Invalid input\n");
        return rc;
    }

    bool is_same_file = (NULL == decrypted);
    unsigned int footer_size = sizeof(key_encryption_info) + fnfn->kei.file_encryption_info_length;
    
    FILE *ifile = fopen(encrypted, "r");
    if (NULL == ifile) {
        printf("- Failed to open file %s: ", encrypted);
        perror("");
        return rc;
    }

    FILE *ofile;
    if (is_same_file) {
        if (verbose) {
            printf("! DECRYPT to the same file %s\n", encrypted);
        }
        decrypted = encrypted;
        ofile = fopen(decrypted, "r+");
    } else {
        if (verbose) {
            printf("! DECRYPT to %s\n", decrypted);
        }
        ofile = fopen(decrypted, "w");
    }

    if (NULL == ofile) {
        perror("- Failed to open output file:");
        fclose(ifile);
        return rc;
    }

    // Get the end of the original file without footer
    fseeko(ifile, 0, SEEK_END);
    off_t end = ftello(ifile);
    end -= (off_t)footer_size;

    rc = do_decrypt(ifile, ofile, fnfn, end, is_same_file);
    fclose(ifile);
    fclose(ofile);

    if (rc == 0) {
        // decrypt OK!
        rc = truncate(decrypted, end);
        if (0 == rc)  {
            if (verbose) {
                printf("+ Truncate to 0x%llx\n", end);
            }
        } else {
            printf("- Failed to truncate %s: ", decrypted);
            perror("");
        }
    }
    return rc;
}

void help()
{
    printf( "Usage: %s  <shortname.encrypted>  <longname.encrypted>  <OriginalLongName>\n"
            "\tshortname.encrypted \tEncrypted file that has a short name.\n"
            "\tlongname.encrypted:\tEncrypted file that has longer name.\n"
            "\tOriginalLongName:\tOriginal name of the long file name.\n",
            prog_name
        );
}

typedef struct EncFooter {
    int len;
    char *data;
    footer_no_filename info;
} EncFooter;

EncFooter load_enc_footer(const char *filename)
{
    footer_no_filename fnfn = { 0 };
    int rc = load_footer(filename, &fnfn);
    size_t pos = fnfn.kei.file_encryption_info_length + 134;
    //read the footer (pos from end of file)
    FILE *f = fopen(filename, "rb");
    fseek(f, -pos, SEEK_END);
    char *data = malloc(pos);
    fread(data, 1, pos, f);
    fclose(f);
    EncFooter ef = { pos, data, fnfn };
    return ef;
}

void hexdump(const char *data, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x ", data[i] & 0xff);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    int rc = -1;
    will_decrypt = 0;
    checksum_only = 0;
    verbose = 1;

    prog_name = malloc(strlen(argv[0]) + 1);
    strcpy(prog_name, argv[0]);
    if (3 > argc) {
        help();
        return rc;
    }
    prepare_shell_funcs();
    const char* short_name_encrypted = argv[1];
    const char* long_name_encrypted = argv[2];
    

    EncFooter ef = load_enc_footer(short_name_encrypted);
    hexdump(ef.data, ef.len);

    EncFooter ef2 = load_enc_footer(long_name_encrypted);
    hexdump(ef2.data, ef2.len);

    iconv_t cd;
    cd = iconv_open("UTF-16LE", "UTF-8");
    if (cd == (iconv_t)-1) {
        perror("iconv_open");
        exit(EXIT_FAILURE);
    }

    void *workmem = malloc(aP_workmem_size(0));
    if (workmem == NULL) {
        fprintf(stderr, "Error: not enough memory\n");
        return 1;
    }
    //make sure we have at least one argument
    if (argc < 2) {
        fprintf(stderr, "Usage: %s string\n", argv[0]);
        return 1;
    }
    const char *long_name = argv[3];
    size_t sourceLen = strlen(long_name);
    size_t bufferSize = sourceLen * 2; // Rough estimate for buffer size (each char may take 2 bytes in UTF-16)
    wchar_t *utf16Buffer = (wchar_t *)malloc((bufferSize + 1) * sizeof(wchar_t)); // +1 for null terminator

    char *inbuf = (char *)long_name;
    char *outbuf = (char *)utf16Buffer;
    size_t inbytesleft = sourceLen;
    size_t outbytesleft = bufferSize * sizeof(wchar_t);
    size_t result = iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft);
    if (result == (size_t)-1) {
       perror("iconv");
       exit(EXIT_FAILURE);
    }


    uint8_t *data = (uint8_t *)utf16Buffer;
    int finalLen = (bufferSize * sizeof(wchar_t)) - outbytesleft;
    //include nulls
    finalLen += 2;

    //compress the string
    char *output = (char*)malloc(aP_max_packed_size(bufferSize * finalLen));
    unsigned int sz = aP_pack(utf16Buffer, output, finalLen, workmem, NULL, NULL);
    if (sz == 0) {
        fprintf(stderr, "Error: compression failed\n");
        return 1;
    }

    //hexdump compressed output
    printf("Compressed file name (%d bytes)", sz);
    hexdump(output, sz);

    char *key = (char *)malloc(sz);
    //xor LongNameEncrypted with compressed long name
    for (int i = 0; i < sz; i++) {
        key[i] = ef2.data[i] ^ output[i];
    }

    printf("KEY: ");
    hexdump(key, sz);

    //decrypt short name encrypted with key
    for (int i = 0; i < sz; i++) {
        if (i > ef.len) {
            break;
        }
        ef.data[i] ^= key[i];
    }    
    //hexdump decrypted 
    printf("Decrypted short name (%d bytes)", ef.len);
    hexdump(ef.data, ef.len);

    footer_no_filename fnfn = { 0 };

    printf("Footer no filename size: %d\n", sizeof(footer_no_filename));

    memcpy(&fnfn, ef.data + ef.len -sizeof(footer_no_filename) , sizeof(footer_no_filename));

    printf("+ filename_size = 0x%x\n", fnfn.fei.filename_size);

    FILE *infile = fopen(short_name_encrypted, "rb");
    FILE *outfile = fopen("decrypted", "wb");

    fseeko(infile, 0, SEEK_END);
    off_t end = ftello(infile);
    end -= (off_t)ef.len;

    printf("Decrypting %s\n", short_name_encrypted);
    printf("END = %d\n", end);

    rc = do_decrypt(infile, outfile, &fnfn, end, 0);


    cleanup_shell_funcs();
    return rc;
}
