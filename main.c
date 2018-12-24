#include <stdio.h>
#include <tomcrypt.h>

int sha256_contents(FILE* file, unsigned char out_hash[32])
{
  const int BUFFER_SIZE = 256;
  unsigned char buf[BUFFER_SIZE];
  const int ITEM_SIZE = BUFFER_SIZE/sizeof(char);
  size_t items = ITEM_SIZE;
  hash_state c;
  sha3_256_init(&c);
  while (items == ITEM_SIZE)
  {
    items = fread(buf, sizeof(char), sizeof(buf)/sizeof(char), file);

    sha3_process(&c, buf, items*sizeof(char));
  }
  sha3_done(&c, out_hash);
  return 0;
}

int import_ecc_from(const char* filename, ecc_key* out_key)
{
  unsigned char* buffer;
  FILE* key_file = fopen(filename, "rb");
  if (key_file == NULL)
    exit(2); 

  fseek(key_file, 0, SEEK_END);
  size_t buffer_len = ftell(key_file);
  size_t item_len = buffer_len/sizeof(char);
  buffer = malloc(buffer_len);
  rewind(key_file);
  size_t items = fread(buffer, sizeof(char), item_len, key_file);
  for (int i = 0; i < items; ++i)
  {
    printf("%c", buffer[i]);
  }
  printf("\n");
  int res = ecc_import(buffer, buffer_len, out_key);
  free(buffer);
  printf("Import %s result: %d\n", filename, res);
  return res;
}

size_t load_signature(const char* filename, unsigned char** out_buffer)
{
  FILE* file = fopen(filename, "rb");
  if (file == NULL)
    return 0;

  fseek(file, 0L, SEEK_END);
  size_t buffer_len = ftell(file);
  size_t item_len = buffer_len/sizeof(char);
  rewind(file);
  unsigned char* buffer = malloc(buffer_len);
  if (fread(buffer, sizeof(char), item_len, file) != item_len)
    return 0;
  *out_buffer = buffer;
  return buffer_len;
}

int verify_ossl_signature()
{
  FILE* messageFile = fopen("message", "rb");

  if (messageFile == NULL)
    exit(1);

  // Hash message
  unsigned char hash[256 / 8] = { 0xab, 0xfa, 0x5d, 0xfd, 0x7f, 0x90, 0xbe, 0xea, 0x2c, 0x7a, 0x06, 0x49, 0xbf, 0x63, 0xda, 0x17, 0x2f, 0x02, 0x4f, 0xe6, 0x9e, 0x56, 0xa1, 0x28, 0x84, 0xa7, 0xe8, 0xeb, 0xc9, 0x92, 0x5d, 0xc5};
  /*sha256_contents(messageFile, hash);*/

  for (int i = 0; i < sizeof(hash); ++i)
  {
    printf("%02X", hash[i]);
  }
  printf("\nmessage hash completed.\n");

  // Init crypto math
  ltc_mp = ltm_desc;

  // Load key
  ecc_key key;
  const char* key_filename = "out_tom.key";
  if (import_ecc_from(key_filename, &key) != CRYPT_OK)
    exit(3);

  // Load the signature
  unsigned char* signature;
  size_t signature_len = load_signature("message_signature_sha256", &signature);
  // Verify
  int stat;
  if (ecc_verify_hash(signature, signature_len, hash, sizeof(hash), &stat, &key) != CRYPT_OK)
      exit(4);
  free(signature);
  signature = NULL;

  printf("Verify stat; %d\n", stat);
  return 0;
}

unsigned char* offsetByte(unsigned char* buffer, long length, int bit)
{
  size_t offset = bit/8;
  if (offset >= length)
    return NULL;
  return &buffer[offset];
}

int main()
{
  return verify_ossl_signature();
}

int der_convert_openssl_to_tomcrypt()
{
  FILE* eckey_file = fopen("ecdsa-p256-public.der", "rb");
  if (eckey_file == NULL)
    return 1;

  fseek(eckey_file, 0, SEEK_END);
  unsigned long eckey_len = ftell(eckey_file);
  rewind(eckey_file);
  unsigned char* eckey = malloc(eckey_len);
  size_t item_len = eckey_len / sizeof(char);
  if (fread(eckey, sizeof(char), item_len, eckey_file) != item_len)
    return 2;

  // Decode the openssl .der file
  void *p, *q, *r, *s, *t;
  int res;
  ltc_asn1_list *obj_seq;

  res = der_decode_sequence_flexi(eckey, &eckey_len, &obj_seq);
  if (res != CRYPT_OK)
    return 3;

  printf("%lu bytes total, root seq len %lu used %d\n", eckey_len, obj_seq->size, obj_seq->used);
  ltc_asn1_list *child1 = obj_seq->child;
  printf("child1 seq type: %d len %lu used %d\n", child1->type, child1->size, child1->used);
  ltc_asn1_list *sibling1 = child1->next;
  printf("sibiling1 type: %d size: %lu used: %d %02X\n", sibling1->type, sibling1->size, sibling1->used, *(unsigned char*)sibling1->data);
  unsigned char* data = sibling1->data;
  size_t xy_buf_len = sibling1->size/8;
  unsigned char* xy_buf = malloc(xy_buf_len);
  printf("xy_buf_len %lu\n", xy_buf_len);
  memset(xy_buf, 0, xy_buf_len);
  for (int i = 0; i < sibling1->size; ++i)
  {
    if (data[i])
      *offsetByte(xy_buf, xy_buf_len, i) |= 1 << (7-i%8);
    printf("%c", data[i]?'1':'0');
  }
  printf("\n");
  for (int i = 0; i < xy_buf_len; ++i)
  {
    printf("%02X", xy_buf[i]);
  }
  printf("\n");

  // Init crypto math
  ltc_mp = ltm_desc;

  // Try writing a tomcrypt format
  ecc_key outKey;
  outKey.type = PK_PUBLIC;

  unsigned char flags[1];
  unsigned char out_buf[ECC_BUF_SIZE];
  unsigned long buf_size = sizeof(out_buf);
  unsigned long key_size = 32;
  void *x, *y;
  if (ltc_mp.init(&x) != CRYPT_OK)
    return 4;
  if (ltc_mp.init(&y) != CRYPT_OK)
    return 4;
  if (ltc_mp.unsigned_read(x, &xy_buf[1], key_size))
    return 5;
  if (ltc_mp.unsigned_read(y, &xy_buf[1+key_size], key_size))
    return 5;
  flags[0] = 0;
  res = der_encode_sequence_multi(out_buf, &buf_size,
      LTC_ASN1_BIT_STRING,      1UL, flags,
      LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
      LTC_ASN1_INTEGER,         1UL, x,
      LTC_ASN1_INTEGER,         1UL, y,
      LTC_ASN1_EOL,             0UL, NULL);

  FILE* keyOut = fopen("out_tom.key", "wb+");
  if (keyOut == NULL)
    return 10;
  fwrite(out_buf, sizeof(char), buf_size, keyOut);
  fclose(keyOut);

  return 0;
}
