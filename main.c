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

int main()
{
  FILE* messageFile = fopen("message", "rb");

  if (messageFile == NULL)
    exit(1);

  // Hash message
  unsigned char hash[256 / 8];
  sha256_contents(messageFile, hash);

  for (int i = 0; i < sizeof(hash); ++i)
  {
    printf("%02X", hash[i]);
  }
  printf("\nmessage hash completed.\n");

  // Init crypto math
  ltc_mp = ltm_desc;

  // Load key
  ecc_key key;
  const char* key_filename = "tom.der";
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
}
