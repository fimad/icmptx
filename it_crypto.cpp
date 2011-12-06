#include "it_crypto.h"
#include <openssl/rand.h> 
#include <openssl/bn.h> 

void it_crypto_init(){
   RAND_egd("/dev/random"); //seed the random number generator
}

int aes_gen_key(unsigned char *data, int data_len, aes_key *key){
  int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL /*no salt*/, data, data_len, 5 /*num rounds*/, key->key, key->iv);
  if (i != 32) {
    fprintf(stderr,"Key size is %d bits - should be 256 bits\n", i);
    return -1;
  }
  return 0;
}

int aes_init( aes_key *key, aes_system *system ){
  EVP_CIPHER_CTX_init(&system->enc);
  EVP_EncryptInit_ex(&system->enc, EVP_aes_256_cbc(), NULL, key->key, key->iv);
  EVP_CIPHER_CTX_init(&system->dec);
  EVP_DecryptInit_ex(&system->dec, EVP_aes_256_cbc(), NULL, key->key, key->iv);
  return 0;
}

void aes_close( aes_system *system ){
  EVP_CIPHER_CTX_cleanup(&system->enc);
  EVP_CIPHER_CTX_cleanup(&system->dec);
}

unsigned char *aes_encrypt( aes_system *system, unsigned char *plaintext, int *len ){
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + EVP_CIPHER_CTX_block_size(&system->enc), f_len = 0;
  unsigned char *ciphertext = (unsigned char *)malloc(c_len);

  EVP_EncryptInit_ex(&system->enc, NULL, NULL, NULL, NULL);
  EVP_EncryptUpdate(&system->enc, ciphertext, &c_len, plaintext, *len);
  EVP_EncryptFinal_ex(&system->enc, ciphertext+c_len, &f_len);

  //set len to the new length of the cipher text
  *len = c_len + f_len;
  return ciphertext;
}

unsigned char *aes_decrypt( aes_system *system, unsigned char *ciphertext, int *len ){
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = (unsigned char *)malloc(p_len);

  EVP_DecryptInit_ex(&system->dec, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(&system->dec, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(&system->dec, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

