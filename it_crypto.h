#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/engine.h>

/*
  Note: http://saju.net.in/code/misc/openssl_aes.c.txt provided a basis for the aes_* routines
 */

//initializes it_crypto, things like seeding random number generators
void it_crypto_init();

/*
   AES related functions and structs
 */

typedef struct {
  unsigned char key[32];
  unsigned char iv[32];
} aes_key;

//combines both encryption and decryption aes ciphers
typedef struct {
  EVP_CIPHER_CTX enc;
  EVP_CIPHER_CTX dec;
} aes_system;

//generates a key from misc data such as diffie-helman secret or a password
int aes_gen_key(unsigned char *data, int data_len, aes_key *key); //returns 0 on success
//initializes an aes crypto system with a given key
int aes_init( aes_key *key, aes_system *system ); //returns 0 on success
//frees internal aes components
void aes_close( aes_system *system );
//both encrypt and decrypt functions return the resulting *text, *len is an in and out param
//also the user is responsible for freeing returned buffers
unsigned char *aes_encrypt( aes_system *system, unsigned char *plaintext, int *len );
unsigned char *aes_decrypt( aes_system *system, unsigned char *ciphertext, int *len );
