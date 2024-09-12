#include "AES.hpp"

/*
This file implements AES-CBC encryption/decryption
*/
extern "C" {
  constexpr size_t KEY_BIT_SIZE_256 = 256;

  Cipher::Aes<KEY_BIT_SIZE_256>* AES256(unsigned char * key) { 
    return new Cipher::Aes<KEY_BIT_SIZE_256>(key);
  }

  unsigned char * xorblock(unsigned char * l, unsigned char * r) {
    l[0] = l[0]^r[0];
    l[1] = l[1]^r[1];
    l[2] = l[2]^r[2];
    l[3] = l[3]^r[3];
    l[4] = l[4]^r[4];
    l[5] = l[5]^r[5];
    l[6] = l[6]^r[6];
    l[7] = l[7]^r[7];
    l[8] = l[8]^r[8];
    l[9] = l[9]^r[9];
    l[10] = l[10]^r[10];
    l[11] = l[11]^r[11];
    l[12] = l[12]^r[12];
    l[13] = l[13]^r[13];
    l[14] = l[14]^r[14];
    l[15] = l[15]^r[15];
    return l;
  }

  void freeme(char *ptr)
  {
    free(ptr);
  }

  unsigned char * AES256EncryptBlock(Cipher::Aes<KEY_BIT_SIZE_256>* cipher, int length, unsigned char * data, unsigned char * iv){ 
    unsigned char * ciphertext = (unsigned char * ) malloc(length);
    unsigned char * block = (unsigned char * ) malloc(16);
    unsigned char * xor_ = (unsigned char * ) malloc(16);
    memcpy(xor_, iv, 16);
    memcpy(block, data, 16);
    block = xorblock(block, xor_);
    cipher->encrypt_block(block);
    memcpy(ciphertext, block, 16);

    for (int i = 16; i<length; i+=16) {
      memcpy(xor_, block, 16);
      memcpy(block, (data + i), 16);
      block = xorblock(block, xor_);
      cipher->encrypt_block(block);
      memcpy((ciphertext + i), block, 16);
    }
    free(block);
    free(xor_);
    return ciphertext;
  }

  unsigned char * AES256DecryptBlock(Cipher::Aes<KEY_BIT_SIZE_256>* cipher, int length, unsigned char * data, unsigned char * iv) { 
     
    unsigned char * plaintext = (unsigned char * ) malloc(length);
    unsigned char * block = (unsigned char * ) malloc(16);
    unsigned char * xor_ = (unsigned char * ) malloc(16);
    
    for (int i = length; i>=32; i-=16) {
      memcpy(block, (data + i - 16), 16);
      cipher->decrypt_block(block);
      memcpy(xor_, (data + i - 32), 16);
      block = xorblock(block, xor_);
      memcpy((plaintext + i - 16), block, 16);
    }
    memcpy(block, data, 16);
    cipher->decrypt_block(block);
    block = xorblock(block, iv);
    memcpy(plaintext, block, 16);
    free(block);
    free(xor_);
    return plaintext;
  }
}