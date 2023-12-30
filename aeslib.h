Cipher::Aes<KEY_BIT_SIZE_256>* AES256(unsigned char key[]);
unsigned char * AES256EncryptBlock(Cipher::Aes<KEY_BIT_SIZE_256>* cipher, int length, unsigned char data [], unsigned char iv[]);
unsigned char * AES256DecryptBlock(Cipher::Aes<KEY_BIT_SIZE_256>* cipher, int length, unsigned char data[], unsigned char iv[]);