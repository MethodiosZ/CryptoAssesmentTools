#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_KEYSIZE 16  // AES-128 key size
#define AES_BLOCKSIZE 16  // AES block size

// Function to print bytes in hex format
void print_hex(const char *label, const unsigned char *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// AES-128 encryption
void aes_encrypt(const unsigned char *plaintext, unsigned char *ciphertext, const unsigned char *key, unsigned char *iv) {
    AES_KEY encrypt_key;
    AES_set_encrypt_key(key, AES_KEYSIZE * 8, &encrypt_key);
    AES_cbc_encrypt(plaintext, ciphertext, AES_BLOCKSIZE, &encrypt_key, iv, AES_ENCRYPT);
}

// AES-128 decryption
void aes_decrypt(const unsigned char *ciphertext, unsigned char *decrypted, const unsigned char *key, unsigned char *iv) {
    AES_KEY decrypt_key;
    AES_set_decrypt_key(key, AES_KEYSIZE * 8, &decrypt_key);
    AES_cbc_encrypt(ciphertext, decrypted, AES_BLOCKSIZE, &decrypt_key, iv, AES_DECRYPT);
}

int main() {
    unsigned char key[AES_KEYSIZE] = "1234567890abcdef";  // 16-byte key
    unsigned char iv[AES_BLOCKSIZE] = "abcdefghijklmnop"; // 16-byte IV

    unsigned char plaintext[AES_BLOCKSIZE] = "Hello, AES-128!"; // 16 bytes plaintext
    unsigned char ciphertext[AES_BLOCKSIZE];
    unsigned char decrypted[AES_BLOCKSIZE];

    printf("Original plaintext: %s\n", plaintext);

    // Encrypt
    aes_encrypt(plaintext, ciphertext, key, iv);
    print_hex("Encrypted", ciphertext, AES_BLOCKSIZE);

    // Decrypt
    aes_decrypt(ciphertext, decrypted, key, iv);
    decrypted[AES_BLOCKSIZE - 1] = '\0'; // Ensure null termination for printing
    printf("Decrypted text: %s\n", decrypted);

    return 0;
}