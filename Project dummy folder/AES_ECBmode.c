#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

void encrypt_aes_ecb(const unsigned char *plaintext, const unsigned char *key, unsigned char *ciphertext) {
    AES_KEY encrypt_key;
    AES_set_encrypt_key(key, 128, &encrypt_key);

    for (int i = 0; i < 16; i++) { // Assume 16-byte blocks
        AES_encrypt(plaintext + (i * AES_BLOCK_SIZE), ciphertext + (i * AES_BLOCK_SIZE), &encrypt_key);
    }
}

int main() {
    unsigned char key[16] = "weakkey12345678"; // 128-bit key
    unsigned char plaintext[32] = "PatternPatternPatternPattern"; // Repeated patterns
    unsigned char ciphertext[32];

    encrypt_aes_ecb(plaintext, key, ciphertext);

    printf("Encrypted text (hex): ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    return 0;
}