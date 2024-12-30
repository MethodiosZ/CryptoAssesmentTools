#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

RSA* generate_rsa_key() {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    if (!BN_set_word(e, RSA_F4)) handle_openssl_error();

    if (!RSA_generate_key_ex(rsa, 1024, e, NULL)) handle_openssl_error();

    BN_free(e);
    return rsa;
}

void rsa_no_padding_demo() {
    RSA* rsa = generate_rsa_key();

    unsigned char plaintext[] = "SensitiveData"; // Example plaintext
    unsigned char ciphertext[128]; // Buffer for ciphertext
    unsigned char decrypted[128]; // Buffer for decrypted plaintext

    int plaintext_len = strlen((char*)plaintext);

    // Encrypt without padding
    int encrypted_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, RSA_NO_PADDING);
    if (encrypted_len == -1) handle_openssl_error();

    printf("Encrypted text (no padding):\n");
    for (int i = 0; i < encrypted_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt without padding
    int decrypted_len = RSA_private_decrypt(encrypted_len, ciphertext, decrypted, rsa, RSA_NO_PADDING);
    if (decrypted_len == -1) handle_openssl_error();

    decrypted[decrypted_len] = '\0'; // Null-terminate
    printf("Decrypted text (no padding): %s\n", decrypted);

    printf("This demonstrates that RSA without proper padding is insecure and susceptible to attacks.\n");

    RSA_free(rsa);
}

int main() {
    rsa_no_padding_demo();
    return 0;
}