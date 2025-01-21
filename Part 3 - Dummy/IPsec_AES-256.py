from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def main():
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)   # Initialization vector

    plaintext = b"Your secret message goes here"
    print(f"Plaintext: {plaintext}")

    ciphertext = encrypt(plaintext, key, iv)
    print(f"Ciphertext: {ciphertext}")

    decrypted_text = decrypt(ciphertext, key, iv)
    print(f"Decrypted text: {decrypted_text}")

if __name__ == "__main__":
    main()