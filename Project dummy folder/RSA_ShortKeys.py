from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from sympy import nextprime
import math

def generate_short_rsa_keys():
    p = nextprime(1000)  # Small prime
    q = nextprime(1100)  # Small prime
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Public exponent
    d = pow(e, -1, phi)  # Private exponent
    return e, d, n

def encrypt_decrypt_rsa_short_keys():
    e, d, n = generate_short_rsa_keys()
    message = 123  # Simple numeric message
    print(f"Original message: {message}")

    # Encrypt
    ciphertext = pow(message, e, n)
    print(f"Encrypted message: {ciphertext}")

    # Decrypt
    decrypted_message = pow(ciphertext, d, n)
    print(f"Decrypted message: {decrypted_message}")

    print("Using short keys, this RSA encryption is easily breakable.")

if __name__ == "__main__":
    encrypt_decrypt_rsa_short_keys()