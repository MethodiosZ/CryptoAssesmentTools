from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

class AES256:
    def __init__(self, key):
        self.key = key

    def pad(self, data):
        pad_length = AES.block_size - len(data) % AES.block_size
        return data + (chr(pad_length) * pad_length).encode()

    def unpad(self, data):
        pad_length = data[-1]
        return data[:-pad_length]

    def encrypt(self, data):
        data = self.pad(data)
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(data)
        return base64.b64encode(iv + encrypted).decode('utf-8')

    def decrypt(self, enc_data):
        enc_data = base64.b64decode(enc_data)
        iv = enc_data[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(enc_data[AES.block_size:])
        return self.unpad(decrypted).decode('utf-8')

# Example usage
if __name__ == "__main__":
    key = get_random_bytes(32)  # AES-256 requires a 32-byte key
    aes = AES256(key)

    data = "This is a secret message."
    print("Original:", data)

    encrypted = aes.encrypt(data.encode())
    print("Encrypted:", encrypted)

    decrypted = aes.decrypt(encrypted)
    print("Decrypted:", decrypted)