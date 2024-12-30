from Crypto.Cipher import DES
from PIL import Image
import numpy as np

def encrypt_image_ecb(image_path, key):
    img = Image.open(image_path).convert('L')  # Convert to grayscale
    data = np.array(img)
    flattened_data = data.flatten()

    # Padding for DES block size
    pad_len = 8 - (len(flattened_data) % 8)
    padded_data = flattened_data.tobytes() + bytes([pad_len] * pad_len)

    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_data = cipher.encrypt(padded_data)

    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)[: len(flattened_data)]
    encrypted_image = Image.fromarray(encrypted_array.reshape(data.shape))
    return encrypted_image

if __name__ == "__main__":
    key = b'weakkey!'  # DES key must be 8 bytes
    image_path = "example.bmp"  # Provide a BMP file with a pattern
    encrypted_img = encrypt_image_ecb(image_path, key)
    encrypted_img.save("encrypted_ecb.bmp")
    print("Image encrypted using DES in ECB mode (check encrypted_ecb.bmp).")