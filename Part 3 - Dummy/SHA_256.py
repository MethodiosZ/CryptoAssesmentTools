import hashlib

def sha256_hash(input_string):
    sha256 = hashlib.sha256()
    sha256.update(input_string.encode('utf-8'))
    return sha256.hexdigest()

if __name__ == "__main__":
    input_string = input("Enter the string to hash: ")
    print(f"SHA-256 hash of '{input_string}': {sha256_hash(input_string)}")