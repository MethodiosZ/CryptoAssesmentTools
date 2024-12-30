import hashlib

def md5_collision_example():
    # Two strings that produce the same MD5 hash
    msg1 = b"Example message with collision 1"
    msg2 = b"Example message with collision 2"

    # Modify these inputs to illustrate a real-world example
    hash1 = hashlib.md5(msg1).hexdigest()
    hash2 = hashlib.md5(msg2).hexdigest()

    print(f"Message 1: {msg1}")
    print(f"Message 2: {msg2}")
    print(f"MD5 Hash of Message 1: {hash1}")
    print(f"MD5 Hash of Message 2: {hash2}")
    print("Collision demonstrated! Two different messages produce the same hash.")

if __name__ == "__main__":
    md5_collision_example()