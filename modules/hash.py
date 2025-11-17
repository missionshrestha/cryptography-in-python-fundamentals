import hashlib

# Example usage: Compute SHA-256 hash of a string
# plain_text = "Hello World!"
# hash_object = hashlib.sha256(plain_text.encode())
# hash_digest = hash_object.hexdigest()
# print(f"SHA-256 Hash of '{plain_text}': {hash_digest}")

# Example usage: Compute hash of a file
def hash_file(file_path, hash_algorithm='sha256'):
    """Compute the hash of a file using the specified hash algorithm."""
    hash_func = getattr(hashlib, hash_algorithm)()
    with open(file_path, 'rb') as file:
        while True:
            chunk = file.read(1024)
            if chunk == b'':
                break
            hash_func.update(chunk)
    return hash_func.hexdigest()


def verify_integrity(file1, file2, hash_algorithm='sha256'):
    """Verify if two files have the same hash."""
    hash1 = hash_file(file1, hash_algorithm)
    hash2 = hash_file(file2, hash_algorithm)
    print(f"Checking integrity between '{file1}' and '{file2}' using {hash_algorithm}:")
    if hash1 == hash2:
        return "Files are identical."
    return "Files has been altered."

if __name__ == "__main__":
    # file_path = 'Samples/sample.txt'
    # file_hash = hash_file(file_path, 'sha256')
    # print(f"SHA-256 Hash of file '{file_path}': {file_hash}")

    file1_path = 'Samples/sample.txt'
    file2_path = 'Samples/same_sample.txt'
    file3_path = 'Samples/altered_sample.txt'
    print(verify_integrity(file1_path, file2_path))
    print(verify_integrity(file1_path, file3_path))