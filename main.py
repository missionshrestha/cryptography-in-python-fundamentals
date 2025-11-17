from modules.hash import hash_file, verify_integrity
from modules.encryption import aes_encrypt_decrypt, rsa_encrypt_decrypt
from modules.password import check_password_strength, hash_password, verify_password

def menu():
    print("Select an option:")
    print("1. Hash a file")
    print("2. Verify file integrity")
    print("3. AES Encrypt/Decrypt a message")
    print("4. RSA Encrypt/Decrypt a message")
    print("5. Check password strength")
    print("6. Hash and verify a password")
    print("7. Exit")

    while True:
        choice = input("Enter your choice (1-7): ")
        if choice == "1":
            file_path = input("Enter the file path to hash: ")
            hash_algorithm = input("Enter hash algorithm (default: sha256): ") or 'sha256'
            file_hash = hash_file(file_path, hash_algorithm)
            print(f"{hash_algorithm.upper()} Hash of file '{file_path}': {file_hash}")
        elif choice == "2":
            file1 = input("Enter the path of the first file: ")
            file2 = input("Enter the path of the second file: ")
            hash_algorithm = input("Enter hash algorithm (default: sha256): ") or 'sha256'
            result = verify_integrity(file1, file2, hash_algorithm)
            print(result)
        elif choice == "3":
            message = input("Enter the message to encrypt/decrypt using AES: ")
            key, ciphertext, decrypted_message = aes_encrypt_decrypt(message)
            print(f"AES Key: {key}")
            print(f"Ciphertext: {ciphertext}")
            print(f"Decrypted Message: {decrypted_message}")
        elif choice == "4":
            message = input("Enter the message to encrypt/decrypt using RSA: ")
            ciphertext, decrypted_message = rsa_encrypt_decrypt(message)
            print(f"RSA Ciphertext: {ciphertext}")
            print(f"RSA Decrypted Message: {decrypted_message}")
        elif choice == "5":
            password = input("Enter a password to check its strength: ")
            result = check_password_strength(password)
            print(result)
        elif choice == "6":
            password = input("Enter a password to hash: ")
            hashed_password = hash_password(password)
            print(f"Hashed Password: {hashed_password}")
            confirm_password = input("Re-enter your password for verification: ")
            verification = verify_password(confirm_password, hashed_password)
            print(verification)
        elif choice == "7":
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()