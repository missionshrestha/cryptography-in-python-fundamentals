import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Symmetric Encryption
# Example usage of AESGCM for encryption and decryption
def aes_encrypt_decrypt(message):
    key = secrets.token_bytes(32)  # AES-256 key
    nonce = secrets.token_bytes(12)  # AES GCM nonce
    aes = AESGCM(key)

    ciphertext = nonce + aes.encrypt(nonce=nonce, data=message.encode(), associated_data=None)
    decrypted_message = aes.decrypt(nonce=ciphertext[:12], data=ciphertext[12:], associated_data=None).decode()
    return key.hex(), ciphertext.hex(), decrypted_message

# Asymmetric Encryption
# Example usage of RSA for encryption and decryption
def rsa_encrypt_decrypt(message):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    ciphertext = public_key.encrypt(
        plaintext=message.encode(),
        padding=padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )
    decrypted_message = private_key.decrypt(
        ciphertext=ciphertext,
        padding=padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    ).decode()

    return ciphertext.hex(), decrypted_message

if __name__ == "__main__":
    message = "Hello, this is Mission"
    # key, ciphertext, decrypted_message = aes_encrypt_decrypt(message)
    # print(f"AES Key: {key}")
    # print(f"Ciphertext: {ciphertext}")
    # print(f"Decrypted Message: {decrypted_message}")

    ciphertext, decrypted_message = rsa_encrypt_decrypt(message)
    print(f"RSA Ciphertext: {ciphertext}")
    print(f"RSA Decrypted Message: {decrypted_message}")
