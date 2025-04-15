import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

def generate_keys(key_size):
    """
    Generate RSA keys and return private/public key objects.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key):
    """
    Save the private and public keys to PEM files.
    """
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_public_key(path="public_key.pem"):
    """
    Load the public key from a PEM file.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path="private_key.pem"):
    """
    Load the private key from a PEM file.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_email(private_key, email_body):
    """
    Sign the SHA-256 hash of the email body with the private key.
    """
    digest = hashlib.sha256(email_body.encode()).digest()
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, email_body, signature):
    """
    Verify the digital signature using the public key and email body.
    """
    digest = hashlib.sha256(email_body.encode()).digest()
    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def sender_flow():
    key_size = int(input("Enter RSA key size (256, 512, 1024, 2048): "))
    if key_size not in [256, 512, 1024, 2048]:
        print("❌ Invalid key size.")
        return

    private_key, public_key = generate_keys(key_size)
    save_keys(private_key, public_key)

    email_body = input("Enter the email body to sign: ")
    signature = sign_email(private_key, email_body)

    print("\n✅ Digital signature created.")
    print("Digital Signature (Hex):")
    print(signature.hex())
    print("Keys saved to 'private_key.pem' and 'public_key.pem'")

    with open("signed_email.txt", "w") as f:
        f.write("Email Body:\n")
        f.write(email_body + "\n\n")
        f.write("Digital Signature (Hex):\n")
        f.write(signature.hex())

    print("📝 Email and signature saved to 'signed_email.txt'")

def receiver_flow():
    if not os.path.exists("public_key.pem"):
        print("❌ 'public_key.pem' not found.")
        return

    email_body = input("Enter the received email body: ")
    signature_hex = input("Enter the received signature (hex): ")
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        print("❌ Invalid signature format.")
        return

    public_key = load_public_key()

    if verify_signature(public_key, email_body, signature):
        print("✅ Signature is VALID. The email is authentic.")
    else:
        print("❌ Signature is INVALID. The email may have been altered.")

def main():
    print("1. Sign Email (Sender)")
    print("2. Verify Email (Receiver)")
    choice = input("Choose (1 or 2): ")

    if choice == "1":
        sender_flow()
    elif choice == "2":
        receiver_flow()
    else:
        print("❌ Invalid choice.")

if __name__ == "__main__":
    main()
