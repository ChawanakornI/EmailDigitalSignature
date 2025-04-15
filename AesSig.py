import hashlib
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- AES and Signing Functions ---

def generate_aes_key():
    return os.urandom(32)  # AES-256 => 32 bytes

def encrypt_email_body(email_body, aes_key):
    iv = os.urandom(16)  # 16 bytes for AES block size
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(email_body.encode()) + encryptor.finalize()
    return iv, ciphertext

def decrypt_email_body(encrypted_data, iv, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_data) + decryptor.finalize()).decode()

def sign_email(email_body):
    return hashlib.sha256(email_body.encode()).hexdigest()

def verify_signature(decrypted_email, signature):
    digest = hashlib.sha256(decrypted_email.encode()).hexdigest()
    return digest == signature

# --- Sender Side ---

def sender_flow():
    print("📤 Sender Mode Selected")

    email_body = input("Enter the email body: ")
    aes_key = generate_aes_key()
    iv, encrypted_email = encrypt_email_body(email_body, aes_key)
    signature = sign_email(email_body)

    # Save all as base64 to prevent binary issues
    with open("signed_encrypted_email.txt", "w") as f:
        f.write(base64.b64encode(aes_key).decode() + "\n")
        f.write(base64.b64encode(iv).decode() + "\n")
        f.write(base64.b64encode(encrypted_email).decode() + "\n")
        f.write(signature + "\n")

    print("✅ Email encrypted, signed, and saved to 'signed_encrypted_email.txt'.")

# --- Receiver Side ---

def receiver_flow():
    print("📥 Receiver Mode Selected")

    try:
        with open("signed_encrypted_email.txt", "r") as f:
            lines = f.read().splitlines()

            aes_key = base64.b64decode(lines[0].strip())
            iv = base64.b64decode(lines[1].strip())
            encrypted_email = base64.b64decode(lines[2].strip())
            signature = lines[3].strip()

            if len(aes_key) != 32:
                raise ValueError(f"Invalid AES key size: {len(aes_key)} bytes (should be 32)")
            if len(iv) != 16:
                raise ValueError(f"Invalid IV size: {len(iv)} bytes (should be 16)")

            decrypted_email = decrypt_email_body(encrypted_email, iv, aes_key)

            print("\n📧 Decrypted Email:")
            print(decrypted_email)

            if verify_signature(decrypted_email, signature):
                print("\n✅ Signature is VALID.")
            else:
                print("\n❌ Signature is INVALID!")

    except Exception as e:
        print(f"⚠️ Error during decryption or verification: {e}")

# --- Main ---

def main():
    print("=== Email Digital Signature Service ===")
    print("1. Sender")
    print("2. Receiver")
    choice = input("Select mode (1 or 2): ")

    if choice == '1':
        sender_flow()
    elif choice == '2':
        receiver_flow()
    else:
        print("❌ Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()
