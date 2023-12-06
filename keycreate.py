from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate a new private key
private_key = rsa.generate_private_key(
    public_exponent=65537,  # Commonly used value for RSA keys
    key_size=2048,  # Size of the key in bits
)

# Obtain the public key from the private key
public_key = private_key.public_key()

# Serialize and save the private key to a file
pem_private_key = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)

with open("private_key.pem", "wb") as f:
    f.write(pem_private_key)

# Serialize and save the public key to a file
pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

with open("public_key.pem", "wb") as f:
    f.write(pem_public_key)
