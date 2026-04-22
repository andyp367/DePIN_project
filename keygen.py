# keygen.py
# Run only once to generate a key pair for Person 1 (the device).

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
import base64, json, os

key = Ed25519PrivateKey.generate()

priv_bytes = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
pub_bytes  = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

keys = {
    "device_id":   "pi-001",
    "public_key":  pub_bytes.hex(),
    "private_key": priv_bytes.hex()
}

os.makedirs("keys", exist_ok=True)
with open("keys/device_keys.json", "w") as f:
    json.dump(keys, f, indent=2)

print("Public key (share this with Person 2):")
print(keys["public_key"])