from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
import os

# ----------------------------------------------------------
# Symmetric KDF Chain Step (Message Keys + Chain Key Update)
# ----------------------------------------------------------
def kdf_chain_step(chain_key: bytes):
    """
    Derives:
      - message_key: used to encrypt/decrypt ONE message
      - next_chain_key: used for the next step in the symmetric ratchet
    This uses HMAC(chain_key, "0") and HMAC(chain_key, "1")
    """
    # Derive message key
    h1 = hmac.HMAC(chain_key, hashes.SHA256())
    h1.update(b"0")
    message_key = h1.finalize()

    # Derive next chain key
    h2 = hmac.HMAC(chain_key, hashes.SHA256())
    h2.update(b"1")
    next_chain_key = h2.finalize()

    return message_key, next_chain_key


# ----------------------------------------------------------
# Root KDF (HKDF) — mixes DH output into the ratchet
# ----------------------------------------------------------
def hkdf_root_mix(root_key: bytes, dh_output: bytes):
    """
    Mixes a new DH shared secret into the root key and
    produces:
      - new_root_key
      - new_chain_key
    This follows the Double Ratchet specification.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,                  # 32 bytes root key + 32 bytes chain key
        salt=root_key,             # old root key used as salt
        info=b"double-ratchet-root"
    )

    derived = hkdf.derive(dh_output)
    new_root_key = derived[:32]
    new_chain_key = derived[32:]

    return new_root_key, new_chain_key


# ----------------------------------------------------------
# Simulate Alice ↔ Bob initial DH exchange
# ----------------------------------------------------------
# Generate DH keypairs
alice_priv = x25519.X25519PrivateKey.generate()
alice_pub = alice_priv.public_key()

bob_priv = x25519.X25519PrivateKey.generate()
bob_pub = bob_priv.public_key()

# Compute DH shared secret (same for both)
alice_shared = alice_priv.exchange(bob_pub)
bob_shared   = bob_priv.exchange(alice_pub)

print("Alice Shared Secret:", alice_shared.hex())
print("Bob Shared Secret:  ", bob_shared.hex())
print("Secrets match:", alice_shared == bob_shared)
print("\n--------------------------------------------\n")

# ----------------------------------------------------------
# Initialize Root Chain using the DH shared secret
# ----------------------------------------------------------
initial_root = os.urandom(32)
root_key, chain_key = hkdf_root_mix(initial_root, alice_shared)

print("Root Key: ", root_key.hex())
print("Initial Chain Key:", chain_key.hex())
print("\n--------------------------------------------\n")

# ----------------------------------------------------------
# Perform 3 symmetric KDF chain steps (message key generation)
# ----------------------------------------------------------
current_chain_key = chain_key

for i in range(1, 4):
    msg_key, current_chain_key = kdf_chain_step(current_chain_key)
    print(f"[Step {i}] Message Key :", msg_key.hex())
    print(f"[Step {i}] Next Chain Key:", current_chain_key.hex())
    print()
