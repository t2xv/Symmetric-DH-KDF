from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
import os

# ------------------------------
# Symmetric KDF Chain Step
# ------------------------------
def kdf_chain_step(chain_key: bytes):
    """
    Derives a message key and the next chain key from the current chain key
    using HMAC-SHA256.
    """
    # Message key
    h1 = hmac.HMAC(chain_key, hashes.SHA256())
    h1.update(b"0")
    message_key = h1.finalize()
    
    # Next chain key
    h2 = hmac.HMAC(chain_key, hashes.SHA256())
    h2.update(b"1")
    next_chain_key = h2.finalize()
    
    return message_key, next_chain_key

# ------------------------------
# Root KDF (DH Ratchet)
# ------------------------------
def hkdf_root_mix(root_key: bytes, dh_output: bytes):
    """
    Mix a DH output into the root key to generate:
      - a new root key
      - a chain key (for sending or receiving)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes root key + 32 bytes chain key
        salt=root_key,
        info=b"double-ratchet-root"
    )
    derived = hkdf.derive(dh_output)
    new_root_key = derived[:32]
    chain_key = derived[32:]
    return new_root_key, chain_key

# ------------------------------
# DH key generation for Alice and Bob
# ------------------------------
def generate_dh_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

# ------------------------------
# Symmetric Ratchet: generate message key
# ------------------------------
def symmetric_ratchet_step(chain_key: bytes):
    msg_key, next_chain_key = kdf_chain_step(chain_key)
    return msg_key, next_chain_key

# ------------------------------
# Initialize
# ------------------------------
root_key = os.urandom(32)

# Initial DH keypairs
alice_priv, alice_pub = generate_dh_keypair()
bob_priv, bob_pub = generate_dh_keypair()

# Compute initial shared secret and derive root + first chain key
shared_secret = alice_priv.exchange(bob_pub)
root_key, alice_send_chain = hkdf_root_mix(root_key, shared_secret)
bob_recv_chain = alice_send_chain  # Bob's receiving chain matches Alice's sending chain

# ------------------------------
# Alice sends a message
# ------------------------------
msg_key_alice, alice_send_chain = symmetric_ratchet_step(alice_send_chain)
msg_key_bob, bob_recv_chain = symmetric_ratchet_step(bob_recv_chain)

print(f"Alice → Bob message key match? {msg_key_alice == msg_key_bob}")

# ------------------------------
# Rotate DH for next message (simulate DH ratchet)
# ------------------------------
alice_priv, alice_pub = generate_dh_keypair()
dh_output = alice_priv.exchange(bob_pub)
root_key, alice_send_chain = hkdf_root_mix(root_key, dh_output)
bob_recv_chain = alice_send_chain  # same chain key for next messages

# ------------------------------
# Bob sends a message back
# ------------------------------
# Bob rotates DH
bob_priv, bob_pub = generate_dh_keypair()
dh_output_bob = bob_priv.exchange(alice_pub)
root_key, bob_send_chain = hkdf_root_mix(root_key, dh_output_bob)
alice_recv_chain = bob_send_chain  # Alice's receiving chain

# Symmetric ratchet to derive message keys
msg_key_bob_send, bob_send_chain = symmetric_ratchet_step(bob_send_chain)
msg_key_alice_recv, alice_recv_chain = symmetric_ratchet_step(alice_recv_chain)

print(f"Bob → Alice message key match? {msg_key_bob_send == msg_key_alice_recv}")

# ------------------------------
# Send a second message from Alice without DH rotation
# ------------------------------
msg_key_alice2, alice_send_chain = symmetric_ratchet_step(alice_send_chain)
msg_key_bob2, bob_recv_chain = symmetric_ratchet_step(bob_recv_chain)

print(f"Alice → Bob second message key match? {msg_key_alice2 == msg_key_bob2}")
