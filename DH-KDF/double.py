from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# ------------------------------
# Symmetric KDF Chain Step
# ------------------------------
def kdf_chain_step(chain_key: bytes):
    """
    Derives a message key and the next chain key from the current chain key
    using HMAC-SHA256.
    """
    h1 = hmac.HMAC(chain_key, hashes.SHA256())
    h1.update(b"0")
    message_key = h1.finalize()
    
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
        length=64,
        salt=root_key,
        info=b"double-ratchet-root"
    )
    derived = hkdf.derive(dh_output)
    new_root_key = derived[:32]
    chain_key = derived[32:]
    return new_root_key, chain_key

# ------------------------------
# DH key generation
# ------------------------------
def generate_dh_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

# ------------------------------
# Symmetric ratchet: message key
# ------------------------------
def symmetric_ratchet_step(chain_key: bytes):
    msg_key, next_chain_key = kdf_chain_step(chain_key)
    return msg_key, next_chain_key

# ------------------------------
# AES-GCM encrypt/decrypt
# ------------------------------
def encrypt_message(message: str, key: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, message.encode(), associated_data=None)
    return ct, nonce

def decrypt_message(ciphertext: bytes, key: bytes, nonce: bytes):
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return pt.decode()

# ------------------------------
# Initialize Double Ratchet
# ------------------------------
root_key = os.urandom(32)

alice_priv, alice_pub = generate_dh_keypair()
bob_priv, bob_pub = generate_dh_keypair()

# Initial shared secret
shared_secret = alice_priv.exchange(bob_pub)
root_key, alice_send_chain = hkdf_root_mix(root_key, shared_secret)
bob_recv_chain = alice_send_chain  # Bob's receiving chain

# ------------------------------
# Alice sends first message
# ------------------------------
plaintext = "Hello Bob!"
msg_key_alice, alice_send_chain = symmetric_ratchet_step(alice_send_chain)
ciphertext, nonce = encrypt_message(plaintext, msg_key_alice)

msg_key_bob, bob_recv_chain = symmetric_ratchet_step(bob_recv_chain)
decrypted = decrypt_message(ciphertext, msg_key_bob, nonce)

print(f"Alice → Bob message decrypted correctly? {plaintext == decrypted}")

# ------------------------------
# Rotate DH for next message (DH ratchet)
# ------------------------------
alice_priv, alice_pub = generate_dh_keypair()
dh_output = alice_priv.exchange(bob_pub)
root_key, alice_send_chain = hkdf_root_mix(root_key, dh_output)
bob_recv_chain = alice_send_chain

# ------------------------------
# Bob sends a message back
# ------------------------------
bob_priv, bob_pub = generate_dh_keypair()
dh_output_bob = bob_priv.exchange(alice_pub)
root_key, bob_send_chain = hkdf_root_mix(root_key, dh_output_bob)
alice_recv_chain = bob_send_chain

plaintext_bob = "Hi Alice!"
msg_key_bob_send, bob_send_chain = symmetric_ratchet_step(bob_send_chain)
ciphertext_bob, nonce_bob = encrypt_message(plaintext_bob, msg_key_bob_send)

msg_key_alice_recv, alice_recv_chain = symmetric_ratchet_step(alice_recv_chain)
decrypted_bob = decrypt_message(ciphertext_bob, msg_key_alice_recv, nonce_bob)

print(f"Bob → Alice message decrypted correctly? {plaintext_bob == decrypted_bob}")

# ------------------------------
# Alice sends another message without DH rotation
# ------------------------------
plaintext2 = "Another message"
msg_key_alice2, alice_send_chain = symmetric_ratchet_step(alice_send_chain)
ciphertext2, nonce2 = encrypt_message(plaintext2, msg_key_alice2)

msg_key_bob2, bob_recv_chain = symmetric_ratchet_step(bob_recv_chain)
decrypted2 = decrypt_message(ciphertext2, msg_key_bob2, nonce2)

print(f"Alice → Bob second message decrypted correctly? {plaintext2 == decrypted2}")
