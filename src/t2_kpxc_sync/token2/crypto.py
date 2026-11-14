"""Cryptographic primitives for Token2 PIN+ hardware token protocol.

Implements NIST P-256 (secp256r1) ECDH ephemeral key exchange and
AES-256-CBC encryption/decryption with fixed IV-1 for WRITE_SEED and DELETE payloads.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..security import scrub_bytes

# Fixed Initialization Vector (IV-1) specified by Token2 hardware protocol:
# 9D D8 91 8E 34 F3 CC AB 08 CB 75 18 F7 19 38 F1
IV_1: bytes = bytes.fromhex("9DD8918E34F3CCAB08CB7518F71938F1")


def generate_ecdh_keypair() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """Generates an ephemeral NIST P-256 private key and 64-byte uncompressed public key.

    Returns:
        Tuple of (private_key, raw_public_bytes_64).
        The raw_public_bytes_64 consists of uncompressed (X || Y) coordinates (64 bytes),
        omitting the leading 0x04 uncompressed point format prefix byte.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_point_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    # Strip leading 0x04 format indicator to get raw 64 bytes (X || Y)
    raw_public_64 = pub_point_bytes[1:]
    return private_key, raw_public_64


def public_key_from_raw_bytes(raw_pub_64: bytes) -> ec.EllipticCurvePublicKey:
    """Reconstructs an EllipticCurvePublicKey from raw 64-byte (X || Y) coordinates.

    Args:
        raw_pub_64: 64 bytes containing X (32 bytes) and Y (32 bytes).

    Raises:
        ValueError: If input is not exactly 64 bytes or represents an invalid point.
    """
    if len(raw_pub_64) != 64:
        raise ValueError(f"Expected 64 bytes of uncompressed P-256 public key, got {len(raw_pub_64)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + raw_pub_64)


def derive_session_key(private_key: ec.EllipticCurvePrivateKey, peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Derives a 32-byte AES-256 session key from an ECDH exchange.

    Session key = SHA-256(shared_secret_x).
    """
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    shared_buf = bytearray(shared_secret)
    try:
        return hashlib.sha256(shared_buf).digest()
    finally:
        scrub_bytes(shared_buf)


def encrypt_payload_ecdh(
    token_public_key_raw: bytes,
    plaintext: bytes | bytearray,
    iv: bytes = IV_1,
) -> bytes:
    """Encrypts plaintext for Token2 device using ephemeral ECDH + AES-256-CBC (IV-1).

    Generates an ephemeral NIST P-256 keypair, performs ECDH with the token's
    public key, derives a 256-bit session key via SHA-256, applies PKCS#7 padding
    to the plaintext, and encrypts with AES-256-CBC.

    Args:
        token_public_key_raw: 64-byte raw public key of the token (X || Y).
        plaintext: Serialized payload to encrypt.
        iv: 16-byte initialization vector (defaults to Token2 IV-1).

    Returns:
        Encrypted block: 64 bytes uncompressed host public key + AES ciphertext.
    """
    token_pub_key = public_key_from_raw_bytes(token_public_key_raw)
    host_priv_key, host_pub_raw = generate_ecdh_keypair()

    session_key = derive_session_key(host_priv_key, token_pub_key)
    session_key_buf = bytearray(session_key)

    # PKCS#7 padding (block size 128 bits / 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(bytes(plaintext)) + padder.finalize()
    padded_buf = bytearray(padded_data)

    try:
        # AES-256-CBC encryption
        cipher = Cipher(algorithms.AES(bytes(session_key_buf)), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(bytes(padded_buf)) + encryptor.finalize()
    finally:
        scrub_bytes(session_key_buf)
        scrub_bytes(padded_buf)

    return host_pub_raw + ciphertext


def decrypt_payload_ecdh(
    token_private_key: ec.EllipticCurvePrivateKey,
    encrypted_block: bytes,
    iv: bytes = IV_1,
) -> bytes:
    """Decrypts an encrypted payload received by/from Token2.

    Extracts the 64-byte host public key from the header, derives the ECDH session key,
    and decrypts the AES-256-CBC ciphertext, removing PKCS#7 padding.

    Args:
        token_private_key: NIST P-256 private key.
        encrypted_block: 64 bytes host public key + AES ciphertext.
        iv: 16-byte initialization vector (defaults to Token2 IV-1).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If encrypted block is too short or padding is invalid.
    """
    if len(encrypted_block) < 80:  # 64 bytes pub key + at least 16 bytes AES block
        raise ValueError(f"Encrypted block too short ({len(encrypted_block)} bytes, minimum 80)")

    host_pub_raw = encrypted_block[:64]
    ciphertext = encrypted_block[64:]

    host_pub_key = public_key_from_raw_bytes(host_pub_raw)
    session_key = derive_session_key(token_private_key, host_pub_key)
    session_key_buf = bytearray(session_key)

    try:
        cipher = Cipher(algorithms.AES(bytes(session_key_buf)), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    finally:
        scrub_bytes(session_key_buf)

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()
