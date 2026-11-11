
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backend.app.security.upload_validation import (
    validate_upload
)


def make_associated_data(owner_user_id, filename):
    """
    Bind encrypted content to its owner and filename.
    This information is authenticated, not encrypted.
    """

    if (
        type(owner_user_id) is not int
        or owner_user_id < 1
    ):
        raise ValueError("Invalid owner user ID")

    if not isinstance(filename, str) or not filename:
        raise ValueError("Invalid filename")

    return (
        f"securevault-file-v1:{owner_user_id}:{filename}"
    ).encode("utf-8")


def encrypt_document(content, owner_user_id, filename):
    """
    Validate and encrypt a practice text document.

    Returns encrypted bytes and a random encryption key.
    This demonstration does not save them to disk.
    """

    # Reuse the Lesson 36 validation rules.
    validate_upload(filename, content)

    associated_data = make_associated_data(
        owner_user_id,
        filename
    )

    # Generate a fresh AES-256 key for this document.
    key = AESGCM.generate_key(bit_length=256)

    # Generate a fresh random 12-byte nonce.
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        content,
        associated_data
    )

    return {
        "key": key,
        "nonce": nonce,
        "ciphertext": ciphertext
    }


def decrypt_document(
    key,
    nonce,
    ciphertext,
    owner_user_id,
    filename
):
    """
    Decrypt a practice document.

    Decryption fails if the data, key, owner,
    filename or authentication tag is incorrect.
    """

    associated_data = make_associated_data(
        owner_user_id,
        filename
    )

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        associated_data
    )

    return plaintext
