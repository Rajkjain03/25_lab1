from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
import hashlib
import hmac as hmac_lib

def pkcs7_pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding length")
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding")
    return data[:-padding_length]

def aes_cbc_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pkcs7_pad(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def aes_cbc_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded_plaintext)

def hmac_sha256(key, message):
    hmac = HMAC.new(key, msg=message, digestmod=SHA256)
    return hmac.digest()

# ======================== Additional Required Functions ========================

def generate_nonce(size=16):
    """
    Generate cryptographically secure random nonce/IV.
    
    Args:
        size (int): Size of nonce in bytes (default: 16 for AES)
        
    Returns:
        bytes: Random nonce
    """
    return get_random_bytes(size)


def encrypt(plaintext, enc_key, mac_key):
    """
    Complete encryption procedure:
    1. Apply PKCS#7 padding (done in aes_cbc_encrypt)
    2. Generate random IV
    3. Encrypt with AES-128-CBC
    4. Compute HMAC over (IV || Ciphertext)
    
    Args:
        plaintext (bytes): Data to encrypt
        enc_key (bytes): 16-byte encryption key
        mac_key (bytes): HMAC key
        
    Returns:
        tuple: (iv, ciphertext, hmac_tag)
    """
    # Generate random IV
    iv = generate_nonce(16)
    
    # Encrypt (padding is done inside aes_cbc_encrypt)
    ciphertext = aes_cbc_encrypt(plaintext, enc_key, iv)
    
    # Compute HMAC over IV || Ciphertext
    hmac_tag = hmac_sha256(mac_key, iv + ciphertext)
    
    return iv, ciphertext, hmac_tag


def decrypt(iv, ciphertext, hmac_tag, enc_key, mac_key):
    """
    Complete decryption procedure:
    1. Verify HMAC (BEFORE decryption)
    2. Decrypt ciphertext
    3. Remove PKCS#7 padding (done in aes_cbc_decrypt)
    
    Args:
        iv (bytes): 16-byte initialization vector
        ciphertext (bytes): Encrypted data
        hmac_tag (bytes): HMAC tag to verify
        enc_key (bytes): 16-byte encryption key
        mac_key (bytes): HMAC key
        
    Returns:
        bytes: Original plaintext
        
    Raises:
        ValueError: If HMAC verification fails or padding is invalid
    """
    # Verify HMAC BEFORE decryption
    if not hmac_verify(mac_key, iv + ciphertext, hmac_tag):
        raise ValueError("HMAC verification failed - message tampered or replayed")
    
    # Decrypt (unpadding is done inside aes_cbc_decrypt)
    plaintext = aes_cbc_decrypt(ciphertext, enc_key, iv)
    
    return plaintext


def hmac_verify(key, data, expected_hmac):
    """
    Verify HMAC-SHA256 tag using constant-time comparison.
    
    Args:
        key (bytes): HMAC key
        data (bytes): Data to authenticate
        expected_hmac (bytes): Expected HMAC tag
        
    Returns:
        bool: True if HMAC is valid, False otherwise
    """
    if not isinstance(expected_hmac, bytes):
        return False
    
    computed = hmac_sha256(key, data)
    
    # Use constant-time comparison to prevent timing attacks
    return hmac_lib.compare_digest(computed, expected_hmac)


# ======================== Key Derivation Functions ========================

def derive_key(master_key, label):
    """
    Derive a key from master key using label.
    H(K_i || label)
    
    Args:
        master_key (bytes): Master key
        label (str or bytes): Label for key derivation
        
    Returns:
        bytes: Derived key (32 bytes from SHA-256)
    """
    if isinstance(label, str):
        label = label.encode('utf-8')
    
    return hashlib.sha256(master_key + label).digest()


def evolve_key(current_key, data):
    """
    Evolve key using current key and data.
    Implements key ratcheting: H(current_key || data)
    
    Args:
        current_key (bytes): Current key
        data (bytes): Data to mix into key evolution
        
    Returns:
        bytes: New evolved key (32 bytes from SHA-256)
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return hashlib.sha256(current_key + data).digest()


def hash_data(data):
    """
    Compute SHA-256 hash of data.
    
    Args:
        data (bytes): Data to hash
        
    Returns:
        bytes: 32-byte hash
    """
    return hashlib.sha256(data).digest()