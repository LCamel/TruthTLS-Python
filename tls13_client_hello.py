"""
TLS 1.3 ClientHello Generator.

This module implements a minimal TLS 1.3 ClientHello message generator according
to RFC 8446 and the requirements in tls13_minimal_client_hello.txt.
"""

import struct
import secrets

# Constants for TLS record types and versions
TLS_RECORD_TYPE_HANDSHAKE = 22
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 1

# Legacy versions
TLS_VERSION_1_0 = 0x0301  # For record header
TLS_VERSION_1_2 = 0x0303  # For legacy_version field
TLS_VERSION_1_3 = 0x0304  # For supported_versions extension

# Cipher suite
TLS_AES_256_GCM_SHA384 = bytes([0x13, 0x01])

# Extension types
EXT_SUPPORTED_VERSIONS = 0x002b
EXT_SUPPORTED_GROUPS = 0x000a
EXT_SIGNATURE_ALGORITHMS = 0x000d
EXT_KEY_SHARE = 0x0033

# Supported group identifiers
GROUP_SECP256R1 = 0x0017

# Signature algorithms
SIG_ECDSA_SECP256R1_SHA256 = 0x0403  # ecdsa_secp256r1_sha256
SIG_RSA_PSS_RSAE_SHA256 = 0x0804     # rsa_pss_rsae_sha256
SIG_RSA_PKCS1_SHA256 = 0x0401        # rsa_pkcs1_sha256


def generate_client_hello(public_key_bytes):
    """
    Generate a TLS 1.3 ClientHello message.
    
    Args:
        public_key_bytes: The secp256r1 public key as bytes
        
    Returns:
        The complete TLS record containing the ClientHello message as bytes
    """
    # Generate 32 bytes of pure random data using cryptographically secure RNG
    random_data = secrets.token_bytes(32)
    
    # Generate 32 bytes for session ID using cryptographically secure RNG
    session_id = secrets.token_bytes(32)
    
    # Construct ClientHello body
    client_hello_body = _create_client_hello_body(random_data, session_id, public_key_bytes)
    
    # Add handshake header
    handshake_message = _add_handshake_header(client_hello_body)
    
    # Add TLS record header
    tls_record = _add_record_header(handshake_message)
    
    return tls_record


def _create_client_hello_body(random_data, session_id, public_key_bytes):
    """
    Create the body of the ClientHello message.
    
    Args:
        random_data: 32 bytes of random data
        session_id: 32 bytes of session ID
        public_key_bytes: The public key for the key_share extension
        
    Returns:
        The ClientHello body as bytes
    """
    # legacy_version (2 bytes, TLS 1.2)
    body = struct.pack('!H', TLS_VERSION_1_2)
    
    # random (32 bytes)
    body += random_data
    
    # legacy_session_id (1 byte length + ID)
    body += bytes([len(session_id)]) + session_id
    
    # cipher_suites (2 bytes length + ciphers)
    cipher_suites = TLS_AES_256_GCM_SHA384
    body += struct.pack('!H', len(cipher_suites)) + cipher_suites
    
    # compression_methods (1 byte length + methods)
    body += bytes([1, 0])  # 1 method, value 0 (no compression)
    
    # Extensions
    extensions = _create_extensions(public_key_bytes)
    
    # Add extensions length (2 bytes) + extensions content
    body += struct.pack('!H', len(extensions)) + extensions
    
    return body


def _create_extensions(public_key_bytes):
    """
    Create all required extensions for the ClientHello.
    
    Args:
        public_key_bytes: The public key for the key_share extension
        
    Returns:
        All concatenated extensions as bytes
    """
    extensions = b''
    
    # 1. supported_versions extension
    extensions += _create_supported_versions_extension()
    
    # 2. supported_groups extension
    extensions += _create_supported_groups_extension()
    
    # 3. signature_algorithms extension
    extensions += _create_signature_algorithms_extension()
    
    # 4. key_share extension
    extensions += _create_key_share_extension(public_key_bytes)
    
    return extensions


def _create_supported_versions_extension():
    """
    Create the supported_versions extension indicating TLS 1.3 support.
    
    Returns:
        The encoded extension as bytes
    """
    # Extension type
    ext = struct.pack('!H', EXT_SUPPORTED_VERSIONS)
    
    # Extension data length (2 bytes)
    ext_data = bytes([2, TLS_VERSION_1_3 >> 8, TLS_VERSION_1_3 & 0xFF])
    ext += struct.pack('!H', len(ext_data)) + ext_data
    
    return ext


def _create_supported_groups_extension():
    """
    Create the supported_groups extension with secp256r1.
    
    Returns:
        The encoded extension as bytes
    """
    # Extension type
    ext = struct.pack('!H', EXT_SUPPORTED_GROUPS)
    
    # Extension data: list of supported groups
    groups = struct.pack('!H', GROUP_SECP256R1)  # secp256r1
    ext_data = struct.pack('!H', len(groups)) + groups
    
    # Extension data length
    ext += struct.pack('!H', len(ext_data)) + ext_data
    
    return ext


def _create_signature_algorithms_extension():
    """
    Create the signature_algorithms extension.
    
    Returns:
        The encoded extension as bytes
    """
    # Extension type
    ext = struct.pack('!H', EXT_SIGNATURE_ALGORITHMS)
    
    # Extension data: list of signature algorithms
    sig_algs = struct.pack('!HHH', 
                         SIG_ECDSA_SECP256R1_SHA256, 
                         SIG_RSA_PSS_RSAE_SHA256, 
                         SIG_RSA_PKCS1_SHA256)
    ext_data = struct.pack('!H', len(sig_algs)) + sig_algs
    
    # Extension data length
    ext += struct.pack('!H', len(ext_data)) + ext_data
    
    return ext


def _create_key_share_extension(public_key_bytes):
    """
    Create the key_share extension with the provided public key.
    
    Args:
        public_key_bytes: The public key to include in the key_share extension
        
    Returns:
        The encoded extension as bytes
    """
    # Extension type
    ext = struct.pack('!H', EXT_KEY_SHARE)
    
    # Create key share entry
    key_share_entry = struct.pack('!H', GROUP_SECP256R1)  # Group: secp256r1
    key_share_entry += struct.pack('!H', len(public_key_bytes)) + public_key_bytes
    
    # Create client_shares
    client_shares = struct.pack('!H', len(key_share_entry)) + key_share_entry
    
    # Extension data length
    ext += struct.pack('!H', len(client_shares)) + client_shares
    
    return ext


def _add_handshake_header(client_hello_body):
    """
    Add handshake header to the ClientHello body.
    
    Args:
        client_hello_body: The ClientHello body as bytes
        
    Returns:
        The complete handshake message as bytes
    """
    handshake_type = bytes([TLS_HANDSHAKE_TYPE_CLIENT_HELLO])
    handshake_length = struct.pack('!I', len(client_hello_body))[1:]  # 3 bytes, drop the first byte
    
    return handshake_type + handshake_length + client_hello_body


def _add_record_header(handshake_message):
    """
    Add TLS record header to the handshake message.
    
    Args:
        handshake_message: The handshake message as bytes
        
    Returns:
        The complete TLS record as bytes
    """
    record_type = bytes([TLS_RECORD_TYPE_HANDSHAKE])
    record_version = struct.pack('!H', TLS_VERSION_1_0)  # Legacy version 1.0 for maximum compatibility
    record_length = struct.pack('!H', len(handshake_message))
    
    return record_type + record_version + record_length + handshake_message


if __name__ == "__main__":
    # Example: Generate a ClientHello with a dummy public key (for testing)
    dummy_public_key = secrets.token_bytes(65)  # Typical size for a secp256r1 public key
    client_hello = generate_client_hello(dummy_public_key)
    
    print(f"Generated ClientHello message of {len(client_hello)} bytes")
    print("Hex dump of first 32 bytes:")
    print(' '.join(f'{b:02x}' for b in client_hello[:32]))