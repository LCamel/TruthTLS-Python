"""
TLS 1.3 Message Layer implementation

This module provides a MessageLayer class that handles the conversion between 
TLS messages and TLS records, including encryption and decryption.
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from record_layer import RecordLayer, RECORD_TYPE_HANDSHAKE, RECORD_TYPE_APPLICATION_DATA, RECORD_TYPE_ALERT, TLS_VERSION

# Constants for TLS 1.3 record protection
TLS13_CONTENT_TYPE_HANDSHAKE = 0x16
TLS13_CONTENT_TYPE_APPLICATION_DATA = 0x17
TLS13_CONTENT_TYPE_ALERT = 0x15

class MessageLayer:
    """
    TLS 1.3 Message Layer implementation.
    
    This class serves as an intermediary between the application and the RecordLayer,
    handling the conversion between TLS messages and TLS records, including
    encryption and decryption of protected TLS 1.3 records.
    """
    
    def __init__(self, record_layer):
        """
        Initialize the message layer with a RecordLayer object.
        
        Args:
            record_layer (RecordLayer): A RecordLayer object
        """
        self.record_layer = record_layer
        self.write_key = None
        self.peer_write_key = None
        self.write_iv = None
        self.peer_write_iv = None
        self.is_encrypted = False
        
        # Sequence numbers for AEAD nonce calculation
        self.write_seq_num = 0
        self.read_seq_num = 0
        
        # Key and IV sizes for AES-GCM
        self.key_size = 16  # 16 bytes (128 bits) for AES-128-GCM
        self.iv_size = 12   # 12 bytes (96 bits) for AES-GCM
        
        # Debug flag
        self.debug = True
    
    def write_handshake(self, data):
        """
        Write a handshake message to the underlying RecordLayer.
        
        Args:
            data (bytes): The handshake message data
        """
        if not self.is_encrypted or self.write_key is None:
            # If encryption is not enabled yet, write plaintext
            self.record_layer.write_handshake(data)
        else:
            # Encrypt the handshake message
            encrypted_data = self._encrypt_data(data, TLS13_CONTENT_TYPE_HANDSHAKE)
            self.record_layer.write_record(RECORD_TYPE_APPLICATION_DATA, encrypted_data)
            self.write_seq_num += 1
    
    def read_message(self):
        """
        Read a TLS message from the underlying RecordLayer.
        
        Returns:
            tuple: (content_type, data) where content_type is an integer and data is bytes
        """
        content_type, data = self.record_layer.read_record()
        
        # Handle decryption for encrypted messages
        if self.is_encrypted and self.peer_write_key is not None:
            # In TLS 1.3, all encrypted records use the application_data content type
            if content_type == RECORD_TYPE_APPLICATION_DATA:
                try:
                    if self.debug:
                        print(f"Attempting to decrypt {len(data)} bytes of data with seq_num={self.read_seq_num}")
                    
                    # Attempt to decrypt the record
                    original_type, plaintext = self._decrypt_data(data)
                    
                    if self.debug:
                        print(f"Successfully decrypted to type {original_type} ({len(plaintext)} bytes)")
                    
                    self.read_seq_num += 1
                    return original_type, plaintext
                except Exception as e:
                    if self.debug:
                        print(f"Decryption error details: {str(e)}")
                        print(f"Encrypted record: {data[:20]}... (total {len(data)} bytes)")
                        print(f"Using key: {self.peer_write_key.hex()[:16]}...")
                        print(f"Using IV: {self.peer_write_iv.hex()}")
                    
                    # Return as-is if decryption fails
                    return content_type, data
            
        return content_type, data
    
    def set_keys(self, client_traffic_secret, server_traffic_secret, key_schedule=None):
        """
        Set the encryption/decryption keys and IVs for this message layer.
        
        Args:
            client_traffic_secret: The client traffic secret
            server_traffic_secret: The server traffic secret
            key_schedule: Optional KeySchedule object to use for key derivation
        """
        # We need to derive actual encryption keys and IVs from the traffic secrets
        # If key_schedule is provided, use its key_funcs for derivation
        if key_schedule:
            if self.debug:
                print(f"Deriving keys using key_schedule")
                print(f"Client traffic secret: {client_traffic_secret.hex()[:16]}...")
                print(f"Server traffic secret: {server_traffic_secret.hex()[:16]}...")
                
            # Client key used for client->server messages
            client_key = key_schedule.key_funcs.hkdf_expand_label(
                client_traffic_secret, 
                b"key", 
                b"", 
                self.key_size
            )
            
            # Client IV used for client->server messages
            client_iv = key_schedule.key_funcs.hkdf_expand_label(
                client_traffic_secret,
                b"iv",
                b"",
                self.iv_size
            )
            
            # Server key used for server->client messages
            server_key = key_schedule.key_funcs.hkdf_expand_label(
                server_traffic_secret,
                b"key",
                b"",
                self.key_size
            )
            
            # Server IV used for server->client messages
            server_iv = key_schedule.key_funcs.hkdf_expand_label(
                server_traffic_secret,
                b"iv",
                b"",
                self.iv_size
            )
            
            if self.debug:
                print(f"Derived client key: {client_key.hex()}")
                print(f"Derived client IV: {client_iv.hex()}")
                print(f"Derived server key: {server_key.hex()}")
                print(f"Derived server IV: {server_iv.hex()}")
        else:
            # Basic implementation if no key_schedule is provided
            # Truncate or pad secrets to desired length (not secure, just for testing)
            client_key = client_traffic_secret[:self.key_size] + b'\x00' * max(0, self.key_size - len(client_traffic_secret))
            client_iv = client_traffic_secret[:self.iv_size] + b'\x00' * max(0, self.iv_size - len(client_traffic_secret))
            server_key = server_traffic_secret[:self.key_size] + b'\x00' * max(0, self.key_size - len(server_traffic_secret))
            server_iv = server_traffic_secret[:self.iv_size] + b'\x00' * max(0, self.iv_size - len(server_traffic_secret))
        
        # For a client, write_key = client_key, peer_write_key = server_key
        self.write_key = client_key
        self.write_iv = client_iv
        self.peer_write_key = server_key
        self.peer_write_iv = server_iv
        
        # Reset sequence numbers
        self.write_seq_num = 0
        self.read_seq_num = 0
        
        self.is_encrypted = True
    
    def disable_encryption(self):
        """
        Disable encryption for testing or specific message types.
        """
        self.is_encrypted = False
    
    def _encrypt_data(self, data, content_type):
        """
        Encrypt data using AES-GCM as specified in TLS 1.3.
        
        Args:
            data (bytes): The plaintext data to encrypt
            content_type (int): The original content type
            
        Returns:
            bytes: The encrypted data including authentication tag
        """
        if not self.is_encrypted or self.write_key is None:
            raise ValueError("Encryption not configured")
        
        if self.debug:
            print(f"\nENCRYPTING DATA:")
            print(f"- Data length: {len(data)} bytes")
            print(f"- Content type: {content_type}")
            print(f"- Write sequence number: {self.write_seq_num}")
            print(f"- Using key: {self.write_key.hex()}")
            print(f"- Using IV: {self.write_iv.hex()}")
        
        # Create nonce from write_iv and sequence number
        # XOR the right-most bytes of the IV with the sequence number
        nonce = bytearray(self.write_iv)
        seq_num_bytes = self.write_seq_num.to_bytes(8, byteorder='big')
        for i in range(8):
            nonce[4 + i] ^= seq_num_bytes[i]
            
        if self.debug:
            print(f"- Calculated nonce: {bytes(nonce).hex()}")
        
        # In TLS 1.3, the additional authenticated data (AAD) is the TLS record header
        # TLSCiphertext.opaque_type + TLSCiphertext.legacy_record_version + TLSCiphertext.length
        # For TLS 1.3, the length in AAD must include content_type (1 byte) and auth tag (16 bytes)
        record_type_byte = bytes([RECORD_TYPE_APPLICATION_DATA])
        length_bytes = struct.pack("!H", len(data) + 1 + 16)  # data + content_type + auth_tag
        aad = record_type_byte + TLS_VERSION + length_bytes
        
        if self.debug:
            print(f"- AAD: {aad.hex()}")
            print(f"  - Record type: {record_type_byte.hex()}")
            print(f"  - TLS version: {TLS_VERSION.hex()}")
            print(f"  - Length bytes: {length_bytes.hex()} (for {len(data) + 1 + 16} bytes)")
        
        # The TLS 1.3 format for encrypted records is:
        # 1. Plaintext content
        # 2. 1-byte content type (the real one, not the outer "application_data" type)
        # 3. Padding (optional, all zeros) - not adding padding for simplicity
        plaintext = data + bytes([content_type])
        
        if self.debug:
            print(f"- Plaintext to encrypt: {plaintext[:20].hex()}... (total {len(plaintext)} bytes)")
        
        # Encrypt using AES-GCM
        aes_gcm = AESGCM(self.write_key)
        ciphertext = aes_gcm.encrypt(bytes(nonce), plaintext, aad)
        
        if self.debug:
            print(f"- Encrypted result: {ciphertext[:20].hex()}... (total {len(ciphertext)} bytes)")
            print(f"  - Auth tag (last 16 bytes): {ciphertext[-16:].hex()}")
            print()
        
        return ciphertext
    
    def _decrypt_data(self, ciphertext):
        """
        Decrypt data using AES-GCM as specified in TLS 1.3.
        
        Args:
            ciphertext (bytes): The encrypted data including authentication tag
            
        Returns:
            tuple: (original_content_type, plaintext) without the content type byte
        """
        if not self.is_encrypted or self.peer_write_key is None:
            raise ValueError("Decryption not configured")
        
        # Create nonce from peer_write_iv and sequence number
        nonce = bytearray(self.peer_write_iv)
        seq_num_bytes = self.read_seq_num.to_bytes(8, byteorder='big')
        for i in range(8):
            nonce[4 + i] ^= seq_num_bytes[i]
        
        # In TLS 1.3, the additional authenticated data (AAD) is the TLS record header
        # TLSCiphertext.opaque_type + TLSCiphertext.legacy_record_version + TLSCiphertext.length
        record_type_byte = bytes([RECORD_TYPE_APPLICATION_DATA])
        length_bytes = struct.pack("!H", len(ciphertext))
        aad = record_type_byte + TLS_VERSION + length_bytes
        
        if self.debug:
            print(f"Decrypting with nonce: {bytes(nonce).hex()}")
            print(f"AAD: {aad.hex()}")
        
        # Decrypt using AES-GCM
        try:
            aes_gcm = AESGCM(self.peer_write_key)
            decrypted = aes_gcm.decrypt(bytes(nonce), ciphertext, aad)
            
            # The last byte is the original content type
            original_content_type = decrypted[-1]
            plaintext = decrypted[:-1]  # Remove the content type byte
            
            # Map TLS 1.3 content types to record layer types
            if original_content_type == TLS13_CONTENT_TYPE_HANDSHAKE:
                return RECORD_TYPE_HANDSHAKE, plaintext
            elif original_content_type == TLS13_CONTENT_TYPE_APPLICATION_DATA:
                return RECORD_TYPE_APPLICATION_DATA, plaintext
            elif original_content_type == TLS13_CONTENT_TYPE_ALERT:
                return RECORD_TYPE_ALERT, plaintext
            else:
                # Unknown content type, return as-is
                if self.debug:
                    print(f"Unrecognized content type in decrypted data: {original_content_type}")
                return original_content_type, plaintext
                
        except Exception as e:
            if self.debug:
                print(f"Decryption exception details: {e.__class__.__name__}: {str(e)}")
            raise