"""
TLS 1.3 Cipher Suite Implementation using cryptography package.

This module implements a TLS 1.3 Cipher Suite with key schedule functions
using cryptography package instead of Python's built-in hmac.
"""

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CipherSuite:
    """
    Implementation of TLS 1.3 Cipher Suite with Key Schedule Functions.
    
    This class implements the cipher suite used in TLS 1.3 with key schedule functions:
    - HKDF-Extract
    - HKDF-Expand
    - HKDF-Expand-Label
    - Derive-Secret
    
    As defined in RFC 8446, Section 7.1.
    """
    
    def __init__(self, hash_alg, aead_alg, key_length=16, iv_length=12):
        """
        Initialize the CipherSuite with hash algorithm and AEAD algorithm.
        
        Args:
            hash_alg: A hash algorithm class from cryptography.hazmat.primitives.hashes
                      (e.g., hashes.SHA256)
            aead_alg: An AEAD algorithm class from cryptography.hazmat.primitives.ciphers.aead
                      (e.g., AESGCM)
            key_length: Length of the key in bytes (default is 16 bytes/128 bits, suitable for AES-128)
            iv_length: Length of the IV in bytes (default is 12 bytes/96 bits, as required for AEAD)
        """
        self.hash_alg = hash_alg
        self.aead_alg = aead_alg
        self.hash_len = hash_alg.digest_size        
        self.key_length = key_length
        self.iv_length = iv_length
    
    def hash_func(self, data):
        """
        計算輸入數據的哈希值，簡化調用方式。
        
        這是一個便利方法，讓調用者可以一步完成哈希計算，而不需要
        自己創建哈希實例、調用 update 和 finalize 方法。
        
        Args:
            data: 要計算哈希值的輸入數據（bytes）
            
        Returns:
            輸入數據的哈希值（bytes）
        """
        # 直接創建哈希實例，不使用 _create_hash_instance 方法
        digest = hashes.Hash(self.hash_alg())
        digest.update(data)
        return digest.finalize()
    
    def hmac_func(self, key, msg):
        """
        計算 HMAC (Hash-based Message Authentication Code)，簡化調用方式。
        
        這是一個便利方法，讓調用者可以一步完成 HMAC 計算。
        
        Args:
            key: 用於 HMAC 計算的密鑰（bytes）
            msg: 要驗證的消息數據（bytes）
        
        Returns:
            計算出的 HMAC 值（bytes）
        """
        # 移除 backend 參數
        h = hmac.HMAC(key, self.hash_alg())
        h.update(msg)
        return h.finalize()
    
    def HKDF_extract(self, salt, ikm):
        """
        HKDF-Extract function as defined in RFC 5869
        
        Args:
            salt: A non-secret random value used to extract entropy from ikm
                  If None or empty, it's replaced with a string of zeros
            ikm:  Input Keying Material (the secret input)
        
        Returns:
            A pseudorandom key (PRK) of Hash.length bytes
        """
        # If salt is not provided, set it to a string of zeros
        if salt is None or len(salt) == 0:
            salt = b'\x00' * self.hash_len
        
        # Extract: PRK = HMAC-Hash(salt, IKM)
        prk = self.hmac_func(salt, ikm)
        
        return prk
    
    def HKDF_expand(self, prk, info, length):
        """
        HKDF-Expand function as defined in RFC 5869
        
        Args:
            prk: A pseudorandom key of at least Hash.length bytes (usually, the output from extract)
            info: Optional context and application specific information (can be zero-length)
            length: Length of output keying material in octets (<= 255*Hash.length)
        
        Returns:
            Output keying material (OKM) of length bytes
        """
        # Check that requested length is not too large
        if length > 255 * self.hash_len:
            raise ValueError("Length too large (maximum is 255*Hash.length)")
        
        # Calculate number of iterations required
        n = (length + self.hash_len - 1) // self.hash_len  # Ceiling division
        
        # Initialize output and T(0)
        T = b""
        T_prev = b""
        okm = b""
        
        # Perform iterations
        for i in range(1, n + 1):
            # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
            counter = bytes([i])  # Ensure i is a single byte
            T = self.hmac_func(prk, T_prev + info + counter)
            T_prev = T
            okm += T
        
        # Return the first 'length' bytes of the output
        return okm[:length]
    
    def _create_hkdf_label(self, length, label, context):
        """
        Create the HkdfLabel structure as defined in TLS 1.3.
        
        struct {
            uint16 length;
            opaque label<7..255> = "tls13 " + Label;
            opaque context<0..255> = Context;
        } HkdfLabel;
        
        Args:
            length: Length of the output key material
            label: The label string (should be bytes)
            context: The context value (should be bytes)
            
        Returns:
            The encoded HkdfLabel structure
        """
        # Prepend "tls13 " to the label
        full_label = b"tls13 " + label
        
        # Construct the HkdfLabel structure
        # length as uint16 (2 bytes, big-endian)
        hkdf_label = length.to_bytes(2, byteorder='big')
        
        # label length as one byte followed by the label
        hkdf_label += bytes([len(full_label)]) + full_label
        
        # context length as one byte followed by the context
        hkdf_label += bytes([len(context)]) + context
        
        return hkdf_label
    
    def hkdf_expand_label(self, secret, label, context, length):
        """
        HKDF-Expand-Label function as defined in TLS 1.3.
        
        HKDF-Expand-Label(Secret, Label, Context, Length) =
             HKDF-Expand(Secret, HkdfLabel, Length)
             
        Args:
            secret: The secret key material
            label: The label string as bytes
            context: The context value as bytes
            length: Length of the output key material
            
        Returns:
            The derived key material of specified length
        """
        hkdf_label = self._create_hkdf_label(length, label, context)
        return self.HKDF_expand(secret, hkdf_label, length)
    
    def derive_secret(self, secret, label, messages):
        """
        Derive-Secret function as defined in TLS 1.3.
        
        Derive-Secret(Secret, Label, Messages) =
             HKDF-Expand-Label(Secret, Label,
                              Transcript-Hash(Messages), Hash.length)
                              
        Args:
            secret: The secret key material
            label: The label string as bytes
            messages: The transcript messages to be hashed
            
        Returns:
            The derived secret of hash length
        """
        # 使用 hash_func 簡化哈希計算
        transcript_hash = self.hash_func(messages)
        
        # Call HKDF-Expand-Label with the transcript hash as context
        return self.hkdf_expand_label(secret, label, transcript_hash, self.hash_len)
        
    def traffic_key_and_iv(self, traffic_secret):
        """
        Traffic Key Calculation as defined in TLS 1.3 (RFC 8446, Section 7.3).
        
        [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
        [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
        
        Args:
            traffic_secret: The traffic secret (e.g., client_handshake_traffic_secret)
            
        Returns:
            A tuple of (key, iv) derived from the traffic secret
        """
        # Generate the traffic key
        key = self.hkdf_expand_label(traffic_secret, b"key", b"", self.key_length)
        
        # Generate the traffic IV
        iv = self.hkdf_expand_label(traffic_secret, b"iv", b"", self.iv_length)
        
        return key, iv
    
    def create_aead_encryptor(self, key):
        """
        Creates an AEAD encryptor using the specified key.
        
        Args:
            key: The encryption key for the AEAD cipher
            
        Returns:
            An AEAD cipher instance from cryptography
        """
        return self.aead_alg(key)    

# 預定義的密碼套件實例，方便直接導入
# TLS_AES_128_GCM_SHA256 為 TLS 1.3 中定義的標準密碼套件，使用:
# - SHA-256 做為哈希算法
# - AES-GCM 做為 AEAD 加密算法，使用 128 位元密鑰
# - 96 位元初始向量
TLS_AES_128_GCM_SHA256 = CipherSuite(hashes.SHA256, AESGCM, key_length=16, iv_length=12)
