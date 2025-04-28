from common import ContentType, TypeAndBytes, LEGACY_RECORD_VERSION_BYTES

class RecordLayer:
    def __init__(self, cipher_suite, read_bytes_func, write_bytes_func, allow_change_cipher_spec=False):
        self.cipher_suite = cipher_suite
        self.read_bytes_func = read_bytes_func
        self.record_decryptor = None
        self.left_over = None
        self.allow_change_cipher_spec = allow_change_cipher_spec

        self.write_bytes_func = write_bytes_func
        self.record_encryptor = None        

    def set_cipher_suite(self, cipher_suite):
        self.cipher_suite = cipher_suite

    def read_record(self):
        header = self.read_bytes_func(5)
        content_type = header[0]
        length = (header[3] << 8) | header[4]

        if content_type in (ContentType.CHANGE_CIPHER_SPEC, ContentType.ALERT, ContentType.HANDSHAKE):
            if length > 16384:
                raise ValueError(f"Invalid TLSPlaintext length: {length} > 2^14")
        elif content_type == ContentType.APPLICATION_DATA:
            if length > 16384 + 256:
                raise ValueError(f"Invalid TLSCiphertext length: {length} > 2^14 + 256")
        else:
            raise ValueError(f"Invalid content type: {content_type}")
        
        return TypeAndBytes(content_type, self.read_bytes_func(length))

    def set_encryption_secret(self, traffic_secret):
        self.record_encryptor = RecordEncryptor(traffic_secret, self.cipher_suite)

    def set_decryption_secret(self, traffic_secret):
        if self.left_over is not None:
            raise ValueError("Cannot set record decryptor while left_over is not None")
        self.record_decryptor = RecordDecryptor(traffic_secret, self.cipher_suite)

    def read_plaintext(self):
        record = self.read_record()

        if self.record_decryptor is None:
            if record.content_type == ContentType.APPLICATION_DATA:
                raise ValueError("Unexpected APPLICATION_DATA message")
            return record
        else:
            # "... it is necessary to detect this condition prior to attempting to deprotect the record."
            if record.content_type == ContentType.CHANGE_CIPHER_SPEC:
                return record

            if record.content_type != ContentType.APPLICATION_DATA:
                raise ValueError(f"Unexpected content type: {record.content_type}")
            inner_plaintext = self.record_decryptor.decrypt(record.data)

            for i in range(len(inner_plaintext) - 1, -1, -1):
                if inner_plaintext[i] != 0:
                    content_type = inner_plaintext[i]
                    content = inner_plaintext[:i]
                    break
            else:
                raise ValueError("Invalid padding: no content-type byte found")

            # "... receives a protected change_cipher_spec record MUST abort the handshake with an "unexpected_message" alert"
            if content_type == ContentType.CHANGE_CIPHER_SPEC:
                raise ValueError("Unexpected CHANGE_CIPHER_SPEC in decrypted data")

            return TypeAndBytes(content_type, content)
        
    def read_reassembled(self):
        assert self.left_over is None or (self.left_over.content_type == ContentType.HANDSHAKE and self.left_over.bytes_available() > 0)

        if self.left_over is None:
            record = self.read_plaintext()
            if record.content_type != ContentType.HANDSHAKE:
                return record
        else:
            record = self.left_over

        # Now we have a handshake record. Any additional records we read are expected to be HANDSHAKE records.
        header, record = self._read_n_bytes(record, 4)
        length = int.from_bytes(header[1:4], 'big') # we may add our own length constraint
        body, record = self._read_n_bytes(record, length)
        
        self.left_over = record if record.bytes_available() > 0 else None
        return TypeAndBytes(ContentType.HANDSHAKE, header + body)

    def _read_n_bytes(self, record, n):
        result = b''
        while True:
            result += record.read_n_bytes(n - len(result))
            if len(result) < n:
                record = self.read_plaintext()
                if record.content_type != ContentType.HANDSHAKE:
                    raise ValueError("Handshake messages MUST NOT be interleaved with other record types.")
            else:
                break
        return result, record

    def read_drop_change_cipher_spec(self):        
        while True:
            record = self.read_reassembled()
            if record.content_type != ContentType.CHANGE_CIPHER_SPEC:
                return record
            else:
                if not self.allow_change_cipher_spec:
                    raise ValueError("Unexpected CHANGE_CIPHER_SPEC message")
                else:
                    if record.data != b'\x01':
                        raise ValueError("Invalid CHANGE_CIPHER_SPEC message")
                    # MUST simply drop it without further processing

    def set_allow_change_cipher_spec(self, value):
        self.allow_change_cipher_spec = value
                 
    def read(self):
        return self.read_drop_change_cipher_spec()

    # I trust the writer    
    def write(self, type_and_bytes):
        if self.record_encryptor is None:
            self.write_bytes_func(bytes([type_and_bytes.content_type]) + LEGACY_RECORD_VERSION_BYTES + len(type_and_bytes.data).to_bytes(2, 'big') + type_and_bytes.data)
        else:
            inner = type_and_bytes.data + bytes([type_and_bytes.content_type])
            ciphertext = self.record_encryptor.encrypt(inner)
            self.write_bytes_func(bytes([ContentType.APPLICATION_DATA]) + LEGACY_RECORD_VERSION_BYTES + len(ciphertext).to_bytes(2, 'big') + ciphertext)


class RecordDecryptor:
    AAD_PREFIX = bytes([ContentType.APPLICATION_DATA]) + LEGACY_RECORD_VERSION_BYTES
    def __init__(self, traffic_secret, cipher_suite):
        key = cipher_suite.hkdf_expand_label(traffic_secret, b"key", b"", cipher_suite.key_length)
        self.aead = cipher_suite.create_aead_encryptor(key)
        self.iv = cipher_suite.hkdf_expand_label(traffic_secret, b"iv", b"", cipher_suite.iv_length)
        self.seq = 0

    def decrypt(self, ciphertext):
        padded_seq = self.seq.to_bytes(len(self.iv), 'big')
        self.seq += 1
        nonce = bytes(a ^ b for a, b in zip(self.iv, padded_seq))
        aad = self.AAD_PREFIX + len(ciphertext).to_bytes(2, byteorder='big')
        decrypted = self.aead.decrypt(nonce, ciphertext, aad)
        return decrypted

class RecordEncryptor:
    AAD_PREFIX = bytes([ContentType.APPLICATION_DATA]) + LEGACY_RECORD_VERSION_BYTES
    def __init__(self, traffic_secret, cipher_suite):
        key = cipher_suite.hkdf_expand_label(traffic_secret, b"key", b"", cipher_suite.key_length)
        self.aead = cipher_suite.create_aead_encryptor(key)
        self.iv = cipher_suite.hkdf_expand_label(traffic_secret, b"iv", b"", cipher_suite.iv_length)
        self.tag_length = cipher_suite.tag_length
        self.seq = 0

    def encrypt(self, plaintext):
        padded_seq = self.seq.to_bytes(len(self.iv), 'big')
        self.seq += 1
        nonce = bytes(a ^ b for a, b in zip(self.iv, padded_seq))
        aad = self.AAD_PREFIX + (len(plaintext) + self.tag_length).to_bytes(2, byteorder='big')
        ciphertext = self.aead.encrypt(nonce, plaintext, aad)
        if (len(ciphertext) > 16384 + 256):
            raise ValueError(f"Invalid ciphertext length: {len(ciphertext)} > 2^14 + 256")
        return ciphertext
    