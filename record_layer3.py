from common import ContentType, TypeAndBytes, LEGACY_RECORD_VERSION

class RecordLayer:
    def __init__(self, read_bytes_func):
        self.read_bytes_func = read_bytes_func
        self.record_decryptor = None
        self.left_over = None
        self.allow_change_cipher_spec = True # for client side  TODO: server side

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

    def set_record_decryptor(self, record_decryptor):
        if self.left_over is not None:
            raise ValueError("Cannot set record decryptor while left_over is not None")
        self.record_decryptor = record_decryptor

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
            record = record_layer.read_plaintext()
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

    def read_without_change_cipher_spec(self):        
        while True:
            record = self.read_reassembled()
            if record.content_type != ContentType.CHANGE_CIPHER_SPEC:
                if record.content_type == ContentType.HANDSHAKE and record.data[0] == 20: # peer Finished
                    self.allow_change_cipher_spec = False
                return record
            else:
                if not self.allow_change_cipher_spec:
                    raise ValueError("Unexpected CHANGE_CIPHER_SPEC message")
                else:
                    if record.data != b'\x01':
                        raise ValueError("Invalid CHANGE_CIPHER_SPEC message")
                    # MUST simply drop it without further processing
    
    def read(self):
        return self.read_without_change_cipher_spec()

class RecordDecryptor:
    AAD_PREFIX = bytes([ContentType.APPLICATION_DATA]) + LEGACY_RECORD_VERSION.to_bytes(2, byteorder='big')
    def __init__(self, traffic_secret, hkdf_expand_label, aead_class, key_length, iv_length):
        key = hkdf_expand_label(traffic_secret, b"key", b"", key_length)
        self.aead = aead_class(key)
        self.iv = hkdf_expand_label(traffic_secret, b"iv", b"", iv_length)
        self.seq = 0

    def decrypt(self, ciphertext):
        padded_seq = self.seq.to_bytes(len(self.iv), 'big')
        self.seq += 1
        nonce = bytes(a ^ b for a, b in zip(self.iv, padded_seq))
        aad = self.AAD_PREFIX + len(ciphertext).to_bytes(2, byteorder='big')
        decrypted = self.aead.decrypt(nonce, ciphertext, aad)
        return decrypted


if __name__ == "__main__":
    import sys
    def read_bytes(n):
        data = sys.stdin.buffer.read(n)
        if (len(data) < n):
            raise ValueError("Not enough data")
        return data
    
    def show(record):
        print(f"ContentType: {record.content_type}, Length: {len(record.data)}, Data: {record.data.hex()}")

    record_layer = RecordLayer(read_bytes)
    record = record_layer.read()
    show(record) # ServerHello
    
    from key_schedule_functions import KeyScheduleFunctions
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import hashlib

    print("====" * 10)
    record_decryptor = RecordDecryptor(
        traffic_secret=bytes.fromhex("9c0e9fbd6b130655ddd885bca6777cbb64f43f0882d2988caaf617a911dc5899"),
        hkdf_expand_label=KeyScheduleFunctions(hashlib.sha256).hkdf_expand_label,
        aead_class=AESGCM,
        key_length=16,
        iv_length=12
    )
    record_layer.set_record_decryptor(record_decryptor)

    for i in range(4):
        record = record_layer.read()
        show(record)

    print("====" * 10)
    record_decryptor = RecordDecryptor(
        traffic_secret=bytes.fromhex("acf8dd4819144487a198b3ec89264f5253e586d0e9983fde08f81e826416f1e2"),
        hkdf_expand_label=KeyScheduleFunctions(hashlib.sha256).hkdf_expand_label,
        aead_class=AESGCM,
        key_length=16,
        iv_length=12
    )
    record_layer.set_record_decryptor(record_decryptor)

    for i in range(3):
        record = record_layer.read()
        show(record)