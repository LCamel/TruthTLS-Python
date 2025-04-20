from common import ContentType, TypeAndBytes, LEGACY_RECORD_VERSION

class RecordLayer:
    def __init__(self, read_bytes):
        self.read_bytes = read_bytes
        self.record_decryptor = None

    def read_record(self):
        # Read record header (5 bytes: type[1] + version[2] + length[2])
        header = self.read_bytes(5)
        if len(header) < 5:
            raise ValueError("Incomplete TLS record header")

        # Parse header
        content_type = header[0]
        version = (header[1] << 8) | header[2]
        length = (header[3] << 8) | header[4]

        # Check if content_type is valid
        if content_type not in [
            ContentType.CHANGE_CIPHER_SPEC,
            ContentType.ALERT,
            ContentType.HANDSHAKE,
            ContentType.APPLICATION_DATA
        ]:
            raise ValueError(f"Invalid content type: {content_type}")

        # Read record data
        data = self.read_bytes(length)
        if len(data) < length:
            raise ValueError("Incomplete TLS record data")

        # Return the record as TypeAndBytes
        return TypeAndBytes(content_type, data)

    def set_record_decryptor(self, record_decryptor):
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





import struct
class RecordDecryptor:
    def __init__(self, traffic_secret, hkdf_expand_label, aead_class, key_length, iv_length):
        key = hkdf_expand_label(traffic_secret, b"key", b"", key_length)
        self.aead = aead_class(key)
        self.iv = hkdf_expand_label(traffic_secret, b"iv", b"", iv_length)
        self.seq = 0

    def decrypt(self, ciphertext):
        padded_seq = self.seq.to_bytes(len(self.iv), 'big')
        self.seq += 1
        nonce = bytes(a ^ b for a, b in zip(self.iv, padded_seq))
        aad = struct.pack('>BHH', ContentType.APPLICATION_DATA, LEGACY_RECORD_VERSION, len(ciphertext))
        decrypted = self.aead.decrypt(nonce, ciphertext, aad)
        return decrypted


if __name__ == "__main__":
    import sys
    def read_bytes(n):
        data = sys.stdin.buffer.read(n)
        if (len(data) < n):
            raise ValueError("Not enough data")
        return data

    record_layer = RecordLayer(read_bytes)
    plaintext = record_layer.read_plaintext()
    print(f"Plaintext: {plaintext.content_type} {plaintext.data.hex()}") # ServerHello
    plaintext = record_layer.read_plaintext()
    print(f"Plaintext: {plaintext.content_type} {plaintext.data.hex()}") # ChangeCipherSpec


    from key_schedule_functions import KeyScheduleFunctions
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import hashlib

    print("====" * 10)
    record_decryptor = RecordDecryptor(
        traffic_secret=bytes.fromhex("f116b50d7cf32d2cc5999e93afe3706b549a1198bff1e35e259e752a81b36479"),
        hkdf_expand_label=KeyScheduleFunctions(hashlib.sha256).hkdf_expand_label,
        aead_class=AESGCM,
        key_length=16,
        iv_length=12
    )
    record_layer.set_record_decryptor(record_decryptor)

    for i in range(4):
        plaintext = record_layer.read_plaintext()
        print(f"Plaintext: {plaintext.content_type} {plaintext.data.hex()}")

    print("====" * 10)
    record_decryptor = RecordDecryptor(
        traffic_secret=bytes.fromhex("6adf51694925b4f9a9e25b0543f8eab0466e14a24848cb8aec42f706378bde36"),
        hkdf_expand_label=KeyScheduleFunctions(hashlib.sha256).hkdf_expand_label,
        aead_class=AESGCM,
        key_length=16,
        iv_length=12
    )
    record_layer.set_record_decryptor(record_decryptor)

    for i in range(4):
        plaintext = record_layer.read_plaintext()
        print(f"Plaintext: {plaintext.content_type} {plaintext.data.hex()}")
