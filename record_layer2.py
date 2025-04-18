import struct
from common import ContentType, TypeAndBytes, LEGACY_RECORD_VERSION
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class MessageLayer:
    def __init__(self, record_layer):
        self.record_layer = record_layer
        self.left_over = None
        self.client_hello_received_or_sent = False
        self.peer_finished_received = False


    def read_message(self):
        record: TypeAndBytes
        if self.left_over is not None:
            record = self.left_over
            self.left_over = None
        else:
            record = self.read_record()

        if record.content_type == ContentType.ALERT:
            if len(record.data) != 2:
                raise ValueError(f"Invalid ALERT length: {len(record.data)}")
            return record
        elif record.content_type == ContentType.APPLICATION_DATA:
            return record
        elif record.content_type == ContentType.HANDSHAKE:
            if len(record.data) == 0:
                raise ValueError("Expecting a non-empty HANDSHAKE message")
            handshake_header, record = self._read_n_bytes(record, 4)
            handshake_length = int.from_bytes(handshake_header[1:4], 'big')
            handshake_body, record = self._read_n_bytes(record, handshake_length)
            
            if record.bytes_available() > 0:
                self.left_over = record
            return TypeAndBytes(ContentType.HANDSHAKE, handshake_header + handshake_body)
        else:
            raise ValueError(f"Unexpected content type: {record.content_type}")


    def _read_n_bytes(self, record, n) -> bytes:
        backup = self.record_layer.allow_change_cipher_spec
        self.record_layer.allow_change_cipher_spec = False

        data = b''
        while len(data) < n:
            if record.available_bytes() <= 0:
                record = self.record_layer.read_and_maybe_decrypt()
                if (record.content_type != ContentType.HANDSHAKE or len(record.data) == 0):
                    raise ValueError("Expecting a non-empty HANDSHAKE message")
            data += record.read_n_bytes(n - len(data))

        self.record_layer.allow_change_cipher_spec = backup
        return data, record

class RecordLayer2:
    def __init__(self, socket, allow_change_cipher_spec=True):
        self.socket = socket
        self.allow_change_cipher_spec = allow_change_cipher_spec

        self.write_key = None
        self.write_iv = None
        self.seq = -1

        self.peer_write_key = None
        self.peer_write_iv = None        
        self.peer_seq = -1

    def set_keys(self, write_key: bytes, write_iv: bytes, peer_write_key: bytes, peer_write_iv: bytes):
        self.write_key = write_key
        self.write_iv = write_iv
        self.seq = 0
        #self.aes_gcm = AESGCM(write_key) # TODO
        
        self.peer_write_key = peer_write_key
        self.peer_write_iv = peer_write_iv
        self.peer_seq = 0
        self.peer_aes_gcm = AESGCM(peer_write_key)

    def set_allow_change_cipher_spec(self, allow_change_cipher_spec: bool):
        self.allow_change_cipher_spec = allow_change_cipher_spec

    # Possible results:
    # TypeAndBytes
    #   type: ALERT / HANDSHAKE / APPLICATION_DATA (no CHANGE_CIPHER_SPEC)
    #   data: bytes (length might be zero)
    # Exceptions: 
    # - ValueError: unexpected message
    # - ConnectionError
    def read_and_maybe_decrypt(self) -> TypeAndBytes:
        while True:
            content_type = self._read_n_bytes(1)[0]
            self._read_n_bytes(2) # ignore legacy_version
            length = int.from_bytes(self._read_n_bytes(2), 'big')
            data = self._read_n_bytes(length)

            if content_type == ContentType.CHANGE_CIPHER_SPEC:
                if not self.allow_change_cipher_spec:
                    raise ValueError("Unexpected CHANGE_CIPHER_SPEC message")
                else:
                    continue # MUST simply drop it

            if self.peer_write_key is None: # expecting plaintext
                if content_type == ContentType.APPLICATION_DATA:
                    raise ValueError("Unexpected APPLICATION_DATA without decryption")
            else:
                if content_type != ContentType.APPLICATION_DATA:
                    raise ValueError(f"Expecting APPLICATION_DATA but: {content_type}")
                data = self._decrypt(data)

                for i in range(len(data) - 1, -1, -1):
                    if data[i] != 0:
                        break
                else:
                    raise ValueError("Invalid padding: no content-type byte found")

                content_type = data[i]
                if content_type == ContentType.CHANGE_CIPHER_SPEC:
                    raise ValueError("Unexpected CHANGE_CIPHER_SPEC in decrypted data")
                data = data[:i]

            return TypeAndBytes(content_type, data)

    def _read_n_bytes(self, n) -> bytes:
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Socket closed before receiving all data")
            data += chunk
        return data

    def _decrypt(self, ciphertext: bytes) -> bytes:
        nonce = self._calc_nonce()
        self.peer_seq += 1
        
        aad = struct.pack('>BHH', ContentType.APPLICATION_DATA, LEGACY_RECORD_VERSION, len(ciphertext))        
        decrypted = self.peer_aes_gcm.decrypt(nonce, ciphertext, aad)
        print(f"ciphertext: {ciphertext.hex()}")
        print(f"decrypted: {decrypted.hex()}")        
        return decrypted
    
    def _calc_nonce(self) -> bytes:
        nonce = bytearray(self.peer_write_iv)
        seq_num_bytes = self.peer_seq.to_bytes(8, byteorder='big')
        offset = len(nonce) - len(seq_num_bytes)
        for i in range(8):
            nonce[offset + i] ^= seq_num_bytes[i]
        return bytes(nonce)


if __name__ == "__main__":

    class FileSocket:
        def __init__(self, filename):
            self.file = open(filename, 'rb')
        
        def recv(self, n_bytes):
            data = self.file.read(n_bytes)
            return data

    socket = FileSocket("./server_traffic.bin")
    record_layer = RecordLayer2(socket)


    type_and_bytes = record_layer.read_and_maybe_decrypt()
    print(type_and_bytes.content_type)
    print(len(type_and_bytes.data))
    print(type_and_bytes.data.hex())


    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), 'external/tlslite-ng'))
    from key_schedule_functions import KeyScheduleFunctions
    import hashlib
    key_funcs = KeyScheduleFunctions(hashlib.sha256)

    server_traffic_secret = bytes.fromhex("ecc4b06e58c82b966baf2d2157103ce1fc49f92df4dcc918a6a833f9f0c11d3f")
    server_key = key_funcs.hkdf_expand_label(
        server_traffic_secret,
        b"key",
        b"",
        16
    )            
    # Server IV used for server->client messages
    server_iv = key_funcs.hkdf_expand_label(
        server_traffic_secret,
        b"iv",
        b"",
        12
    )
    print(f"server_traffic_secret: {server_traffic_secret.hex()}")
    print(f"server_key: {server_key.hex()}")
    print(f"server_iv: {server_iv.hex()}")


    print("ENCRYPTED_EXTENSIONS")
    record_layer.set_keys(b'', b'', server_key, server_iv)
    type_and_bytes = record_layer.read_and_maybe_decrypt()
    print(type_and_bytes.content_type)
    print(len(type_and_bytes.data))
    print(type_and_bytes.data.hex())

    print("CERTIFICATE")
    type_and_bytes = record_layer.read_and_maybe_decrypt()
    print(type_and_bytes.content_type)
    print(len(type_and_bytes.data))
    print(type_and_bytes.data.hex())

    print("CERTIFICATE_VERIFY")
    type_and_bytes = record_layer.read_and_maybe_decrypt()
    print(type_and_bytes.content_type)
    print(len(type_and_bytes.data))
    print(type_and_bytes.data.hex())

    print("server FINISHED")
    type_and_bytes = record_layer.read_and_maybe_decrypt()
    print(type_and_bytes.content_type)
    print(len(type_and_bytes.data))
    print(type_and_bytes.data.hex())

    record_layer.set_allow_change_cipher_spec(False)

    server_traffic_secret = bytes.fromhex("51e2ad8e757e3a9c10ed1953963652386ffe1286bcdbfe61e9e27633c6d63488")
    server_key = key_funcs.hkdf_expand_label(
        server_traffic_secret,
        b"key",
        b"",
        16
    )            
    # Server IV used for server->client messages
    server_iv = key_funcs.hkdf_expand_label(
        server_traffic_secret,
        b"iv",
        b"",
        12
    )
    record_layer.set_keys(b'', b'', server_key, server_iv)

    print("NEW_SESSION_TICKET")
    type_and_bytes = record_layer.read_and_maybe_decrypt()
    print(type_and_bytes.content_type)
    print(len(type_and_bytes.data))
    print(type_and_bytes.data.hex())

    print("NEW_SESSION_TICKET")
    type_and_bytes = record_layer.read_and_maybe_decrypt()
    print(type_and_bytes.content_type)
    print(len(type_and_bytes.data))
    print(type_and_bytes.data.hex())
