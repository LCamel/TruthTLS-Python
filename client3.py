import socket
from common import make_read_write_fully_funcs, TypeAndBytes, ContentType
from record_layer3 import RecordLayer
from transcript import Transcript
from tls13_client_hello import generate_client_hello
from cryptography.hazmat.primitives.asymmetric import ec
from server_hello import extract_server_key_share
from key_schedule4 import KeySchedule4
from cipher_suite import TLS_AES_128_GCM_SHA256

class Handshaker:
    def __init__(self, sock):        
        self.record_layer = RecordLayer(None, *make_read_write_fully_funcs(sock))
        self.transcript = Transcript()
        self.key_schedule = None

    def read_handshake(self):
        handshake = self.record_layer.read()
        self.transcript.add_handshake(handshake.data)
        return handshake
    def write_handshake(self, handshake_bytes):
        self.record_layer.write(TypeAndBytes(ContentType.HANDSHAKE, handshake_bytes))
        self.transcript.add_handshake(handshake_bytes)

    @staticmethod
    def client_calc_ec_shared_secret(private_key, server_hello_bytes):
        public_key_bytes = extract_server_key_share(server_hello_bytes)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)        
        return private_key.exchange(ec.ECDH(), public_key)

    @staticmethod
    def compute_finished(traffic_secret, transcript_hash, cipher_suite):
        finished_key = cipher_suite.hkdf_expand_label(traffic_secret, b"finished", b"", cipher_suite.hash_len)
        verified_data = cipher_suite.hmac_func(finished_key, transcript_hash)

        # Create a properly formatted Finished handshake message
        finished_msg_type = bytes([0x14])  # Handshake type Finished (20)
        finished_length = len(verified_data).to_bytes(3, 'big')  # 3-byte length
        client_finished_message = finished_msg_type + finished_length + verified_data

        return client_finished_message

    def run(self):
        # Generate ClientHello message
        private_key = ec.generate_private_key(ec.SECP256R1())
        client_hello_bytes = generate_client_hello(private_key.public_key())

        self.write_handshake(client_hello_bytes)
        self.record_layer.set_allow_change_cipher_spec(True)
        server_hello = self.read_handshake()
        print(f"Server Hello: {server_hello.data.hex()}")

        # pretending that we have done the handshake
        cipher_suite = TLS_AES_128_GCM_SHA256        
        self.record_layer.set_cipher_suite(cipher_suite)
        self.transcript.set_hash_alg(cipher_suite.hash_alg)
        to_server_hello_transcript_hash = self.transcript.current_hash()

        dhe = self.client_calc_ec_shared_secret(private_key, server_hello.data)
        self.key_schedule = KeySchedule4(cipher_suite).to_early().to_handshake(dhe)
        client_handshake_traffic_secret = self.key_schedule.client_handshake_traffic_secret(to_server_hello_transcript_hash)
        server_handshake_traffic_secret = self.key_schedule.server_handshake_traffic_secret(to_server_hello_transcript_hash)
        self.record_layer.set_encryption_secret(client_handshake_traffic_secret)
        self.record_layer.set_decryption_secret(server_handshake_traffic_secret)

        encrypted_extensions = self.read_handshake()
        print(f"EncryptedExtensions: {encrypted_extensions.data.hex()}")

        certificate = self.read_handshake()
        print(f"Certificate: {certificate.data.hex()}")

        certificate_verify = self.read_handshake()
        print(f"CertificateVerify: {certificate_verify.data.hex()}")

        server_finished = self.read_handshake()
        print(f"server Finished: {server_finished.data.hex()}")
        to_server_finished_transcript_hash = self.transcript.current_hash()
        self.record_layer.set_allow_change_cipher_spec(False)

        client_finished = self.compute_finished(client_handshake_traffic_secret, to_server_finished_transcript_hash, cipher_suite)        
        self.write_handshake(client_finished)

        self.key_schedule.to_application()
        client_application_traffic_secret_0 = self.key_schedule.client_application_traffic_secret_0(to_server_finished_transcript_hash)
        server_application_traffic_secret_0 = self.key_schedule.server_application_traffic_secret_0(to_server_finished_transcript_hash)
        self.record_layer.set_encryption_secret(client_application_traffic_secret_0)
        self.record_layer.set_decryption_secret(server_application_traffic_secret_0)

        self.record_layer.write(TypeAndBytes(ContentType.APPLICATION_DATA, b"GET / HTTP/1.1\r\nHost: example.com\r\n\Connection: close\r\n\r\n"))
        while True:
            record = self.record_layer.read_reassembled()
            print(f"Decrypted message type: {record.content_type}")
            print(f"Decrypted data: {record.data.hex()}")



host = 'example.com'
port = 443

# Create a socket and connect to the host and port
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    print(f"Connected to {host}:{port}")

    Handshaker(s).run()

