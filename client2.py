import socket
from cryptography.hazmat.primitives.asymmetric import ec
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hmac import HMAC

from common import TypeAndBytes, ContentType
from record_layer3 import RecordLayer, RecordDecryptor, RecordEncryptor
from tls13_client_hello import generate_client_hello
from server_hello import extract_server_key_share
from key_schedule import KeySchedule

def read_write_funcs(sock):
    def read_bytes(n):  
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise RuntimeError("Socket connection closed before reading enough data")
            data += chunk
        return data

    def write_bytes(data):
        sock.sendall(data)

    return read_bytes, write_bytes
    
def client_calc_ec_shared_secret(private_key, server_hello_bytes):
    public_key_bytes = extract_server_key_share(server_hello_bytes)
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)        
    return private_key.exchange(ec.ECDH(), public_key)

def read_write_handshake_funcs(record_layer, key_schedule):
    def read_handshake():
        handshake = record_layer.read()
        key_schedule.add_handshake(handshake.data)
        return handshake
    def write_handshake(type_and_bytes):
        record_layer.write(type_and_bytes)
        key_schedule.add_handshake(type_and_bytes.data)
    return read_handshake, write_handshake

def compute_finished(traffic_secret, transcript, key_schedule_funcs):
    hash_func = key_schedule_funcs.hash_func
    transcript_hash = hash_func(transcript).digest()
    finished_key = key_schedule_funcs.hkdf_expand_label(traffic_secret, b"finished", b"", key_schedule_funcs.hash_len)
    hmac_obj = HMAC(key=finished_key, msg=transcript_hash, digestmod=hash_func)
    verified_data = hmac_obj.digest()

    # Create a properly formatted Finished handshake message
    finished_msg_type = bytes([0x14])  # Handshake type Finished (20)
    finished_length = len(verified_data).to_bytes(3, 'big')  # 3-byte length
    client_finished_message = finished_msg_type + finished_length + verified_data

    return client_finished_message


host = 'example.com'  # Replace with the actual host
port = 443            # Replace with the actual port
#host = 'localhost'
#port = 4433

# Create a socket and connect
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))

record_layer = RecordLayer(*read_write_funcs(client_socket))
key_schedule = KeySchedule(sha256)
read_handshake, write_handshake = read_write_handshake_funcs(record_layer, key_schedule)

private_key = ec.generate_private_key(ec.SECP256R1())
client_hello_bytes = generate_client_hello(private_key.public_key())

write_handshake(TypeAndBytes(ContentType.HANDSHAKE, client_hello_bytes))
record_layer.set_allow_change_cipher_spec(True)
server_hello = read_handshake()


shared_secret = client_calc_ec_shared_secret(private_key, server_hello.data)
key_schedule.set_DH_shared_secret(shared_secret)
client_handshake_traffic_secret, server_handshake_traffic_secret = key_schedule.calc_handshake_traffic_secrets()
record_layer.set_record_decryptor(
    RecordDecryptor(
        traffic_secret=server_handshake_traffic_secret,
        hkdf_expand_label_func=key_schedule.key_funcs.hkdf_expand_label,
        aead_class=AESGCM,
        key_length=16,
        iv_length=12
    )
)
record_layer.set_record_encryptor(
    RecordEncryptor(
        traffic_secret=client_handshake_traffic_secret,
        hkdf_expand_label_func=key_schedule.key_funcs.hkdf_expand_label,
        aead_class=AESGCM,
        key_length=16,
        iv_length=12
    )
)

encrypted_extensions = read_handshake()
print(f"EncryptedExtensions: {encrypted_extensions.data.hex()}")
certificate = read_handshake()
print(f"Certificate: {certificate.data.hex()}")
certificate_verify = read_handshake()
print(f"CertificateVerify: {certificate_verify.data.hex()}")
server_finished = read_handshake()
record_layer.set_allow_change_cipher_spec(False)
print(f"server Finished: {server_finished.data.hex()}")

client_application_traffic_secret, server_application_traffic_secret = key_schedule.calc_application_traffic_secrets()

client_finished = compute_finished(client_handshake_traffic_secret, key_schedule.transcript, key_schedule.key_funcs)
write_handshake(TypeAndBytes(ContentType.HANDSHAKE, client_finished))


# 在計算完 client_finished 之後，生成應用數據加密所需的密鑰
#client_application_traffic_secret, server_application_traffic_secret = key_schedule.calc_application_traffic_secrets()

# 設置應用數據解密器
record_layer.set_record_decryptor(
    RecordDecryptor(
        traffic_secret=server_application_traffic_secret,
        hkdf_expand_label_func=key_schedule.key_funcs.hkdf_expand_label,
        aead_class=AESGCM,
        key_length=16,
        iv_length=12
    )
)
# 現在嘗試讀取並解密消息
record = record_layer.read_reassembled()
print(f"Decrypted message type: {record.content_type}")
print(f"Decrypted data: {record.data.hex()}")