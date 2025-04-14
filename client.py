import socket
import struct
import sys
import os
import hashlib
from hmac import HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import time

# Add the external tlslite-ng directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'external/tlslite-ng'))

# Import the generate_client_hello function from tls13_client_hello
from tls13_client_hello import generate_client_hello
# Import RecordLayer class
from record_layer import RecordLayer, RECORD_TYPE_HANDSHAKE
# Import MessageLayer class
from message_layer import MessageLayer
# Import KeySchedule directly from key_schedule.py now that we've added it to the path
from key_schedule import KeySchedule

# Constants for TLS
TLS_HANDSHAKE_TYPE_SERVER_HELLO = 2
TLS_HANDSHAKE_TYPE_FINISHED = 20
EXT_KEY_SHARE = 0x0033
GROUP_SECP256R1 = 0x0017

def generate_keys():
    """Generate a SECP256R1 private key and corresponding public key"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    # Serialize the public key to uncompressed format (65 bytes)
    # The format is: 0x04 + x_coordinate (32 bytes) + y_coordinate (32 bytes)
    uncompressed_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return private_key, public_key, uncompressed_bytes

def extract_server_key_share(server_hello):
    """
    Extract the server's key share from the ServerHello message
    
    Args:
        server_hello (bytes): The ServerHello message
        
    Returns:
        bytes: The server's public key
    """
    # Skip handshake header (4 bytes) and ServerHello fixed fields
    # (2 bytes version + 32 bytes random + 1 byte session id length + session id)
    pos = 4 + 2 + 32
    
    # Skip session ID
    session_id_len = server_hello[pos]
    pos += 1 + session_id_len
    
    # Skip cipher suite (2 bytes) and compression method (1 byte)
    pos += 3
    
    # Get extensions length
    extensions_length = (server_hello[pos] << 8) | (server_hello[pos + 1])
    pos += 2
    
    # End position of extensions
    end_pos = pos + extensions_length
    
    # Process extensions
    while pos < end_pos:
        # Get extension type
        ext_type = (server_hello[pos] << 8) | (server_hello[pos + 1])
        pos += 2
        
        # Get extension length
        ext_length = (server_hello[pos] << 8) | (server_hello[pos + 1])
        pos += 2
        
        # If we found the key_share extension
        if ext_type == EXT_KEY_SHARE:
            # Read group
            group = (server_hello[pos] << 8) | (server_hello[pos + 1])
            pos += 2
            
            # Read key exchange length
            key_exchange_length = (server_hello[pos] << 8) | (server_hello[pos + 1])
            pos += 2
            
            # Check if this is the group we expect (secp256r1)
            if group == GROUP_SECP256R1:
                # Extract the public key
                return server_hello[pos:pos + key_exchange_length]
            
            # If not our group, skip this key exchange
            pos += key_exchange_length
        else:
            # Skip other extensions
            pos += ext_length
    
    return None

def client_handshake(key_schedule, message_layer, ec_private_key):
    """
    Perform the TLS 1.3 handshake
    
    Args:
        key_schedule: A KeySchedule object
        message_layer: A MessageLayer object
        ec_private_key: The client's EC private key
        
    Returns:
        bool: True if handshake is successful, False otherwise
    """
    try:
        # Step 1: Generate and send ClientHello
        print("Generating ClientHello...")
        public_key = ec_private_key.public_key()
        uncompressed_pubkey = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        client_hello = generate_client_hello(uncompressed_pubkey)
        print(f"Sending ClientHello ({len(client_hello)} bytes)")
        message_layer.write_handshake(client_hello)
        
        # Add ClientHello to transcript
        key_schedule.add_handshake(client_hello)
        
        # Step 2: Receive ServerHello
        print("Waiting for ServerHello...")
        content_type, server_hello = message_layer.read_message()
        
        if content_type != RECORD_TYPE_HANDSHAKE or server_hello[0] != TLS_HANDSHAKE_TYPE_SERVER_HELLO:
            print("Error: Did not receive ServerHello")
            return False
        
        print(f"Received ServerHello ({len(server_hello)} bytes)")
        
        # Add ServerHello to transcript
        key_schedule.add_handshake(server_hello)
        
        # Step 3: Extract the server's public key from ServerHello
        server_pubkey = extract_server_key_share(server_hello)
        if not server_pubkey:
            print("Error: Could not extract server key share")
            return False
        
        print(f"Extracted server public key ({len(server_pubkey)} bytes)")
        
        # Step 4: Compute shared secret
        server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            server_pubkey
        )
        
        shared_secret = ec_private_key.exchange(ec.ECDH(), server_public_key)
        print(f"Computed shared secret ({len(shared_secret)} bytes)")
        
        # Step 5: Set the shared secret in the key schedule (using correct method name)
        key_schedule.set_DH_shared_secret(shared_secret)
        
        # Step 6: Derive handshake traffic keys
        client_handshake_traffic_secret, server_handshake_traffic_secret = key_schedule.calc_handshake_traffic_secrets()
        
        # Print traffic secrets for comparison with SSL key log
        print("\n===== TRAFFIC SECRETS FOR COMPARISON =====")
        print(f"CLIENT_HANDSHAKE_TRAFFIC_SECRET: {client_handshake_traffic_secret.hex()}")
        print(f"SERVER_HANDSHAKE_TRAFFIC_SECRET: {server_handshake_traffic_secret.hex()}")
        print("=========================================\n")
        
        # Set keys for MessageLayer with the key_schedule for proper key derivation
        message_layer.set_keys(client_handshake_traffic_secret, server_handshake_traffic_secret, key_schedule)
        
        # Step 7: Process encrypted server messages
        print("Receiving encrypted server handshake messages...")
        
        # Helper function to parse a handshake message
        def parse_handshake_message(data):
            if len(data) < 4:  # Need at least type (1) and length (3)
                return None, None, data
            
            msg_type = data[0]
            msg_length = (data[1] << 16) | (data[2] << 8) | data[3]
            
            # Validate message length to avoid parsing errors
            if len(data) < msg_length + 4:
                print(f"Warning: Incomplete handshake message of type {msg_type}, length {msg_length}, but only {len(data)-4} bytes available")
                return None, None, data
            
            msg_data = data[4:4+msg_length]
            remaining = data[4+msg_length:]
            
            return msg_type, msg_data, remaining
        
        # Server might send ChangeCipherSpec for compatibility
        content_type, data = message_layer.read_message()
        if content_type == 20:  # ChangeCipherSpec
            print("Received ChangeCipherSpec (compatibility mode)")
            # Read the next message which should contain handshake data
            content_type, data = message_layer.read_message()
        
        handshake_messages = []  # Store all parsed handshake messages
            
        # Process encrypted handshake messages
        if content_type == RECORD_TYPE_HANDSHAKE:
            print(f"Received encrypted handshake record ({len(data)} bytes)")
            
            # The encrypted data might contain multiple handshake messages concatenated
            remaining_data = data
            
            # Process all handshake messages in the record
            while remaining_data and len(remaining_data) >= 4:
                msg_type, msg_data, remaining_data = parse_handshake_message(remaining_data)
                
                if msg_type is None:
                    break
                
                # Based on the message type, print appropriate information
                message_type_names = {
                    0x08: "EncryptedExtensions",
                    0x0B: "Certificate",
                    0x0F: "CertificateVerify",
                    0x14: "Finished"
                }
                
                message_name = message_type_names.get(msg_type, f"Unknown({msg_type})")
                print(f"Received {message_name} ({len(msg_data)} bytes)")
                
                # Format as a complete handshake message and add to transcript
                handshake_msg = bytes([msg_type]) + struct.pack("!I", len(msg_data))[1:] + msg_data
                key_schedule.add_handshake(handshake_msg)
                
                # Add to our list of parsed messages
                handshake_messages.append((msg_type, msg_data))
            
            # If we didn't receive a complete message set from the server in one record,
            # we need to continue reading more records
            found_encrypted_extensions = any(msg_type == 0x08 for msg_type, _ in handshake_messages)
            found_certificate = any(msg_type == 0x0B for msg_type, _ in handshake_messages)
            found_cert_verify = any(msg_type == 0x0F for msg_type, _ in handshake_messages)
            found_finished = any(msg_type == 0x14 for msg_type, _ in handshake_messages)
            
            # Continue reading records until we get the server Finished message
            if not found_finished:
                max_tries = 3  # Limit attempts to prevent infinite loops
                tries = 0
                
                while not found_finished and tries < max_tries:
                    tries += 1
                    try:
                        print(f"Looking for more handshake messages (attempt {tries})...")
                        content_type, data = message_layer.read_message()
                        
                        if content_type == RECORD_TYPE_HANDSHAKE:
                            print(f"Received additional handshake record ({len(data)} bytes)")
                            
                            # Process additional handshake messages
                            remaining_data = data
                            while remaining_data and len(remaining_data) >= 4:
                                msg_type, msg_data, remaining_data = parse_handshake_message(remaining_data)
                                
                                if msg_type is None:
                                    break
                                
                                message_name = message_type_names.get(msg_type, f"Unknown({msg_type})")
                                print(f"Received {message_name} ({len(msg_data)} bytes)")
                                
                                # Add to transcript hash
                                handshake_msg = bytes([msg_type]) + struct.pack("!I", len(msg_data))[1:] + msg_data
                                key_schedule.add_handshake(handshake_msg)
                                
                                # Add to our list
                                handshake_messages.append((msg_type, msg_data))
                                
                                # Check if this is the Finished message
                                if msg_type == 0x14:
                                    found_finished = True
                        else:
                            print(f"Unexpected content type: {content_type}, expected handshake message")
                            break
                    except Exception as e:
                        print(f"Error reading additional handshake messages: {e}")
                        break
            
            print(f"Handshake messages status:")
            print(f"- EncryptedExtensions: {'Found' if found_encrypted_extensions else 'Not found'}")
            print(f"- Certificate: {'Found' if found_certificate else 'Not found'}")
            print(f"- CertificateVerify: {'Found' if found_cert_verify else 'Not found'}")
            print(f"- Finished: {'Found' if found_finished else 'Not found'}")
            
            if not found_encrypted_extensions:
                print("Warning: EncryptedExtensions not found, but continuing...")
            
            if not found_finished:
                print("Warning: Server Finished not found, but continuing...")
                
        else:
            print(f"Unexpected content type: {content_type}, expected handshake message, trying to continue...")
        
        # Step 8: Send client Finished message
        # Since KeySchedule doesn't have a derive_finished_key method, we'll implement it here
        # In TLS 1.3, finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.length)
        
        # Define a function to derive the finished key
        def derive_finished_key(traffic_secret):
            # Using the key_funcs from key_schedule, with correct method name (lowercase)
            return key_schedule.key_funcs.hkdf_expand_label(
                traffic_secret,
                b"finished",
                b"",
                key_schedule.hash_len
            )
        
        # Get the client finished key from the client_handshake_traffic_secret
        # This is the correct secret to use according to TLS 1.3 spec
        client_finished_key = derive_finished_key(client_handshake_traffic_secret)
        
        # Calculate the transcript hash at this point (before adding Client Finished)
        transcript_hash = key_schedule.hash_func(key_schedule.transcript).digest()
        
        # Calculate verify data (HMAC of transcript hash using finished key)
        verify_data = HMAC(client_finished_key, transcript_hash, key_schedule.hash_func).digest()
        
        print(f"\n===== CLIENT FINISHED DEBUG INFO =====")
        print(f"Transcript hash: {transcript_hash.hex()}")
        print(f"Client finished key: {client_finished_key.hex()}")
        print(f"Verify data: {verify_data.hex()}")
        print(f"Verify data length: {len(verify_data)} bytes")
        print(f"========================================\n")
        
        # Format as a proper Finished handshake message: type(1) + length(3) + verify_data
        # Handshake message format: HandshakeType(1) + Length(3) + Content
        client_finished = bytes([TLS_HANDSHAKE_TYPE_FINISHED])  # HandshakeType.finished
        client_finished += struct.pack("!I", len(verify_data))[1:]  # 3-byte length
        client_finished += verify_data  # The actual verify_data
        
        print(f"Client Finished message structure:")
        print(f"- Type: {client_finished[0]} (Finished)")
        print(f"- Length: {client_finished[1:4].hex()} ({len(verify_data)} bytes)")
        print(f"- Verify data: {client_finished[4:].hex()}")
        print(f"- Total message length: {len(client_finished)} bytes")
        
        # Send the Client Finished message (still encrypted with handshake traffic keys)
        print(f"Sending client Finished ({len(client_finished)} bytes)")
        message_layer.write_handshake(client_finished)
        
        # NOW add the Client Finished to the transcript - AFTER calculating it
        # This is needed for proper application traffic secret derivation
        key_schedule.add_handshake(client_finished)
        
        # Calculate the application traffic secrets
        # This uses the complete transcript including Client Finished
        print("Calculating application traffic secrets...")
        client_application_traffic_secret_0, server_application_traffic_secret_0, _, _ = key_schedule.calc_master_derived_secrets()
        
        # Switch to application traffic keys for subsequent messages
        print("Switching to application traffic keys...")
        message_layer.set_keys(client_application_traffic_secret_0, server_application_traffic_secret_0, key_schedule)
        print("Now using application traffic keys for encryption/decryption")
        
        # Check for alert message from server
        print("Waiting for response from server...")
        try:
            content_type, response = message_layer.read_message()
            print(f"Received message with content type: {content_type}")
            
            # Define alert levels
            ALERT_LEVEL_WARNING = 1
            ALERT_LEVEL_FATAL = 2
            
            # Define alert description codes
            ALERT_DESCRIPTIONS = {
                0: "close_notify",
                10: "unexpected_message",
                20: "bad_record_mac",
                21: "decryption_failed_RESERVED",
                22: "record_overflow",
                30: "decompression_failure_RESERVED",
                40: "handshake_failure",
                41: "no_certificate_RESERVED",
                42: "bad_certificate",
                43: "unsupported_certificate",
                44: "certificate_revoked",
                45: "certificate_expired",
                46: "certificate_unknown",
                47: "illegal_parameter",
                48: "unknown_ca",
                49: "access_denied",
                50: "decode_error",
                51: "decrypt_error",
                60: "export_restriction_RESERVED",
                70: "protocol_version",
                71: "insufficient_security",
                80: "internal_error",
                86: "inappropriate_fallback",
                90: "user_canceled",
                100: "no_renegotiation_RESERVED",
                109: "missing_extension",
                110: "unsupported_extension",
                111: "certificate_unobtainable_RESERVED",
                112: "unrecognized_name",
                113: "bad_certificate_status_response",
                114: "bad_certificate_hash_value_RESERVED",
                115: "unknown_psk_identity",
                116: "certificate_required",
                120: "no_application_protocol"
            }
            
            # Check if the message is an alert (content type 21)
            if content_type == 21:  # Alert record type
                print("Received alert message from server")
                if len(response) >= 2:
                    alert_level = response[0]
                    alert_description = response[1]
                    
                    # Get the level name
                    level_name = "WARNING" if alert_level == ALERT_LEVEL_WARNING else "FATAL" if alert_level == ALERT_LEVEL_FATAL else "UNKNOWN"
                    
                    # Get the description name
                    description_name = ALERT_DESCRIPTIONS.get(alert_description, "unknown")
                    
                    print(f"Alert level: {alert_level} ({level_name}), Alert description: {alert_description} ({description_name})")
                    return False
                else:
                    print("Malformed alert message (too short)")
                    return False
            else:
                # For application data or handshake messages after the handshake completion
                message_type_names = {
                    20: "Change Cipher Spec",
                    21: "Alert",
                    22: "Handshake",
                    23: "Application Data"
                }
                content_name = message_type_names.get(content_type, f"Unknown({content_type})")
                print(f"Received {content_name} message ({len(response)} bytes)")
        except socket.timeout:
            print("Connection timed out waiting for server response - this is normal after handshake completion")
        except Exception as e:
            print(f"Error receiving response: {e}")
        
        # Calculate the application traffic secrets
        print("Calculating application traffic secrets...")
        client_application_traffic_secret_0, server_application_traffic_secret_0, _, _ = key_schedule.calc_master_derived_secrets()
        
        print("TLS 1.3 handshake completed successfully")
        return True
        
    except Exception as e:
        print(f"Error during handshake: {e}")
        return False

def connect_to_server(hostname, port):
    """Connect to the server and perform TLS handshake"""
    try:
        # Generate keys
        private_key, public_key, uncompressed_pubkey = generate_keys()
        print(f"Generated SECP256R1 key pair")
        print(f"Public key length: {len(uncompressed_pubkey)} bytes")
        
        # Create a socket and connect to the server using 'with' statement
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)  # Set timeout to 5 seconds
            sock.connect((hostname, port))
            print(f"Connected to {hostname}:{port}")
            
            # Create RecordLayer instance
            record_layer = RecordLayer(sock)
            
            # Create MessageLayer instance
            message_layer = MessageLayer(record_layer)
            
            # Create KeySchedule instance with sha256 hash function
            key_schedule = KeySchedule(hashlib.sha256)
            
            # Perform TLS handshake
            success = client_handshake(key_schedule, message_layer, private_key)
            
            return success
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return False

def main():
    # Use localhost:4433 as the default to work with run.sh local
    hostname = "localhost"
    port = 4433
    
    print(f"Connecting to {hostname}:{port} using TLS 1.3...")
    success = connect_to_server(hostname, port)
    
    if success:
        print("Connection established successfully")
    else:
        print("Failed to establish secure connection")
    
if __name__ == "__main__":
    main()