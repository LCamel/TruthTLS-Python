import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import time

# Import the generate_client_hello function from tls13_client_hello
from tls13_client_hello import generate_client_hello
# Import RecordLayer class
from record_layer import RecordLayer, RECORD_TYPE_HANDSHAKE
# Import MessageLayer class
from message_layer import MessageLayer

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

def connect_to_server(hostname, port, client_hello):
    """Connect to the server, send ClientHello message, and receive ServerHello"""
    try:
        # Create a socket and connect to the server using 'with' statement
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)  # Set timeout to 5 seconds
            sock.connect((hostname, port))
            
            # Create RecordLayer instance
            record_layer = RecordLayer(sock)
            
            # Create MessageLayer instance
            message_layer = MessageLayer(record_layer)
            
            # Send the ClientHello message using MessageLayer
            message_layer.write_handshake(client_hello)
            print(f"Sent {len(client_hello)} bytes of ClientHello message")
            
            # Wait for the ServerHello response (should be a handshake message)
            try:
                content_type, data = message_layer.read_message()
                print(f"Received message type {content_type} with {len(data)} bytes")
                
                # Check if the received message is a handshake message (type 22)
                if content_type == RECORD_TYPE_HANDSHAKE:
                    print("Received handshake message (ServerHello)")
                    return content_type, data
                else:
                    print(f"Unexpected message type: {content_type}")
            except Exception as e:
                print(f"Error receiving response: {e}")
            
            return None
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None

def main():
    hostname = "www.google.com"
    port = 443
    
    # Generate keys
    private_key, public_key, uncompressed_pubkey = generate_keys()
    print(f"Generated SECP256R1 key pair")
    print(f"Public key length: {len(uncompressed_pubkey)} bytes")
    print(f"Public key (hex): {uncompressed_pubkey.hex()}")
    
    # Generate ClientHello message
    client_hello = generate_client_hello(uncompressed_pubkey)
    print(f"Generated ClientHello message of {len(client_hello)} bytes")
    
    # Send ClientHello and get response
    print(f"Connecting to {hostname}:{port}...")
    response = connect_to_server(hostname, port, client_hello)
    
    if response:
        content_type, data = response
        print(f"Received message:")
        print(f"  Type: {content_type}")
        print(f"  Length: {len(data)} bytes")
        print(f"  First 20 bytes: {data[:20].hex()}")
        
        # Special handling for handshake messages
        if content_type == RECORD_TYPE_HANDSHAKE:
            print("  This is a handshake message")
            # In a complete implementation, we would further parse
            # the handshake message type and contents here
    else:
        print("No response received or error occurred")
    
if __name__ == "__main__":
    main()