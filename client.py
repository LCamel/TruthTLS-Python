import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import time

# Import the generate_client_hello function from tls13_client_hello
from tls13_client_hello import generate_client_hello

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
    """Connect to the server and send ClientHello message"""
    try:
        # Create a socket and connect to the server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # Set timeout to 5 seconds
        sock.connect((hostname, port))
        
        # Send the ClientHello message
        sock.sendall(client_hello)
        print(f"Sent {len(client_hello)} bytes of ClientHello message")
        
        # Receive the response
        response = b""
        start_time = time.time()
        while time.time() - start_time < 3:  # Wait for up to 3 seconds for data
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                # If we have enough data, we can stop
                if len(response) > 100:  # At least get enough to see the ServerHello
                    break
            except socket.timeout:
                break
        
        sock.close()
        return response
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
        print(f"Received {len(response)} bytes in response")
        # Check if response contains ServerHello (very simplified check)
        # ServerHello typically starts with record type 22 (handshake) and contains message type 2
        # This is a very basic check and might not be 100% accurate
        if len(response) > 5 and response[0] == 22:
            print("Received what appears to be a TLS handshake response")
            print(f"First 20 bytes: {response[:20].hex()}")
        else:
            print("Response doesn't appear to be a TLS handshake")
            print(f"First 20 bytes: {response[:20].hex()}")
    else:
        print("No response received or error occurred")
    
if __name__ == "__main__":
    main()