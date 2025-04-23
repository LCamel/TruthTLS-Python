# Constants for TLS
TLS_HANDSHAKE_TYPE_SERVER_HELLO = 2
TLS_HANDSHAKE_TYPE_FINISHED = 20
EXT_KEY_SHARE = 0x0033
GROUP_SECP256R1 = 0x0017

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
