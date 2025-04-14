"""
TLS 1.3 Record Layer implementation

This module provides a simple RecordLayer class for handling TLS 1.3 record operations.
"""

import struct

# TLS record types
RECORD_TYPE_CHANGE_CIPHER_SPEC = 20
RECORD_TYPE_ALERT = 21
RECORD_TYPE_HANDSHAKE = 22
RECORD_TYPE_APPLICATION_DATA = 23

# TLS version for TLS 1.3 (actually TLS 1.2 for backwards compatibility)
TLS_VERSION = b'\x03\x03'  # TLS 1.2 (0x0303)


class RecordLayer:
    """
    TLS 1.3 Record Layer implementation.
    
    This class handles the sending and receiving of TLS records.
    """
    
    def __init__(self, socket):
        """
        Initialize the record layer with a socket.
        
        Args:
            socket: A connected socket object
        """
        self.socket = socket
    
    def write_handshake(self, data):
        """
        Write a handshake message to the socket.
        
        Args:
            data (bytes): The handshake message data
        """
        record = self._create_record(RECORD_TYPE_HANDSHAKE, data)
        self.socket.sendall(record)
    
    def write_record(self, record_type, data):
        """
        Write a record of any type to the socket.
        
        Args:
            record_type (int): The type of record (e.g., handshake, application_data)
            data (bytes): The record data
        """
        record = self._create_record(record_type, data)
        self.socket.sendall(record)
    
    def read_record(self):
        """
        Read a TLS record from the socket.
        
        Returns:
            tuple: (record_type, data) where record_type is an integer and data is bytes
        """
        # Read the record header (5 bytes: 1 byte type, 2 bytes version, 2 bytes length)
        header = self._recv_exactly(5)
        if not header or len(header) < 5:
            raise ConnectionError("Failed to read record header")
        
        # Parse the header
        record_type = header[0]
        version = header[1:3]
        record_length = struct.unpack("!H", header[3:5])[0]
        
        # Read the record data
        record_data = self._recv_exactly(record_length)
        if not record_data or len(record_data) < record_length:
            raise ConnectionError("Failed to read complete record data")
        
        return record_type, record_data
    
    def _create_record(self, record_type, data):
        """
        Create a TLS record.
        
        Args:
            record_type (int): The record type
            data (bytes): The record data
        
        Returns:
            bytes: The complete TLS record
        """
        record_header = bytes([record_type]) + TLS_VERSION + struct.pack("!H", len(data))
        return record_header + data
    
    def _recv_exactly(self, n):
        """
        Receive exactly n bytes from the socket.
        
        Args:
            n (int): Number of bytes to receive
        
        Returns:
            bytes: The received data or None if connection closed
        """
        data = b''
        while len(data) < n:
            try:
                chunk = self.socket.recv(n - len(data))
                if not chunk:  # Connection closed
                    return None
                data += chunk
            except Exception as e:
                print(f"Error receiving data: {e}")
                return None
        return data