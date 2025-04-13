"""
TLS 1.3 Message Layer implementation

This module provides a MessageLayer class that handles the conversion between 
TLS messages and TLS records.
"""

from record_layer import RecordLayer

class MessageLayer:
    """
    TLS 1.3 Message Layer implementation.
    
    This class serves as an intermediary between the application and the RecordLayer,
    handling the conversion between TLS messages and TLS records.
    """
    
    def __init__(self, record_layer):
        """
        Initialize the message layer with a RecordLayer object.
        
        Args:
            record_layer (RecordLayer): A RecordLayer object
        """
        self.record_layer = record_layer
    
    def write_handshake(self, data):
        """
        Write a handshake message to the underlying RecordLayer.
        
        Args:
            data (bytes): The handshake message data
        """
        self.record_layer.write_handshake(data)
    
    def read_message(self):
        """
        Read a TLS message from the underlying RecordLayer.
        
        Currently assuming a 1:1 relationship between records and messages.
        
        Returns:
            tuple: (content_type, data) where content_type is an integer and data is bytes
        """
        # For now, this is a simple pass-through to the record layer
        # In a more complete implementation, this would handle message fragmentation
        # and coalescing across multiple records
        content_type, data = self.record_layer.read_record()
        return content_type, data