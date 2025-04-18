from common import ContentType, TypeAndBytes, LEGACY_RECORD_VERSION

class RecordLayer:
    def __init__(self, get_bytes):
        self.get_bytes = get_bytes
        
    def get_record(self):
        # Read record header (5 bytes: type[1] + version[2] + length[2])
        header = self.get_bytes(5)
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
        data = self.get_bytes(length)
        if len(data) < length:
            raise ValueError("Incomplete TLS record data")
        
        # Return the record as TypeAndBytes
        return TypeAndBytes(content_type, data)

