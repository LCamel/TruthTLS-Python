from enum import IntEnum

class ContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

LEGACY_RECORD_VERSION = 0x0303
LEGACY_RECORD_VERSION_BYTES = LEGACY_RECORD_VERSION.to_bytes(2, byteorder='big')

class TypeAndBytes:
    def __init__(self, content_type, data):
        self.content_type = content_type
        self.data = data
        self.length = len(data)
        self.idx = 0

    def bytes_available(self):
        return self.length - self.idx
    
    def read_n_bytes(self, n):
        end = self.idx + n
        if end > self.length:
            end = self.length
        result = self.data[self.idx:end]
        self.idx = end
        return result
    
    def length(self):
        return len(self.data)
    
def make_read_write_fully_funcs(sock):
    def read_fully(n):  
        if n < 0:
            raise ValueError("Cannot read negative number of bytes")
        
        data = bytearray(n)
        bytes_read = 0
        while bytes_read < n:
            view = memoryview(data)[bytes_read:]
            remaining = n - bytes_read
            
            chunk_len = sock.recv_into(view, remaining)
            if chunk_len == 0:
                raise RuntimeError(f"Socket connection closed before reading enough data (got {bytes_read} bytes, expected {n})")
            
            bytes_read += chunk_len
        
        return bytes(data)

    def write_fully(data):
        sock.sendall(data)

    return read_fully, write_fully
