from enum import IntEnum

class ContentType(IntEnum):
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

LEGACY_RECORD_VERSION = 0x0303

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