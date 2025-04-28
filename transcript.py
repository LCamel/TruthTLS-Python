from cryptography.hazmat.primitives import hashes

class Transcript:
    def __init__(self, hash_alg=None):
        self._hash_alg_selected = False
        self._sha256_hash = hashes.Hash(hashes.SHA256())
        self._sha384_hash = hashes.Hash(hashes.SHA384())
        self._curr_hash = None
        if hash_alg is not None:
            self.set_hash_alg(hash_alg)

    def set_hash_alg(self, hash_alg):
        if hash_alg not in (hashes.SHA256, hashes.SHA384):
            raise ValueError("Hash algorithm must be SHA-256 or SHA-384")

        if self._hash_alg_selected:
            raise ValueError("Hash algorithm has already been set")

        if hash_alg == hashes.SHA256:
            self._curr_hash = self._sha256_hash
            self._sha256_hash = None
            self._sha384_hash.finalize()
            self._sha384_hash = None
        else:
            self._curr_hash = self._sha384_hash
            self._sha384_hash = None
            self._sha256_hash.finalize()
            self._sha256_hash = None

        self._hash_alg_selected = True        

    def add_handshake(self, handshake_bytes):
        if not self._hash_alg_selected:
            self._sha256_hash.update(handshake_bytes)
            self._sha384_hash.update(handshake_bytes)
        else:
            self._curr_hash.update(handshake_bytes)

    def current_hash(self):
        if not self._hash_alg_selected:
            raise ValueError("Hash algorithm not set, cannot calculate hash")

        return self._curr_hash.copy().finalize()
    
    def close(self):
        if self._sha256_hash is not None:
            self._sha256_hash.finalize()
            self._sha256_hash = None
        if self._sha384_hash is not None:
            self._sha384_hash.finalize()
            self._sha384_hash = None
        if self._curr_hash is not None:
            self._curr_hash.finalize()
            self._curr_hash = None
