from enum import Enum, auto

class State(Enum):
    INIT = auto()
    EARLY = auto()
    HANDSHAKE = auto()
    APPLICATION = auto()

class KeySchedule4:
    def __init__(self, cipher_suite):
        self.cipher_suite = cipher_suite
        self.ZERO = b'\x00' * self.cipher_suite.hash_len
        self._state = State.INIT
        self._curr_secret = None
        
        self._empty_string_hash = self.cipher_suite.hash_func(b"")        
        self.HKDF_extract = self.cipher_suite.HKDF_extract
        self.derive_secret_with_hash = self.cipher_suite.derive_secret_with_hash
        
    def _check_state(self, required_state, method_name):
        if self._state != required_state:
            raise ValueError(f"Cannot call {method_name} in {self._state.name} state. Must be in {required_state.name} state.")
    
    def to_early(self, psk):
        self._check_state(State.INIT, "to_early")
        if psk is None:
            raise ValueError("PSK cannot be None")
        self._curr_secret = self.HKDF_extract(self.ZERO, psk)
        self._state = State.EARLY
        return self
    
    def to_handshake(self, dhe):
        self._check_state(State.EARLY, "to_handshake")
        if dhe is None:
            raise ValueError("DHE cannot be None")
        derived_secret = self.derive_secret_with_hash(self._curr_secret, b"derived", self._empty_string_hash)
        self._curr_secret = self.HKDF_extract(derived_secret, dhe)
        self._state = State.HANDSHAKE
        return self
    
    def to_application(self):
        self._check_state(State.HANDSHAKE, "to_application")
        derived_secret_handshake = self.derive_secret_with_hash(self._curr_secret, b"derived", self._empty_string_hash)
        self._curr_secret = self.HKDF_extract(derived_secret_handshake, self.ZERO)
        self._state = State.APPLICATION
        return self
    
    def binder_key(self, is_ext_binder):
        self._check_state(State.EARLY, "binder_key")
        label = b"ext binder" if is_ext_binder else b"res binder"
        return self.derive_secret_with_hash(self._curr_secret, label, self._empty_string_hash)
    
    def client_early_traffic_secret(self, client_hello_transcript_hash):
        self._check_state(State.EARLY, "client_early_traffic_secret")
        return self.derive_secret_with_hash(self._curr_secret, b"c e traffic", client_hello_transcript_hash)
    
    def early_exporter_master_secret(self, client_hello_transcript_hash):
        self._check_state(State.EARLY, "early_exporter_master_secret")
        return self.derive_secret_with_hash(self._curr_secret, b"e exp master", client_hello_transcript_hash)
    
    def client_handshake_traffic_secret(self, to_server_hello_transcript_hash):
        self._check_state(State.HANDSHAKE, "client_handshake_traffic_secret")
        return self.derive_secret_with_hash(self._curr_secret, b"c hs traffic", to_server_hello_transcript_hash)
    
    def server_handshake_traffic_secret(self, to_server_hello_transcript_hash):
        self._check_state(State.HANDSHAKE, "server_handshake_traffic_secret")
        return self.derive_secret_with_hash(self._curr_secret, b"s hs traffic", to_server_hello_transcript_hash)
    
    def client_application_traffic_secret_0(self, to_server_finished_transcript_hash):
        self._check_state(State.APPLICATION, "client_application_traffic_secret_0")
        return self.derive_secret_with_hash(self._curr_secret, b"c ap traffic", to_server_finished_transcript_hash)
    
    def server_application_traffic_secret_0(self, to_server_finished_transcript_hash):
        self._check_state(State.APPLICATION, "server_application_traffic_secret_0")
        return self.derive_secret_with_hash(self._curr_secret, b"s ap traffic", to_server_finished_transcript_hash)
    
    def exporter_master_secret(self, to_server_finished_transcript_hash):
        self._check_state(State.APPLICATION, "exporter_master_secret")
        return self.derive_secret_with_hash(self._curr_secret, b"exp master", to_server_finished_transcript_hash)
    
    def resumption_master_secret(self, to_client_finished_transcript_hash):
        self._check_state(State.APPLICATION, "resumption_master_secret")
        return self.derive_secret_with_hash(self._curr_secret, b"res master", to_client_finished_transcript_hash)