"""
TLS 1.3 Key Schedule Implementation with on-demand computation.

This module implements the TLS 1.3 key schedule as defined in RFC 8446 Section 7.1.
It uses the CipherSuite class for cryptographic operations. Values are computed on demand
via getter methods instead of automatically when inputs are provided.
"""

from cipher_suite import CipherSuite, TLS_AES_128_GCM_SHA256

# Constants for transcript stages
TRANSCRIPT_CLIENT_HELLO = 0       # Transcript up to ClientHello
TRANSCRIPT_SERVER_HELLO = 1       # Transcript up to ServerHello
TRANSCRIPT_SERVER_FINISHED = 2    # Transcript up to server Finished
TRANSCRIPT_CLIENT_FINISHED = 3    # Transcript up to client Finished

class KeySchedule3:
    """
    Implementation of the TLS 1.3 Key Schedule with on-demand computation.
    
    This class computes key material on demand via getter methods and stores 
    the results to avoid recomputation. It raises errors if required inputs
    are not available for computation.
    """
    
    def __init__(self, cipher_suite=None):
        self.cipher_suite = cipher_suite or TLS_AES_128_GCM_SHA256
        
        # Zero value for derivation
        self.ZERO = b'\x00' * self.cipher_suite.hash_len
        
        # Input parameters
        self._psk = None
        self._dhe = None
        self._transcripts = [None, None, None, None]
        
        # Cached results
        self._early_secret = None
        self._derived_secret = None
        self._handshake_secret = None
        self._derived_secret_handshake = None
        self._master_secret = None
        self._client_early_traffic_secret = None
        self._early_exporter_master_secret = None
        self._client_handshake_traffic_secret = None
        self._server_handshake_traffic_secret = None
        self._client_application_traffic_secret_0 = None
        self._server_application_traffic_secret_0 = None
        self._exporter_master_secret = None
        self._resumption_master_secret = None
    
    def set_PSK(self, psk):
        if psk is None:
            raise ValueError("PSK cannot be None")
            
        if self._psk is not None:
            raise ValueError("PSK has already been set")
            
        self._psk = psk
    
    def set_DHE(self, dhe):
        if dhe is None:
            raise ValueError("DHE cannot be None")
            
        if self._dhe is not None:
            raise ValueError("DHE has already been set")
            
        self._dhe = dhe
    
    def set_transcript(self, data, nth):
        if data is None:
            raise ValueError("Transcript data cannot be None")
            
        if nth not in range(4):
            raise ValueError(f"Invalid transcript stage: {nth}. Must be 0-3")
            
        if self._transcripts[nth] is not None:
            raise ValueError(f"Transcript for stage {nth} has already been set")
            
        self._transcripts[nth] = data
    
    def get_early_secret(self):
        # First check if we have a cached value
        if self._early_secret is not None:
            return self._early_secret
            
        # If no cached value, check dependencies
        if self._psk is None:
            raise ValueError("PSK must be set before getting early_secret")
            
        # Calculate and cache the value
        # Early Secret = HKDF-Extract(ZERO, PSK)
        self._early_secret = self.cipher_suite.HKDF_extract(self.ZERO, self._psk)
        return self._early_secret
    
    def get_derived_secret(self):
        # First check if we have a cached value
        if self._derived_secret is not None:
            return self._derived_secret
        
        # If no cached value, get dependencies
        early_secret = self.get_early_secret()  # Will raise error if PSK not set
            
        # Calculate and cache the value
        # derived_secret = Derive-Secret(Early Secret, "derived", "")
        self._derived_secret = self.cipher_suite.derive_secret(
            early_secret, b"derived", b"")
        return self._derived_secret
    
    def get_handshake_secret(self):
        # First check if we have a cached value
        if self._handshake_secret is not None:
            return self._handshake_secret
            
        # If no cached value, check dependencies
        if self._dhe is None:
            raise ValueError("DHE must be set before getting handshake_secret")
            
        derived_secret = self.get_derived_secret()  # Will raise error if PSK not set
            
        # Calculate and cache the value
        # Handshake Secret = HKDF-Extract(derived_secret, (EC)DHE)
        self._handshake_secret = self.cipher_suite.HKDF_extract(
            derived_secret, self._dhe)
        return self._handshake_secret
    
    def get_derived_secret_handshake(self):
        # First check if we have a cached value
        if self._derived_secret_handshake is not None:
            return self._derived_secret_handshake
            
        # If no cached value, get dependencies
        handshake_secret = self.get_handshake_secret()  # Will raise error if inputs not set
            
        # Calculate and cache the value
        # derived_secret_handshake = Derive-Secret(Handshake Secret, "derived", "")
        self._derived_secret_handshake = self.cipher_suite.derive_secret(
            handshake_secret, b"derived", b"")
        return self._derived_secret_handshake
    
    def get_master_secret(self):
        # First check if we have a cached value
        if self._master_secret is not None:
            return self._master_secret
            
        # If no cached value, get dependencies
        derived_secret_handshake = self.get_derived_secret_handshake()  # Will raise error if inputs not set
            
        # Calculate and cache the value
        # Master Secret = HKDF-Extract(derived_secret_handshake, ZERO)
        self._master_secret = self.cipher_suite.HKDF_extract(
            derived_secret_handshake, self.ZERO)
        return self._master_secret
    
    def get_client_early_traffic_secret(self):
        # First check if we have a cached value
        if self._client_early_traffic_secret is not None:
            return self._client_early_traffic_secret
            
        # If no cached value, check dependencies
        if self._transcripts[TRANSCRIPT_CLIENT_HELLO] is None:
            raise ValueError("ClientHello transcript must be set before getting client_early_traffic_secret")
            
        early_secret = self.get_early_secret()  # Will raise error if PSK not set
            
        # Calculate and cache the value
        # client_early_traffic_secret = Derive-Secret(Early Secret, "c e traffic", ClientHello)
        self._client_early_traffic_secret = self.cipher_suite.derive_secret(
            early_secret, b"c e traffic", self._transcripts[TRANSCRIPT_CLIENT_HELLO])
        return self._client_early_traffic_secret
    
    def get_early_exporter_master_secret(self):
        # First check if we have a cached value
        if self._early_exporter_master_secret is not None:
            return self._early_exporter_master_secret
            
        # If no cached value, check dependencies
        if self._transcripts[TRANSCRIPT_CLIENT_HELLO] is None:
            raise ValueError("ClientHello transcript must be set before getting early_exporter_master_secret")
            
        early_secret = self.get_early_secret()  # Will raise error if PSK not set
            
        # Calculate and cache the value
        # early_exporter_master_secret = Derive-Secret(Early Secret, "e exp master", ClientHello)
        self._early_exporter_master_secret = self.cipher_suite.derive_secret(
            early_secret, b"e exp master", self._transcripts[TRANSCRIPT_CLIENT_HELLO])
        return self._early_exporter_master_secret
    
    def get_client_handshake_traffic_secret(self):
        # First check if we have a cached value
        if self._client_handshake_traffic_secret is not None:
            return self._client_handshake_traffic_secret
            
        # If no cached value, check dependencies
        if self._transcripts[TRANSCRIPT_SERVER_HELLO] is None:
            raise ValueError("ServerHello transcript must be set before getting client_handshake_traffic_secret")
            
        handshake_secret = self.get_handshake_secret()  # Will raise error if inputs not set
            
        # Calculate and cache the value
        # client_handshake_traffic_secret = Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello)
        self._client_handshake_traffic_secret = self.cipher_suite.derive_secret(
            handshake_secret, b"c hs traffic", self._transcripts[TRANSCRIPT_SERVER_HELLO])
        return self._client_handshake_traffic_secret
    
    def get_server_handshake_traffic_secret(self):
        # First check if we have a cached value
        if self._server_handshake_traffic_secret is not None:
            return self._server_handshake_traffic_secret
            
        # If no cached value, check dependencies
        if self._transcripts[TRANSCRIPT_SERVER_HELLO] is None:
            raise ValueError("ServerHello transcript must be set before getting server_handshake_traffic_secret")
            
        handshake_secret = self.get_handshake_secret()  # Will raise error if inputs not set
            
        # Calculate and cache the value
        # server_handshake_traffic_secret = Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello)
        self._server_handshake_traffic_secret = self.cipher_suite.derive_secret(
            handshake_secret, b"s hs traffic", self._transcripts[TRANSCRIPT_SERVER_HELLO])
        return self._server_handshake_traffic_secret
    
    def get_client_application_traffic_secret_0(self):
        # First check if we have a cached value
        if self._client_application_traffic_secret_0 is not None:
            return self._client_application_traffic_secret_0
            
        # If no cached value, check dependencies
        if self._transcripts[TRANSCRIPT_SERVER_FINISHED] is None:
            raise ValueError("Server Finished transcript must be set before getting client_application_traffic_secret_0")
            
        master_secret = self.get_master_secret()  # Will raise error if inputs not set
            
        # Calculate and cache the value
        # client_application_traffic_secret_0 = Derive-Secret(Master Secret, "c ap traffic", ClientHello...server Finished)
        self._client_application_traffic_secret_0 = self.cipher_suite.derive_secret(
            master_secret, b"c ap traffic", self._transcripts[TRANSCRIPT_SERVER_FINISHED])
        return self._client_application_traffic_secret_0
    
    def get_server_application_traffic_secret_0(self):
        # First check if we have a cached value
        if self._server_application_traffic_secret_0 is not None:
            return self._server_application_traffic_secret_0
            
        # If no cached value, check dependencies
        if self._transcripts[TRANSCRIPT_SERVER_FINISHED] is None:
            raise ValueError("Server Finished transcript must be set before getting server_application_traffic_secret_0")
            
        master_secret = self.get_master_secret()  # Will raise error if inputs not set
            
        # Calculate and cache the value
        # server_application_traffic_secret_0 = Derive-Secret(Master Secret, "s ap traffic", ClientHello...server Finished)
        self._server_application_traffic_secret_0 = self.cipher_suite.derive_secret(
            master_secret, b"s ap traffic", self._transcripts[TRANSCRIPT_SERVER_FINISHED])
        return self._server_application_traffic_secret_0
    
    def get_exporter_master_secret(self):
        # First check if we have a cached value
        if self._exporter_master_secret is not None:
            return self._exporter_master_secret
            
        # If no cached value, check dependencies
        if self._transcripts[TRANSCRIPT_SERVER_FINISHED] is None:
            raise ValueError("Server Finished transcript must be set before getting exporter_master_secret")
            
        master_secret = self.get_master_secret()  # Will raise error if inputs not set
            
        # Calculate and cache the value
        # exporter_master_secret = Derive-Secret(Master Secret, "exp master", ClientHello...server Finished)
        self._exporter_master_secret = self.cipher_suite.derive_secret(
            master_secret, b"exp master", self._transcripts[TRANSCRIPT_SERVER_FINISHED])
        return self._exporter_master_secret
    
    def get_resumption_master_secret(self):
        # First check if we have a cached value
        if self._resumption_master_secret is not None:
            return self._resumption_master_secret
            
        # If no cached value, check dependencies
        if self._transcripts[TRANSCRIPT_CLIENT_FINISHED] is None:
            raise ValueError("Client Finished transcript must be set before getting resumption_master_secret")
            
        master_secret = self.get_master_secret()  # Will raise error if inputs not set
            
        # Calculate and cache the value
        # resumption_master_secret = Derive-Secret(Master Secret, "res master", ClientHello...client Finished)
        self._resumption_master_secret = self.cipher_suite.derive_secret(
            master_secret, b"res master", self._transcripts[TRANSCRIPT_CLIENT_FINISHED])
        return self._resumption_master_secret