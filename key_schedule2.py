"""
TLS 1.3 Key Schedule Implementation.

This module implements the TLS 1.3 key schedule as defined in RFC 8446 Section 7.1.
It uses the CipherSuite class for cryptographic operations.
"""

from cipher_suite import CipherSuite, TLS_AES_128_GCM_SHA256

# Constants for transcript stages
TRANSCRIPT_CLIENT_HELLO = 0
TRANSCRIPT_SERVER_HELLO = 1
TRANSCRIPT_SERVER_FINISHED = 2
TRANSCRIPT_CLIENT_FINISHED = 3

class KeySchedule2:
    """
    Implementation of the TLS 1.3 Key Schedule.
    
    This class automatically computes key material as soon as the required inputs
    are available. Results are stored as public members for easy access.
    """
    
    def __init__(self, cipher_suite=None):
        """
        Initialize the KeySchedule2 with a CipherSuite instance.
        
        Args:
            cipher_suite: A CipherSuite instance. If None, uses TLS_AES_128_GCM_SHA256.
        """
        self.cipher_suite = cipher_suite or TLS_AES_128_GCM_SHA256
        
        # State tracking
        self._psk_set = False
        self._dhe_set = False
        self._transcripts = [None, None, None, None]
        
        # Zero value for derivation
        self.ZERO = b'\x00' * self.cipher_suite.hash_len
        
        # Initialize results as None
        self._init_results()
    
    def _init_results(self):
        """Initialize all result fields as None."""
        # Early secrets
        self.early_secret = None
        self.client_early_traffic_secret = None
        self.early_exporter_master_secret = None
        self.derived_secret = None
        
        # Handshake secrets
        self.handshake_secret = None
        self.client_handshake_traffic_secret = None
        self.server_handshake_traffic_secret = None
        self.derived_secret_handshake = None
        
        # Master secrets
        self.master_secret = None
        self.client_application_traffic_secret_0 = None
        self.server_application_traffic_secret_0 = None
        self.exporter_master_secret = None
        self.resumption_master_secret = None
    
    def set_PSK(self, psk):
        """
        Set the Pre-Shared Key and compute early secrets if possible.
        
        Args:
            psk: The Pre-Shared Key as bytes
        """
        self.psk = psk
        self._psk_set = True
        
        # Compute early secret: Early Secret = HKDF-Extract(ZERO, PSK)
        self.early_secret = self.cipher_suite.HKDF_extract(self.ZERO, self.psk)
        
        # Compute derived secret
        self.derived_secret = self.cipher_suite.derive_secret(
            self.early_secret, b"derived", b"")
        
        # If we have the client hello transcript, compute early traffic secrets
        if self._transcripts[TRANSCRIPT_CLIENT_HELLO] is not None:
            self._compute_early_traffic_secrets()
            
        # If we have DHE and later transcripts, compute subsequent secrets
        if self._dhe_set:
            self._compute_handshake_secrets()
    
    def _compute_early_traffic_secrets(self):
        """Compute early traffic secrets if early_secret and ClientHello are available."""
        if not self._psk_set or self._transcripts[TRANSCRIPT_CLIENT_HELLO] is None:
            return
            
        client_hello = self._transcripts[TRANSCRIPT_CLIENT_HELLO]
        
        # client_early_traffic_secret = Derive-Secret(Early Secret, "c e traffic", ClientHello)
        self.client_early_traffic_secret = self.cipher_suite.derive_secret(
            self.early_secret, b"c e traffic", client_hello)
        
        # early_exporter_master_secret = Derive-Secret(Early Secret, "e exp master", ClientHello)
        self.early_exporter_master_secret = self.cipher_suite.derive_secret(
            self.early_secret, b"e exp master", client_hello)
    
    def set_DHE(self, dhe):
        """
        Set the (EC)DHE shared secret and compute handshake secrets if possible.
        
        Args:
            dhe: The (EC)DHE shared secret as bytes
        """
        self.dhe = dhe
        self._dhe_set = True
        
        # If we have the PSK and derived_secret, compute handshake secrets
        if self._psk_set and self.derived_secret is not None:
            self._compute_handshake_secrets()
    
    def _compute_handshake_secrets(self):
        """Compute handshake secrets if derived_secret and DHE are available."""
        if not self._psk_set or not self._dhe_set:
            return
            
        # Handshake Secret = HKDF-Extract(derived_secret, (EC)DHE)
        self.handshake_secret = self.cipher_suite.HKDF_extract(
            self.derived_secret, self.dhe)
        
        # derived_secret_handshake = Derive-Secret(Handshake Secret, "derived", "")
        self.derived_secret_handshake = self.cipher_suite.derive_secret(
            self.handshake_secret, b"derived", b"")
        
        # Compute the master secret regardless of transcript
        self.master_secret = self.cipher_suite.HKDF_extract(
            self.derived_secret_handshake, self.ZERO)
            
        # If we have the transcript up to ServerHello, compute handshake traffic secrets
        if self._transcripts[TRANSCRIPT_SERVER_HELLO] is not None:
            self._compute_handshake_traffic_secrets()
        
        # If we have the transcript up to server Finished, compute application traffic secrets
        if self._transcripts[TRANSCRIPT_SERVER_FINISHED] is not None:
            self._compute_server_application_secrets()
            
        # If we have the transcript up to client Finished, compute resumption master secret
        if self._transcripts[TRANSCRIPT_CLIENT_FINISHED] is not None:
            self._compute_resumption_master_secret()
    
    def _compute_handshake_traffic_secrets(self):
        """Compute handshake traffic secrets if handshake_secret and transcripts are available."""
        if self.handshake_secret is None or self._transcripts[TRANSCRIPT_SERVER_HELLO] is None:
            return
            
        # Get transcript up to ServerHello
        transcript = self._transcripts[TRANSCRIPT_SERVER_HELLO]
        
        # client_handshake_traffic_secret = Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello)
        self.client_handshake_traffic_secret = self.cipher_suite.derive_secret(
            self.handshake_secret, b"c hs traffic", transcript)
            
        # server_handshake_traffic_secret = Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello)
        self.server_handshake_traffic_secret = self.cipher_suite.derive_secret(
            self.handshake_secret, b"s hs traffic", transcript)
    
    def _compute_server_application_secrets(self):
        """Compute application traffic secrets if master_secret and server Finished transcript are available."""
        if self.master_secret is None or self._transcripts[TRANSCRIPT_SERVER_FINISHED] is None:
            return
            
        # Get transcript up to server Finished
        transcript = self._transcripts[TRANSCRIPT_SERVER_FINISHED]
        
        # client_application_traffic_secret_0 = Derive-Secret(Master Secret, "c ap traffic", ClientHello...server Finished)
        self.client_application_traffic_secret_0 = self.cipher_suite.derive_secret(
            self.master_secret, b"c ap traffic", transcript)
            
        # server_application_traffic_secret_0 = Derive-Secret(Master Secret, "s ap traffic", ClientHello...server Finished)
        self.server_application_traffic_secret_0 = self.cipher_suite.derive_secret(
            self.master_secret, b"s ap traffic", transcript)
            
        # exporter_master_secret = Derive-Secret(Master Secret, "exp master", ClientHello...server Finished)
        self.exporter_master_secret = self.cipher_suite.derive_secret(
            self.master_secret, b"exp master", transcript)
    
    def _compute_resumption_master_secret(self):
        """Compute resumption master secret if master_secret and client Finished transcript are available."""
        if self.master_secret is None or self._transcripts[TRANSCRIPT_CLIENT_FINISHED] is None:
            return
            
        # Get transcript up to client Finished
        transcript = self._transcripts[TRANSCRIPT_CLIENT_FINISHED]
        
        # resumption_master_secret = Derive-Secret(Master Secret, "res master", ClientHello...client Finished)
        self.resumption_master_secret = self.cipher_suite.derive_secret(
            self.master_secret, b"res master", transcript)
    
    def set_transcript(self, data, nth):
        """
        Set the transcript data for a specific stage.
        
        Args:
            data: The transcript data as bytes
            nth: The transcript stage (use constants: 
                 TRANSCRIPT_CLIENT_HELLO,
                 TRANSCRIPT_SERVER_HELLO, 
                 TRANSCRIPT_SERVER_FINISHED,
                 TRANSCRIPT_CLIENT_FINISHED)
        """
        if nth not in range(4):
            raise ValueError(f"Invalid transcript stage: {nth}. Must be 0-3")
        
        self._transcripts[nth] = data
        
        # Compute any secrets that depend on this transcript
        if nth == TRANSCRIPT_CLIENT_HELLO and self._psk_set:
            # Compute early traffic secrets
            self._compute_early_traffic_secrets()
            
        if nth == TRANSCRIPT_SERVER_HELLO and self.handshake_secret is not None:
            # Compute handshake traffic secrets
            self._compute_handshake_traffic_secrets()
            
        if nth == TRANSCRIPT_SERVER_FINISHED and self.master_secret is not None:
            # Compute application traffic secrets
            self._compute_server_application_secrets()
            
        if nth == TRANSCRIPT_CLIENT_FINISHED and self.master_secret is not None:
            # Compute resumption master secret
            self._compute_resumption_master_secret()