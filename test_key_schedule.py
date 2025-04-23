#!/usr/bin/env python3
"""
Test program to compare KeySchedule and KeySchedule2 implementations.

This script creates equivalent test cases for both KeySchedule implementations
and verifies that they produce identical results at each stage of the TLS 1.3
key schedule process.
"""

import hashlib
import os
import binascii
from cryptography.hazmat.primitives import hashes

from key_schedule import KeySchedule
from key_schedule2 import KeySchedule2
from cipher_suite import CipherSuite, TLS_AES_128_GCM_SHA256
from key_schedule2 import (
    TRANSCRIPT_CLIENT_HELLO,
    TRANSCRIPT_SERVER_HELLO,
    TRANSCRIPT_SERVER_FINISHED,
    TRANSCRIPT_CLIENT_FINISHED
)

def print_comparison(name, value1, value2):
    """Print a comparison between two values with clear formatting."""
    match = "✅ MATCH" if value1 == value2 else "❌ DIFFERENT"
    print(f"{match} | {name}")
    if value1 != value2:
        print(f"  KeySchedule:  {binascii.hexlify(value1).decode() if value1 else 'None'}")
        print(f"  KeySchedule2: {binascii.hexlify(value2).decode() if value2 else 'None'}")
    print()

def compare_key_schedules():
    """Compare KeySchedule and KeySchedule2 implementations."""
    print("Comparing KeySchedule and KeySchedule2 implementations\n")
    
    # Create random test data
    psk = os.urandom(32)
    dhe = os.urandom(32)
    client_hello = os.urandom(128)
    server_hello = os.urandom(128)
    server_finished = os.urandom(128)
    client_finished = os.urandom(128)
    
    # Initialize KeySchedule with SHA-256
    ks = KeySchedule(hashlib.sha256)
    
    # Initialize KeySchedule2 with equivalent cipher suite
    ks2 = KeySchedule2(TLS_AES_128_GCM_SHA256)
    
    print("Step 1: Setting PSK")
    # Set PSK for both
    ks.set_PSK(psk)
    ks2.set_PSK(psk)
    
    # Compare early_secret
    print_comparison("early_secret", ks.early_secret, ks2.early_secret)
    
    print("Step 2: Adding ClientHello")
    # Add ClientHello transcript to both
    ks.add_handshake(client_hello)
    
    # For KeySchedule2, we need to set the transcript data for ClientHello
    ch_transcript = client_hello
    ks2.set_transcript(ch_transcript, TRANSCRIPT_CLIENT_HELLO)
    
    # At this point, KeySchedule2 calculates early traffic secrets automatically
    # There's no direct equivalent in KeySchedule but we can compare derived values
    
    print("Step 3: Setting DHE/DH shared secret")
    # Set DHE for both
    ks.set_DH_shared_secret(dhe)
    ks2.set_DHE(dhe)
    
    # Compare handshake_secret and master_secret
    print_comparison("handshake_secret", ks.handshake_secret, ks2.handshake_secret)
    print_comparison("master_secret", ks.master_secret, ks2.master_secret)
    
    print("Step 4: Adding ServerHello")
    # Add ServerHello transcript to both
    ks.add_handshake(server_hello)
    
    # For KeySchedule2, we set the transcript data for ClientHello+ServerHello
    sh_transcript = client_hello + server_hello
    ks2.set_transcript(sh_transcript, TRANSCRIPT_SERVER_HELLO)
    
    # Calculate handshake traffic secrets for KeySchedule
    ks.calc_handshake_traffic_secrets()
    
    # Compare handshake traffic secrets
    print_comparison(
        "client_handshake_traffic_secret", 
        ks.client_handshake_traffic_secret, 
        ks2.client_handshake_traffic_secret
    )
    print_comparison(
        "server_handshake_traffic_secret", 
        ks.server_handshake_traffic_secret, 
        ks2.server_handshake_traffic_secret
    )
    
    print("Step 5: Adding Server Finished")
    # Add ServerFinished transcript to both
    ks.add_handshake(server_finished)
    
    # For KeySchedule2, we set the transcript for ClientHello+ServerHello+ServerFinished
    sf_transcript = client_hello + server_hello + server_finished
    ks2.set_transcript(sf_transcript, TRANSCRIPT_SERVER_FINISHED)
    
    # Calculate application traffic secrets and exporter master secret for KeySchedule
    ks.calc_application_traffic_secrets()
    ks.calc_exporter_master_secret()
    
    # Compare application traffic secrets and exporter master secret
    print_comparison(
        "client_application_traffic_secret_0", 
        ks.client_application_traffic_secret_0, 
        ks2.client_application_traffic_secret_0
    )
    print_comparison(
        "server_application_traffic_secret_0", 
        ks.server_application_traffic_secret_0, 
        ks2.server_application_traffic_secret_0
    )
    print_comparison(
        "exporter_master_secret", 
        ks.exporter_master_secret, 
        ks2.exporter_master_secret
    )
    
    print("Step 6: Adding Client Finished")
    # Add ClientFinished transcript to both
    ks.add_handshake(client_finished)
    
    # For KeySchedule2, we set the transcript for the full handshake
    cf_transcript = client_hello + server_hello + server_finished + client_finished
    ks2.set_transcript(cf_transcript, TRANSCRIPT_CLIENT_FINISHED)
    
    # Calculate resumption master secret for KeySchedule
    ks.calc_resumption_master_secret()
    
    # Compare resumption master secret
    print_comparison(
        "resumption_master_secret", 
        ks.resumption_master_secret, 
        ks2.resumption_master_secret
    )

if __name__ == "__main__":
    compare_key_schedules()