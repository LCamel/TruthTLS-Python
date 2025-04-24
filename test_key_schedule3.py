#!/usr/bin/env python3
"""
Test program to compare KeySchedule2 and KeySchedule3 implementations.

This script creates equivalent test cases for both KeySchedule2 and KeySchedule3
implementations and verifies that they produce identical results at each stage
of the TLS 1.3 key schedule process. The main difference is that KeySchedule3
calculates values on demand via getter methods rather than automatically.
"""

import os
import binascii

from key_schedule2 import KeySchedule2
from key_schedule3 import KeySchedule3
from cipher_suite import TLS_AES_128_GCM_SHA256
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
        print(f"  KeySchedule2: {binascii.hexlify(value1).decode() if value1 else 'None'}")
        print(f"  KeySchedule3: {binascii.hexlify(value2).decode() if value2 else 'None'}")
    print()

def compare_key_schedules():
    """Compare KeySchedule2 and KeySchedule3 implementations."""
    print("Comparing KeySchedule2 and KeySchedule3 implementations\n")
    
    # Create random test data
    psk = os.urandom(32)
    dhe = os.urandom(32)
    client_hello = os.urandom(128)
    server_hello = os.urandom(128)
    server_finished = os.urandom(128)
    client_finished = os.urandom(128)
    
    # Initialize both key schedules with the same cipher suite
    ks2 = KeySchedule2(TLS_AES_128_GCM_SHA256)
    ks3 = KeySchedule3(TLS_AES_128_GCM_SHA256)
    
    print("Step 1: Setting PSK")
    # Set PSK for both
    ks2.set_PSK(psk)
    ks3.set_PSK(psk)
    
    # Compare early_secret
    # Note: KeySchedule2 calculates it automatically, KeySchedule3 on demand
    print_comparison("early_secret", ks2.early_secret, ks3.get_early_secret())
    
    # Compare derived_secret
    print_comparison("derived_secret", ks2.derived_secret, ks3.get_derived_secret())
    
    print("Step 2: Adding ClientHello")
    # Set ClientHello transcript for both
    ch_transcript = client_hello
    ks2.set_transcript(ch_transcript, TRANSCRIPT_CLIENT_HELLO)
    ks3.set_transcript(ch_transcript, TRANSCRIPT_CLIENT_HELLO)
    
    # Compare early traffic secrets
    print_comparison("client_early_traffic_secret", 
                    ks2.client_early_traffic_secret, 
                    ks3.get_client_early_traffic_secret())
    
    print_comparison("early_exporter_master_secret", 
                    ks2.early_exporter_master_secret, 
                    ks3.get_early_exporter_master_secret())
    
    print("Step 3: Setting DHE secret")
    # Set DHE for both
    ks2.set_DHE(dhe)
    ks3.set_DHE(dhe)
    
    # Compare handshake_secret and derived values
    print_comparison("handshake_secret", 
                    ks2.handshake_secret, 
                    ks3.get_handshake_secret())
    
    print_comparison("derived_secret_handshake", 
                    ks2.derived_secret_handshake, 
                    ks3.get_derived_secret_handshake())
    
    print_comparison("master_secret", 
                    ks2.master_secret, 
                    ks3.get_master_secret())
    
    print("Step 4: Adding ServerHello")
    # Set ServerHello transcript for both
    sh_transcript = client_hello + server_hello
    ks2.set_transcript(sh_transcript, TRANSCRIPT_SERVER_HELLO)
    ks3.set_transcript(sh_transcript, TRANSCRIPT_SERVER_HELLO)
    
    # Compare handshake traffic secrets
    print_comparison("client_handshake_traffic_secret", 
                    ks2.client_handshake_traffic_secret, 
                    ks3.get_client_handshake_traffic_secret())
    
    print_comparison("server_handshake_traffic_secret", 
                    ks2.server_handshake_traffic_secret, 
                    ks3.get_server_handshake_traffic_secret())
    
    print("Step 5: Adding Server Finished")
    # Set ServerFinished transcript for both
    sf_transcript = client_hello + server_hello + server_finished
    ks2.set_transcript(sf_transcript, TRANSCRIPT_SERVER_FINISHED)
    ks3.set_transcript(sf_transcript, TRANSCRIPT_SERVER_FINISHED)
    
    # Compare application traffic secrets and exporter master secret
    print_comparison("client_application_traffic_secret_0", 
                    ks2.client_application_traffic_secret_0, 
                    ks3.get_client_application_traffic_secret_0())
    
    print_comparison("server_application_traffic_secret_0", 
                    ks2.server_application_traffic_secret_0, 
                    ks3.get_server_application_traffic_secret_0())
    
    print_comparison("exporter_master_secret", 
                    ks2.exporter_master_secret, 
                    ks3.get_exporter_master_secret())
    
    print("Step 6: Adding Client Finished")
    # Set ClientFinished transcript for both
    cf_transcript = client_hello + server_hello + server_finished + client_finished
    ks2.set_transcript(cf_transcript, TRANSCRIPT_CLIENT_FINISHED)
    ks3.set_transcript(cf_transcript, TRANSCRIPT_CLIENT_FINISHED)
    
    # Compare resumption master secret
    print_comparison("resumption_master_secret", 
                    ks2.resumption_master_secret, 
                    ks3.get_resumption_master_secret())

if __name__ == "__main__":
    compare_key_schedules()