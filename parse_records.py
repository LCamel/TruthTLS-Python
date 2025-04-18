#!/usr/bin/env python3
import sys
from record_layer3 import RecordLayer
from common import ContentType

def main():
    # Create a buffer to accumulate stdin bytes
    buffer = bytearray()
    
    def get_bytes(n):
        # Function to supply bytes to RecordLayer
        nonlocal buffer
        
        # Fill buffer if needed
        while len(buffer) < n:
            chunk = sys.stdin.buffer.read(4096)  # Read in chunks
            if not chunk:  # EOF
                return buffer[:n]  # Return what we have even if less than n
            buffer.extend(chunk)
            
        # Return requested bytes and update buffer
        result = buffer[:n]
        buffer = buffer[n:]
        return result
    
    # Create RecordLayer with our get_bytes function
    record_layer = RecordLayer(get_bytes)
    
    # Process records until EOF
    try:
        record_count = 0
        while True:
            try:
                record = record_layer.get_record()
                record_count += 1
                
                # Print type and size
                type_name = ContentType(record.content_type).name if record.content_type in ContentType else f"UNKNOWN({record.content_type})"
                print(f"Record #{record_count}: Type={type_name} ({record.content_type}), Size={record.length} bytes")
                
            except ValueError as e:
                if "Incomplete TLS record header" in str(e) and record_count > 0:
                    # Expected at EOF
                    break
                else:
                    print(f"Error: {e}", file=sys.stderr)
                    break
                    
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        
    print(f"\nTotal records processed: {record_count}", file=sys.stderr)

if __name__ == "__main__":
    main()