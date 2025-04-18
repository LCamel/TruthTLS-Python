#!/bin/bash
# filepath: /Users/lcamel/vc/TrustTLS-Python/capture_url.sh

# Check if we have the required parameters
if [ $# -ne 2 ]; then
    echo "Usage: $0 <url> <directory>"
    exit 1
fi

URL="$1"
DIR="$2"
INTERFACE="en0"
CURL_BIN="/opt/homebrew/Cellar/curl/8.12.1/bin/curl"
PREFIX="$(basename "$DIR")"

# Extract hostname and port from URL
if [[ "$URL" =~ ^https?://([^:/]+)(:[0-9]+)?(/.*)?$ ]]; then
    HOSTNAME="${BASH_REMATCH[1]}"
    PORT="${BASH_REMATCH[2]}"
    PORT="${PORT#:}" # Remove colon if port is specified
    PORT="${PORT:-443}" # Default to 443 if not specified
else
    echo "Invalid URL format: $URL"
    exit 1
fi

# Create the directory
mkdir -p "$DIR"
cd "$DIR" || exit 1

# Start capturing network traffic
echo "Starting tcpdump capture on interface $INTERFACE..."
tcpdump -i "$INTERFACE" -w "${PREFIX}.pcap" "host $HOSTNAME and port $PORT" -U &
TCPDUMP_PID=$!

# Wait a moment for tcpdump to start
sleep 1

# Set up SSL key logging
export SSLKEYLOGFILE="${PWD}/${PREFIX}.keylog"

# Connect to the URL with TLS 1.3 only and HTTP/1.1
echo "Connecting to $URL..."
"$CURL_BIN" --tlsv1.3 --http1.1 --tls13-ciphers TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256 -o "${PREFIX}.response" -s "$URL"

# Wait a moment before stopping tcpdump to ensure all packets are captured
echo "Waiting for any remaining packets..."
sleep 2

# Stop tcpdump
echo "Stopping tcpdump..."
kill "$TCPDUMP_PID"
wait "$TCPDUMP_PID" 2>/dev/null

# Use tcpflow to separate the TCP streams
echo "Processing with tcpflow..."
tcpflow -r "${PREFIX}.pcap" -o .

# Rename tcpflow files to more meaningful names if possible
# Look for files that match the pattern
TCPFLOW_FILES=$(find . -name "*${PORT}-*" -o -name "*-${PORT}*")
for file in $TCPFLOW_FILES; do
    if [[ "$file" == *"${PORT}-"* ]]; then
        # This is data sent to the server
        cp "$file" "${PREFIX}.to"
    elif [[ "$file" == *"-${PORT}"* ]]; then
        # This is data received from the server
        cp "$file" "${PREFIX}.from"
    fi
done

echo "Capture complete. Files saved to $DIR:"
echo "- ${PREFIX}.pcap: Raw packet capture"
echo "- ${PREFIX}.to: Data sent to server"
echo "- ${PREFIX}.from: Data received from server"
echo "- ${PREFIX}.keylog: TLS key log"
echo "- ${PREFIX}.response: Response content"