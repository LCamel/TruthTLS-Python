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
tcpdump -s 0 -i "$INTERFACE" -w "${PREFIX}.pcap" "host $HOSTNAME and port $PORT" -U &
TCPDUMP_PID=$!

# Wait a moment for tcpdump to start
sleep 1

# Set up SSL key logging
export SSLKEYLOGFILE="${PWD}/${PREFIX}.keylog"

# Connect to the URL with TLS 1.3 only and HTTP/1.1
echo "Connecting to $URL..."
"$CURL_BIN" -k --tlsv1.3 --http1.1 --tls13-ciphers TLS_AES_128_GCM_SHA256: -o "${PREFIX}.response" -s "$URL"

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

# Find tcpflow output files
echo "Processing tcpflow files..."
# Look for files that match the pattern of tcpflow output
for file in $(find . -type f -name "[0-9]*.[0-9]*.[0-9]*.[0-9]*.[0-9]*-[0-9]*.[0-9]*.[0-9]*.[0-9]*.[0-9]*"); do
    # Extract source and destination from filename
    if [[ "$file" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)-([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+) ]]; then
        SRC_IP="${BASH_REMATCH[1]}"
        SRC_PORT="${BASH_REMATCH[2]}"
        DST_IP="${BASH_REMATCH[3]}"
        DST_PORT="${BASH_REMATCH[4]}"
        
        # If destination port matches server port, this is client to server traffic
        if [[ "$DST_PORT" == "00$PORT" || "$DST_PORT" == "0$PORT" || "$DST_PORT" == "$PORT" ]]; then
            echo "Found client->server traffic: $file"
            cp "$file" "${PREFIX}.to"
        # If source port matches server port, this is server to client traffic
        elif [[ "$SRC_PORT" == "00$PORT" || "$SRC_PORT" == "0$PORT" || "$SRC_PORT" == "$PORT" ]]; then
            echo "Found server->client traffic: $file"
            cp "$file" "${PREFIX}.from"
        fi
    fi
done

echo "Capture complete. Files saved to $DIR:"
echo "- ${PREFIX}.pcap: Raw packet capture"
echo "- ${PREFIX}.to: Data sent to server (if found)"
echo "- ${PREFIX}.from: Data received from server (if found)"
echo "- ${PREFIX}.keylog: TLS key log"
echo "- ${PREFIX}.response: Response content"
