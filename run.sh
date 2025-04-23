#!/bin/bash

# Check if we should use local OpenSSL server
USE_LOCAL_SERVER=false
if [ "$1" == "local" ]; then
  USE_LOCAL_SERVER=true
fi

# 建立輸出目錄
mkdir -p captures

# 定義檔案名稱
CAPTURE_FILE="captures/tls_capture_openssl_$(date +%Y%m%d_%H%M%S).pcap"

# 清除先前的 ssl_keylog.txt 檔案
if [ -f "ssl_keylog.txt" ]; then
  echo "清除先前的 ssl_keylog.txt 檔案..."
  rm -f ssl_keylog.txt
  touch ssl_keylog.txt
fi

# 預先準備 HEAD 請求內容
cat > request.txt << EOF
HEAD / HTTP/1.1
Host: google.com
Connection: close

EOF

# 開始tcpdump捕獲（不需要sudo，使用-w寫入文件）
echo "開始捕獲網絡流量..."
tcpdump -i lo0 -n "tcp port 4433" -w "$CAPTURE_FILE" &
TCPDUMP_PID=$!

# 等待tcpdump啟動
sleep 1

# 決定是否使用本地OpenSSL服務器或連接到Google
if [ "$USE_LOCAL_SERVER" = true ]; then
  echo "啟動本地OpenSSL服務器在端口4433..."
  
  # 確保有自簽證書
  if [ ! -f "server.key" ] || [ ! -f "server.crt" ]; then
    echo "生成自簽證書..."
    openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost" -addext "subjectAltName = DNS:localhost"
    cat server.key server.crt > server.pem
  fi
  
  # 設置密鑰日誌文件
  export SSLKEYLOGFILE="$(pwd)/ssl_keylog.txt"
  echo "密鑰日誌文件: $SSLKEYLOGFILE"
  
  # 啟動OpenSSL服務器
  openssl s_server \
    -cert server.crt \
    -key server.key \
    -accept 4433 \
    -www \
    -tls1_3 \
    -keylogfile "$SSLKEYLOGFILE" \
    -ciphersuites TLS_AES_128_GCM_SHA256 \
    -msg \
    -debug \
    -state &
  SERVER_PID=$!
  
  # 等待服務器啟動
  sleep 2
else
  # 啟動本地端口轉發器
  echo "啟動本地端口轉發器..."
  socat TCP-LISTEN:4433,fork,reuseaddr TCP:google.com:443 &
  SOCAT_PID=$!
  
  # 等待socat啟動
  sleep 1
fi

# 使用openssl s_client通過本地端口轉發器發送HEAD請求到google.com，使用 TLS 1.3
echo "使用openssl發送HEAD請求，使用TLS 1.3並限制 extension和僅使用TLS_AES_128_GCM_SHA256..."
#cat request.txt | openssl s_client -connect localhost:4433 \
#  -tls1_3 \
#  -ciphersuites TLS_AES_128_GCM_SHA256 \
#  -sigalgs "rsa_pkcs1_sha256:rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256" \
#  -curves secp256r1 \
#  -no_etm \
#  -no_ems \
#  -no_ticket \
#  -ign_eof \
#  -quiet
#cd /Users/lcamel/vc/TruthTLS ; /usr/bin/env /opt/homebrew/Cellar/openjdk/23.0.2/libexec/openjdk.jdk/Contents/Home/bin/java -XX:+ShowCodeDetailsInExceptionMessages -cp /Users/lcamel/vc/TruthTLS/target/classes org.truthtls.Main

python client2.py

# 等待確保捕獲完成
sleep 2

# 終止進程
echo "終止捕獲和服務..."
kill $TCPDUMP_PID
if [ "$USE_LOCAL_SERVER" = true ]; then
  kill $SERVER_PID
else
  kill $SOCAT_PID
fi

# 等待進程完全終止
sleep 1

# 清理臨時文件
rm -f request.txt

# 開啟Wireshark查看捕獲檔案
echo "用Wireshark開啟捕獲檔案: $CAPTURE_FILE"
#open -a Wireshark "$CAPTURE_FILE"
WIRESHARK_BIN="/Applications/Wireshark.app/Contents/MacOS/Wireshark"
"$WIRESHARK_BIN" -o "tls.keylog_file:$SSLKEYLOGFILE" "$CAPTURE_FILE" &

echo "完成!"