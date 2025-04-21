使用 tlslight-ng 來幫助開發, 但不使用 code.

```
我想實作功能最少, 但是符合 TLS 1.3 規格的 TLS client.
不打算支援 TLS 1.2, 但是希望能夠相容於舊的網路設備.
閱讀 tls13_minimal_client_hello.txt 的內容, 和我討論有沒有問題.
```

```
閱讀 tls13_minimal_client_hello.txt 的內容,
實作一個可以產生 ClientHello 的 handshake message 的 function.
這個 function 接受一個 secp256r1 的 public key 的 input
return message 表示為 bytes 或 bytearray, 看你實作方便.
```

```
寫一個 client.py
使用 module cryptography 生出 secp256r1 的 private key 和 public key
把 public key 表示成 uncompressed 格式的 65 bytes
使用 tls13_client_hello.py 中的 generate_client_hello 生出 ClientHello message
送到 www.google.com 443
並收取 response bytes 看看是否有 ServerHello 回來
```

```
我想要有一個 class RecordLayer
initialize 時給一個 socket
有幾個 method
write_handshake() 給一個 bytes 的 data
read_record() 回傳 integer 的 type 和 bytes 的 data
```

```
我想要有一個 class MessageLayer
這個 layer 負責處理 message 與 record 之間的轉換
而讓 RecordLayer 去負責 record 與 bytes 間的轉換

initialize 時給一個 object RecordLayer
MessageLayer 有幾個 method
write_handshake() 給一個 bytes 的 data
read_message() 回傳 integer 的 content_type 和 bytes 的 data

先不要處理 message 與 record 的多對一或一對多的關係
先假設是一對一個關係
也就是從 RecordLayer 讀出來的一個 record 剛好就是一個 message

同時修改 client.py 來使用 MessageLayer
```

```
簡化 connect_to_server 的邏輯
由於我們做出來的 ClientHello 使用的參數都是接收方被規定在 TLS 1.3 必須支援的
所以在送出 ClientHello 後
應該會收到 ServerHello
也就是一個 content type 為 handshake(22) 的 message
先處理到這邊就好
```


後來多下了一些 prompt 走上了叉路. revert 回先前的版本.

認清: 我們維持一個小的規模
沒有要完整支援整個 TLS 1.3
我們沒有要支援 Hello Retry Request
我們也沒有要送出多餘的 extension
因此 server 也不可以(MUST NOT)送一些我們不想處理的 extension 回來.
```
Implementations MUST NOT send extension responses if the remote
endpoint did not send the corresponding extension requests, with the
exception of the "cookie" extension in the HelloRetryRequest.
```
所以我們只要 parse 少部分的 extension 就好.

"理論上"我們還應該送 "unsupported_extension" alert. (TODO)


如果想成一個大的 handshake "block", 這個 block 應該有什麼輸出?
因為我們所有的實作都鎖死了, 不會隨 handshake 而變, 所以等於只有產生 DH shared secret.
或者說由 handshake "agent" 幫我們出面交涉, 回來拿出 shared secret.

或者更複雜一些: 拿回一個裝載好的 KeySchedule 物件. 因為後面還需要前面的 transcript (or transcript hasher)
精確一些是 master secret 和 update 到一半的 hash_obj

```
RecordLayer 的責任:
讓上層可以讀出/寫入一個 record, 也就是 (type, data bytes) pair

MessageLayer 的責任:
讓上層可以讀出/寫入一個 message, 也就是 (type, data bytes) pair
負責使用上層設定的 write_key / peer_write_key 來加解密
對 key schedule 並不了解.

function client_handshake(key_schedule, record_layer) 的責任:
完成 handshake, 更新 key_schedule
過程中會:
發送 ClientHello
接收 ServerHello
發送 client Finished
而接收 ServerHello 後, 會從中取出 ECDHE 的 DH peer public key, 計算出 DH shared secret, 設定給 key_schedule
並且會更新 transcript, 計算出 handshake traffic secret, 設定給 record_layer

client.py 中 import 在 external/tlslite-ng/key_schedule.py 裡面的已經實作好的 class KeySchedule 來使用.

幫我修改 message_layer.py 和 client.py, 其他檔案不動.
client_handshake 加在 client.py 裡面.
```

```
我系統已經安裝了這些軟體
- 不需要 sudo 的 tcpdump
- tcpflow
- CURL_BIN=/opt/homebrew/Cellar/curl/8.12.1/bin/curl

幫我寫一個 capture_url.sh
給兩個參數
第一個是 url
第二個是 directory, 把目錄建出來, 把過程和結果的檔案都放在裡面

INTERFACE=en0
用 tcpdump 捕捉 INTERFACE
連接 url, 並且只使用 TLS 1.3, 禁用更低的版本. 使用 HTTP/1.1. 不用顯示內容在畫面上.

我想看到幾個檔案
{prefix}.pcap
{prefix}.to 和 {prefix}.from (用 tcpflow 分離)
{prefix}.keylog

使用 tcpdump 時要盡早將內容存檔
結束 tcpdump 前要等一下

注意: 我連接的 port 不一定是 443, 也可能是 4433 之類的其他 port
```

```
我想要一個 class RecordLayer
construct 時會給一個 function get_bytes(n: int) -> bytes

有一個 member function get_record() -> TypeAndBytes 
會從 get_bytes() 的內容中讀取一個 TLS 1.3 的 record
並檢查 type 是否在合法的 ContentType 中
version 不檢查

不用註解. 進量少換行.
```

```
寫一段程式, 讀取 stdin, 然後用 RecordLayer parse
對每個 record 印出 type and size
```

比對這兩個 output, 看來是正確的
```
./parse_records.py < ./captures/e1/e1.from

tshark -r e1.pcap -o 'tls.keylog_file:e1.keylog' -O tls -Y 'tls.record && tcp.srcport==443' |grep -A 3 'Record Layer'
```


```
(venv) lcamel@macbookpro TrustTLS-Python % echo $PYTHONPATH
./external/tlslite-ng
(venv) lcamel@macbookpro TrustTLS-Python % python record_layer3.py < captures/long/long.from
Plaintext: 22 0200007603035b42eb9881bd9ec586b854061531fb3494065a5883f837ac82e51b16a64f205920de8d227ecf1006bd6d551f27f07f6e43ce90e9da2f39cc3398ec05ad42211786130100002e002b0002030400330024001d0020fa768c486e2565942c52cabdfd76a4fbed8d9d1680fdc90907064f5faf1a1a43
Plaintext: 20 01
========================================
Plaintext: 22 21 08000011000f0010000b000908687474702f312e
Plaintext: 22 93178 0b016bf600016bf200052c3082052830820310a0 <=== long
Plaintext: 22 520 0f000204080402006b4950bf0c127c30c438f4db
Plaintext: 22 36 14000020411cc17e830ea69385b03b80b81da280
========================================
Plaintext: 22 130 0400007e00093a80000000000000711b4c0e8bea
Plaintext: 23 280 485454502f312e3120323030204f4b0d0a416363
Plaintext: 21 2 0100
```
