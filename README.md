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