```
我想要一個 class CipherSuite 存到 cipher_suite.py
constructor 可以指定 hash_alg (使用 cryptography package 的, 如 sha256)
constructor 可以指定 aead_alg (使用 cryptography package 的, 如 AESGCM)
可以指定 AEAD key length, iv length
實作 external/tlslite-ng/key_schedule_functions.py 的所有 function
不要用 python 原本的 hmac
hash_func 改成 cryptography 的 
```

```
請幫我使用 Python 和 cryptography 套件實現一個 TLS 1.3 密碼套件（CipherSuite）類，要求如下：

1. 創建一個名為 cipher_suite.py 的檔案
2. 實現 CipherSuite 類，用於 TLS 1.3 密鑰派生和加密函數
3. 類需要支援以下 TLS 1.3 密鑰排程函數：
   - HKDF_extract
   - HKDF_expand
   - hkdf_expand_label
   - derive_secret
   - traffic_key_and_iv

技術要求：
- 使用 cryptography 套件而不是 Python 內建的 hmac 模組
- 接受哈希算法類（例如 hashes.SHA256）和 AEAD 加密算法類（例如 AESGCM）作為構造函數的參數
- 提供便利方法 hash_func() 用於直接計算哈希值
- 提供便利方法 hmac_func() 用於直接計算 HMAC 值
- 在模組級別提供預設的 TLS_AES_128_GCM_SHA256 常量，配置為 TLS 1.3 標準密碼套件

函數實現要求：
1. HKDF_extract: 按照 RFC 5869 實現，從 IKM 和 salt 中提取偽隨機密鑰
2. HKDF_expand: 按照 RFC 5869 實現，擴展密鑰材料到指定長度
3. hkdf_expand_label: 按照 TLS 1.3 (RFC 8446) 實現，用於標籤化的密鑰擴展
4. derive_secret: 按照 TLS 1.3 實現，從訊息和密鑰派生新的密鑰
5. traffic_key_and_iv: 按照 TLS 1.3 實現，從交通密鑰派生加密密鑰和 IV

代碼應該可以與 tlslite-ng 庫中的 key_schedule_functions.py 功能兼容，並使用 cryptography 套件提供的更現代的密碼學實現。

提供配置好的 TLS_AES_128_GCM_SHA256 常量以便與 TLS 1.3 協議中的標準密碼套件直接配合使用。
```


```
幫我把這張圖整理成一些公式
最上面的 0 和最左邊的 0 用 "ZERO" 表示
我想要這樣的公式:
Early Secret = HKDF-Extract(ZERO, PSK)
binder_key = Derive-Secret(Early Secret, "ext binder" | "res binder", "")
```


```
Early Secret = HKDF-Extract(ZERO, PSK)

binder_key = Derive-Secret(Early Secret, "ext binder" | "res binder", "")
client_early_traffic_secret = Derive-Secret(Early Secret, "c e traffic", ClientHello)
early_exporter_master_secret = Derive-Secret(Early Secret, "e exp master", ClientHello)
derived_secret = Derive-Secret(Early Secret, "derived", "")

Handshake Secret = HKDF-Extract(derived_secret, (EC)DHE)

client_handshake_traffic_secret = Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello)
server_handshake_traffic_secret = Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello)
derived_secret_handshake = Derive-Secret(Handshake Secret, "derived", "")

Master Secret = HKDF-Extract(derived_secret_handshake, ZERO)

client_application_traffic_secret_0 = Derive-Secret(Master Secret, "c ap traffic", ClientHello...server Finished)
server_application_traffic_secret_0 = Derive-Secret(Master Secret, "s ap traffic", ClientHello...server Finished)
exporter_master_secret = Derive-Secret(Master Secret, "exp master", ClientHello...server Finished)
resumption_master_secret = Derive-Secret(Master Secret, "res master", ClientHello...client Finished)
```

```
幫我寫一個 class KeySchedule3
放在 key_schedule3.py 裡面
我希望有這些 function:
set_PSK
(先跳過 binder_key)
set_DHE
set_transcript(data, nth)
其中 nth 的值是 0, 1, 2, 3
0 代表到 ClientHello 為止
1 代表到 ServerHello 為止
2 代表到 server Finished 為止
3 代表到 client Finished 為止
幫我把 0 1 2 3 這四個值取對應的 constant 名稱

被 set 的欄位本來都是 None, set 給的 input 必定不可以是 None. 但可以是 hash length 長度的 constant ZERO.
set 以後就不能重複 set.

有一些 get function, 像 get_client_handshake_traffic_secret()
裡面會去呼叫 dependency 像 get_handshake_secret()
如果拿回的 dependency 是 None 則 raise error
會把計算結果在內部儲存下來
```


```
幫我寫一個 class KeySchedule2
放在 key_schedule.py 裡面
我希望有這些 function:
set_PSK
(先跳過 binder_key)
set_DHE
set_transcript(data, nth)
其中 nth 的值是 0, 1, 2, 3
0 代表到 ClientHello 為止
1 代表到 ServerHello 為止
2 代表到 server Finished 為止
3 代表到 client Finished 為止
幫我把 0 1 2 3 這四個值取對應的 constant 名稱

當 set 了足夠的資訊以後, 就會把目前能計算的值都算出來
比方說 set_PSK 之後, early_secret 和 client_early_traffic_secret 和 early_exporter_master_secret 就能算出來, 把結果儲存在對應名稱的 public data member 裡.
```

```
幫我寫一個測試程式
from key_schedule import KeySchedule
from key_schedule2 import KeySchedule2

其中 external/tlslite-ng/key_schedule.py 因為已經在 PYTHONPATH 了, 所以寫簡短的 from 就好了

幫我比對 KeySchedule 和 KeySchedule2 的實作是否一致
```

```
我希望 class KeySchedule2 和 class KeySchedule 比較, 而不是光和 KeyScheduleFunctions 比較
```