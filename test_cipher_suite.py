"""
測試程序，比較 CipherSuite 和 KeyScheduleFunctions 兩個類的結果。

此程序驗證 CipherSuite 類的實現與原始 KeyScheduleFunctions 類的功能一致。
"""

import hashlib
import os
from key_schedule_functions import KeyScheduleFunctions
from cipher_suite import TLS_AES_128_GCM_SHA256

def test_hkdf_extract():
    """測試 HKDF_extract 方法"""
    print("測試 HKDF_extract 方法...")
    
    # 使用相同的鹽和輸入密鑰材料
    salt = os.urandom(32)  # 隨機生成 32 字節的鹽
    ikm = os.urandom(32)   # 隨機生成 32 字節的輸入密鑰材料
    
    # 使用 KeyScheduleFunctions
    ksf = KeyScheduleFunctions(hashlib.sha256)
    ksf_result = ksf.HKDF_extract(salt, ikm)
    
    # 使用預定義的 TLS_AES_128_GCM_SHA256 常量
    cs_result = TLS_AES_128_GCM_SHA256.HKDF_extract(salt, ikm)
    
    # 比較結果
    if ksf_result == cs_result:
        print("HKDF_extract 測試通過: 兩者結果一致")
    else:
        print("HKDF_extract 測試失敗: 結果不一致")
        print(f"KeyScheduleFunctions 結果: {ksf_result.hex()}")
        print(f"CipherSuite 結果: {cs_result.hex()}")

def test_hkdf_expand():
    """測試 HKDF_expand 方法"""
    print("測試 HKDF_expand 方法...")
    
    # 使用相同的偽隨機密鑰、附加信息和長度
    prk = os.urandom(32)   # 隨機生成 32 字節的偽隨機密鑰
    info = b"test info"
    length = 32
    
    # 使用 KeyScheduleFunctions
    ksf = KeyScheduleFunctions(hashlib.sha256)
    ksf_result = ksf.HKDF_expand(prk, info, length)
    
    # 使用預定義的 TLS_AES_128_GCM_SHA256 常量
    cs_result = TLS_AES_128_GCM_SHA256.HKDF_expand(prk, info, length)
    
    # 比較結果
    if ksf_result == cs_result:
        print("HKDF_expand 測試通過: 兩者結果一致")
    else:
        print("HKDF_expand 測試失敗: 結果不一致")
        print(f"KeyScheduleFunctions 結果: {ksf_result.hex()}")
        print(f"CipherSuite 結果: {cs_result.hex()}")

def test_hkdf_expand_label():
    """測試 hkdf_expand_label 方法"""
    print("測試 hkdf_expand_label 方法...")
    
    # 使用相同的密鑰材料、標籤、上下文和長度
    secret = os.urandom(32)
    label = b"tls13 label"
    context = b"context"
    length = 16
    
    # 使用 KeyScheduleFunctions
    ksf = KeyScheduleFunctions(hashlib.sha256)
    ksf_result = ksf.hkdf_expand_label(secret, label, context, length)
    
    # 使用預定義的 TLS_AES_128_GCM_SHA256 常量
    cs_result = TLS_AES_128_GCM_SHA256.hkdf_expand_label(secret, label, context, length)
    
    # 比較結果
    if ksf_result == cs_result:
        print("hkdf_expand_label 測試通過: 兩者結果一致")
    else:
        print("hkdf_expand_label 測試失敗: 結果不一致")
        print(f"KeyScheduleFunctions 結果: {ksf_result.hex()}")
        print(f"CipherSuite 結果: {cs_result.hex()}")

def test_derive_secret():
    """測試 derive_secret 方法"""
    print("測試 derive_secret 方法...")
    
    # 使用相同的密鑰材料、標籤和消息
    secret = os.urandom(32)
    label = b"derived"
    messages = b"example transcript message"
    
    # 使用 KeyScheduleFunctions
    ksf = KeyScheduleFunctions(hashlib.sha256)
    ksf_result = ksf.derive_secret(secret, label, messages)
    
    # 使用預定義的 TLS_AES_128_GCM_SHA256 常量
    cs_result = TLS_AES_128_GCM_SHA256.derive_secret(secret, label, messages)
    
    # 比較結果
    if ksf_result == cs_result:
        print("derive_secret 測試通過: 兩者結果一致")
    else:
        print("derive_secret 測試失敗: 結果不一致")
        print(f"KeyScheduleFunctions 結果: {ksf_result.hex()}")
        print(f"CipherSuite 結果: {cs_result.hex()}")

def test_traffic_key_and_iv():
    """測試 traffic_key_and_iv 方法"""
    print("測試 traffic_key_and_iv 方法...")
    
    # 使用相同的交通密鑰
    traffic_secret = os.urandom(32)
    
    # 使用 KeyScheduleFunctions
    ksf = KeyScheduleFunctions(hashlib.sha256)
    ksf_key, ksf_iv = ksf.traffic_key_and_iv(traffic_secret)
    
    # 使用預定義的 TLS_AES_128_GCM_SHA256 常量
    cs_key, cs_iv = TLS_AES_128_GCM_SHA256.traffic_key_and_iv(traffic_secret)
    
    # 比較結果
    if ksf_key == cs_key and ksf_iv == cs_iv:
        print("traffic_key_and_iv 測試通過: 兩者結果一致")
    else:
        print("traffic_key_and_iv 測試失敗: 結果不一致")
        if ksf_key != cs_key:
            print(f"密鑰不一致:")
            print(f"KeyScheduleFunctions 密鑰: {ksf_key.hex()}")
            print(f"CipherSuite 密鑰: {cs_key.hex()}")
        if ksf_iv != cs_iv:
            print(f"IV 不一致:")
            print(f"KeyScheduleFunctions IV: {ksf_iv.hex()}")
            print(f"CipherSuite IV: {cs_iv.hex()}")

def test_tls13_key_schedule():
    """測試 TLS 1.3 完整密鑰派生流程"""
    print("測試 TLS 1.3 完整密鑰派生流程...")
    
    # 初始化
    ksf = KeyScheduleFunctions(hashlib.sha256)
    
    # 模擬 TLS 1.3 密鑰派生
    # 1. 計算 early_secret
    psk = bytes(32)  # 全零 PSK
    ksf_early_secret = ksf.HKDF_extract(None, psk)
    cs_early_secret = TLS_AES_128_GCM_SHA256.HKDF_extract(None, psk)
    
    # 2. 派生 empty_hash - 使用 hash_func 方法
    empty_hash = TLS_AES_128_GCM_SHA256.hash_func(b"")
    
    # 3. 派生 derived_secret
    ksf_derived_secret = ksf.hkdf_expand_label(ksf_early_secret, b"derived", empty_hash, 32)
    cs_derived_secret = TLS_AES_128_GCM_SHA256.hkdf_expand_label(cs_early_secret, b"derived", empty_hash, 32)
    
    # 4. 計算 handshake_secret
    dh_shared_secret = os.urandom(32)  # 模擬 DH 共享密鑰
    ksf_handshake_secret = ksf.HKDF_extract(ksf_derived_secret, dh_shared_secret)
    cs_handshake_secret = TLS_AES_128_GCM_SHA256.HKDF_extract(cs_derived_secret, dh_shared_secret)
    
    # 5. 派生客戶端和服務器握手流量密鑰
    # 使用 hash_func 方法簡化哈希計算
    transcript_hash = TLS_AES_128_GCM_SHA256.hash_func(b"client_hello, server_hello")  # 模擬握手訊息哈希
    
    ksf_client_handshake_secret = ksf.hkdf_expand_label(ksf_handshake_secret, 
                                                      b"c hs traffic", 
                                                      transcript_hash, 
                                                      32)
    cs_client_handshake_secret = TLS_AES_128_GCM_SHA256.hkdf_expand_label(cs_handshake_secret, 
                                                    b"c hs traffic", 
                                                    transcript_hash, 
                                                    32)
    
    ksf_server_handshake_secret = ksf.hkdf_expand_label(ksf_handshake_secret, 
                                                      b"s hs traffic", 
                                                      transcript_hash, 
                                                      32)
    cs_server_handshake_secret = TLS_AES_128_GCM_SHA256.hkdf_expand_label(cs_handshake_secret, 
                                                    b"s hs traffic", 
                                                    transcript_hash, 
                                                    32)
    
    # 6. 派生握手流量密鑰和 IV
    ksf_client_key, ksf_client_iv = ksf.traffic_key_and_iv(ksf_client_handshake_secret)
    cs_client_key, cs_client_iv = TLS_AES_128_GCM_SHA256.traffic_key_and_iv(cs_client_handshake_secret)
    
    ksf_server_key, ksf_server_iv = ksf.traffic_key_and_iv(ksf_server_handshake_secret)
    cs_server_key, cs_server_iv = TLS_AES_128_GCM_SHA256.traffic_key_and_iv(cs_server_handshake_secret)
    
    # 比較結果
    if (ksf_client_key == cs_client_key and 
        ksf_client_iv == cs_client_iv and 
        ksf_server_key == cs_server_key and 
        ksf_server_iv == cs_server_iv):
        print("TLS 1.3 密鑰派生測試通過: 兩者結果一致")
    else:
        print("TLS 1.3 密鑰派生測試失敗: 結果不一致")
        print("客戶端密鑰比較:")
        print(f"KeyScheduleFunctions: {ksf_client_key.hex()}")
        print(f"CipherSuite: {cs_client_key.hex()}")
        print("客戶端 IV 比較:")
        print(f"KeyScheduleFunctions: {ksf_client_iv.hex()}")
        print(f"CipherSuite: {cs_client_iv.hex()}")
        print("伺服器密鑰比較:")
        print(f"KeyScheduleFunctions: {ksf_server_key.hex()}")
        print(f"CipherSuite: {cs_server_key.hex()}")
        print("伺服器 IV 比較:")
        print(f"KeyScheduleFunctions: {ksf_server_iv.hex()}")
        print(f"CipherSuite: {cs_server_iv.hex()}")

if __name__ == "__main__":
    print("開始測試 CipherSuite 與 KeyScheduleFunctions 類的結果比較\n")
    
    test_hkdf_extract()
    print()
    
    test_hkdf_expand()
    print()
    
    test_hkdf_expand_label()
    print()
    
    test_derive_secret()
    print()
    
    test_traffic_key_and_iv()
    print()
    
    test_tls13_key_schedule()
    print()
    
    print("所有測試完成")