import json
import os
import time
import hmac
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pynput import keyboard
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- ASCII 매핑 ----------
ASCII_CHARS = [chr(i) for i in range(32, 127)]

def create_ascii_mapping():
    shuffled = ASCII_CHARS.copy()
    secrets.SystemRandom().shuffle(shuffled)
    mapping = {char: shuffled[i] for i, char in enumerate(ASCII_CHARS)}
    with open("ascii_mapping.json", "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2)
    return mapping

def load_ascii_mapping():
    if not os.path.exists("ascii_mapping.json"):
        return create_ascii_mapping()
    with open("ascii_mapping.json", "r", encoding="utf-8") as f:
        return json.load(f)

# ---------- HMAC을 이용한 AES 키 생성 ----------
def generate_session_key(user_secret: bytes, block_hash: bytes) -> bytes:
    return hmac.new(user_secret, block_hash, hashlib.sha256).digest()  # 32바이트 AES-256 키

# ---------- AES 암호화 (ECB 모드) ----------
'''
class AESEncryptor:
    def __init__(self, key: bytes):
        assert len(key) == 32  # AES-256
        self.cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()

    def encrypt_byte(self, byte_val: bytes) -> bytes:
        padded = byte_val + b'\x00' * (16 - len(byte_val))  # AES는 16바이트 단위 블록
        return self.cipher.update(padded)
    '''
# ---------- AES 암호화 (GCB 모드) ----------
class AESEncryptor:
    def __init__(self, key: bytes):
        assert len(key) == 32  # AES-256
        self.key = key
        self.aesgcm = AESGCM(self.key)
        self.nonce = secrets.token_bytes(12)  # GCM 표준: 96비트 = 12바이트

    def encrypt_byte(self, byte_val: bytes) -> bytes:
        # GCM은 인증 태그 포함된 전체 암호문 반환
        return self.aesgcm.encrypt(self.nonce, byte_val, None)

# ---------- 실시간 입력 암호화 ----------
class RealTimeEncryptor:
    def __init__(self):
        self.mapping = load_ascii_mapping()

        # SecureRandom 기반 시크릿키 + 더미 블록해시
        self.user_secret = secrets.token_bytes(32)
        self.block_hash = secrets.token_bytes(32)

        # HMAC으로 AES 키 생성
        self.session_key = generate_session_key(self.user_secret, self.block_hash)
        self.encryptor = AESEncryptor(self.session_key)

        self.total_time = 0.0

        print(f"userSecret : {self.user_secret.hex()}")
        print(f"blockHash  : {self.block_hash.hex()}")
        print(f"sessionKey : {self.session_key.hex()}")

    def on_press(self, key):
        try:
            char = key.char
            if char in self.mapping:
                remapped_char = self.mapping[char]
                start = time.perf_counter()
                encrypted_byte = self.encryptor.encrypt_byte(remapped_char.encode("utf-8"))
                elapsed = (time.perf_counter() - start) * 1000
                self.total_time += elapsed

                print(f"[입력] '{char}' → [재정의] '{remapped_char}' → [암호문] {encrypted_byte.hex()} | {elapsed:.3f} ms | 총 누적 시간: {self.total_time:.3f} ms")
            else:
                print(f"'{char}'는 매핑되지 않은 문자입니다.")
        except AttributeError:
            if key == keyboard.Key.esc:
                print("종료합니다.")
                return False
            print(f"[특수키] {key} 무시됨.")

    def run(self):
        print("키보드 입력 대기 중입니다. 종료하려면 ESC키를 눌러주세요")
        with keyboard.Listener(on_press=self.on_press) as listener:
            listener.join()

# ---------- 실행 ----------
if __name__ == "__main__":
    RealTimeEncryptor().run()
