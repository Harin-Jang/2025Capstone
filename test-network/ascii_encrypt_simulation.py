import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

# 사용자 ID
user_id = "user123"

# 사용자 ASCII 매핑 테이블
ascii_mapping = {
    "A": "0x41", "B": "0x42", "C": "0x43", "D": "0x44", "E": "0x45",
    "F": "0x46", "G": "0x47", "H": "0x48", "I": "0x49", "J": "0x4A",
    "K": "0x4B", "L": "0x4C", "M": "0x4D", "N": "0x4E", "O": "0x4F",
    "P": "0x50", "Q": "0x51", "R": "0x52", "S": "0x53", "T": "0x54",
    "U": "0x55", "V": "0x56", "W": "0x57", "X": "0x58", "Y": "0x59",
    "Z": "0x5A",

    "a": "0x61", "b": "0x62", "c": "0x63", "d": "0x64", "e": "0x65",
    "f": "0x66", "g": "0x67", "h": "0x68", "i": "0x69", "j": "0x6A",
    "k": "0x6B", "l": "0x6C", "m": "0x6D", "n": "0x6E", "o": "0x6F",
    "p": "0x70", "q": "0x71", "r": "0x72", "s": "0x73", "t": "0x74",
    "u": "0x75", "v": "0x76", "w": "0x77", "x": "0x78", "y": "0x79",
    "z": "0x7A",

    "0": "0x30", "1": "0x31", "2": "0x32", "3": "0x33", "4": "0x34",
    "5": "0x35", "6": "0x36", "7": "0x37", "8": "0x38", "9": "0x39",

    "!": "0x21", "@": "0x40", "#": "0x23", "$": "0x24", "%": "0x25",
    "^": "0x5E", "&": "0x26", "*": "0x2A", "(": "0x28", ")": "0x29"
}


# 2. 직렬화
#serialized_json = json.dumps(ascii_mapping, ensure_ascii=False)
json_str = json.dumps(ascii_mapping)

# 3. AES 키 준비 (256비트)
password = "user123-secret-password"  # 사용자별 비밀번호
key = hashlib.sha256(password.encode()).digest()  # 32바이트 키로 변환

# 4. AES-GCM 모드 암호화
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(json_str.encode())
    
# 5. 암호문 + nonce + tag → 모두 base64로 인코딩
encrypted_package = {
    "nonce": base64.b64encode(cipher.nonce).decode(),
    "ciphertext": base64.b64encode(ciphertext).decode(),
    "tag": base64.b64encode(tag).decode()
}

# 6. 결과 출력
print(f"🔐 Encrypted Mapping Data:\n{json.dumps(encrypted_package, indent=2)}")

