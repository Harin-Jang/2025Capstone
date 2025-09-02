# secure_kbd_dashboard.py
import json, os, time, hmac, hashlib, secrets, threading, asyncio
from typing import Set, Optional

import psutil
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
from pynput import keyboard
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ---------- 대시보드 HTML ----------
DASHBOARD_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>Keyboard Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font-family:system-ui;margin:16px}
.grid{display:grid;grid-template-columns:repeat(19,1fr);gap:6px}
.cell{border:1px solid #ddd;padding:6px;text-align:center;border-radius:8px}
.row{display:flex;gap:16px;margin-bottom:16px}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #eee;padding:6px 8px}
small{color:#777}
</style></head><body>
<h2>Real-Time Keyboard Security Dashboard</h2>
<div class="row">
  <div style="flex:2">
    <h3>입력 → 매핑 → 암호문</h3>
    <table id="log"><thead>
      <tr><th>시간</th><th>입력</th><th>매핑</th><th>암호문(hex, 앞부분)</th></tr>
    </thead><tbody></tbody></table>
  </div>
  <div style="flex:1">
    <h3>CPU 사용률(%)</h3>
    <canvas id="cpuChart"></canvas>
    <div id="cryptoMs" style="margin-top:8px;color:#555"></div>
    <small>프로세스 전체 CPU 사용률. 입력 시 암호화 구간(ms)이 갱신됩니다.</small>
  </div>
</div>
<h3>나의 ASCII 재정의 표</h3>
<div id="mapGrid" class="grid"></div>

<script>
const tbody = document.querySelector("#log tbody");
const cpuCtx = document.getElementById('cpuChart').getContext('2d');
const cpuData = {labels:[], datasets:[{label:'Process CPU %', data:[]}]};
const cpuChart = new Chart(cpuCtx, {type:'line', data:cpuData, options:{
  animation:false, responsive:true, scales:{y:{min:0,max:100}} }});
const ws = new WebSocket(`ws://${location.host}/ws`);

function addRow(ev){
  const tr = document.createElement("tr");
  const t = new Date(ev.ts*1000).toLocaleTimeString();
  tr.innerHTML = `<td>${t}</td><td>${ev.input}</td><td>${ev.mapped}</td><td>${ev.cipher_hex}</td>`;
  tbody.prepend(tr);
  while(tbody.rows.length>20) tbody.deleteRow(20);
}
ws.onmessage = (msg)=>{
  const data = JSON.parse(msg.data);
  if(data.type === "event"){ addRow(data); }
  else if(data.type === "cpu"){
    const ts = new Date().toLocaleTimeString();
    cpuData.labels.push(ts);
    cpuData.datasets[0].data.push(data.proc_cpu);
    if(cpuData.labels.length>60){ cpuData.labels.shift(); cpuData.datasets[0].data.shift(); }
    cpuChart.update();
    document.getElementById("cryptoMs").textContent =
      `최근 암호화 구간: ${data.crypto_ms.toFixed(3)} ms`;
  }
};

fetch("/mapping").then(r=>r.json()).then(MAP=>{
  const grid = document.getElementById("mapGrid");
  const ascii = Array.from({length:95},(_,i)=>String.fromCharCode(i+32));
  ascii.forEach(ch=>{
    const div = document.createElement("div");
    div.className="cell";
    div.textContent = `${ch} → ${MAP[ch]||'?'}`;
    grid.appendChild(div);
  });
});
</script>
</body></html>"""

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

# ---------- HMAC 기반 sessionKey ----------
def generate_session_key(user_secret: bytes, block_hash: bytes) -> bytes:
    return hmac.new(user_secret, block_hash, hashlib.sha256).digest()

# ---------- SecureRandom ----------
def generate_secure_random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)

# ---------- AEAD ----------
class ChaCha20Poly1305Encryptor:
    def __init__(self, key: bytes):
        assert len(key) == 32
        self.aead = ChaCha20Poly1305(key)
    def encrypt_byte(self, nonce: bytes, byte_val: bytes) -> bytes:
        return self.aead.encrypt(nonce, byte_val, None)

# ---------- 실시간 입력 암호화 + 대시보드 연동 ----------
class RealTimeEncryptor:
    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.mapping = load_ascii_mapping()
        self.user_secret = generate_secure_random_bytes(32)
        self.block_hash = generate_secure_random_bytes(32)
        self.session_key = generate_session_key(self.user_secret, self.block_hash)
        self.encryptor = ChaCha20Poly1305Encryptor(self.session_key)

        self.total_time_ms = 0.0
        self.last_crypto_ms = 0.0
        self.encrypted_log = []  # nonce + 암호문 저장
        print(f"userSecret : {self.user_secret.hex()}")
        print(f"blockHash  : {self.block_hash.hex()}")
        print(f"sessionKey : {self.session_key.hex()}")

        # 대시보드로 보낼 이벤트 큐 (asyncio)
        self.event_q: asyncio.Queue = asyncio.Queue()

    def _broadcast_event(self, ch_in: str, remapped: str, ciphertext_hex: str):
        ev = {
            "type": "event",
            "ts": time.time(),
            "input": ch_in,
            "mapped": remapped,
            "cipher_hex": ciphertext_hex[:40]  # 앞부분만 노출
        }
        # pynput 콜백(thread) -> asyncio 루프 안전 큐
        self.loop.call_soon_threadsafe(self.event_q.put_nowait, ev)

    def on_press(self, key):
        try:
            char = key.char
            if char in self.mapping:
                remapped_char = self.mapping[char]
                nonce = generate_secure_random_bytes(12)
                t0 = time.perf_counter()
                ciphertext = self.encryptor.encrypt_byte(nonce, remapped_char.encode("utf-8"))
                self.last_crypto_ms = (time.perf_counter() - t0) * 1000.0
                self.total_time_ms += self.last_crypto_ms

                self.encrypted_log.append({
                    "nonce": nonce.hex(),
                    "cipher": ciphertext.hex()
                })
                print(f"[입력] '{char}' → '{remapped_char}' → 암호문: {ciphertext.hex()} | "
                      f"Nonce: {nonce.hex()} | {self.last_crypto_ms:.3f}ms | 누적: {self.total_time_ms:.3f}ms")

                # 대시보드 이벤트
                self._broadcast_event(char, remapped_char, ciphertext.hex())
            else:
                print(f"[무시됨] '{char}'는 매핑되지 않은 문자입니다.")
        except AttributeError:
            if key == keyboard.Key.esc:
                self.finish()
                return False
            print(f"[특수키] {key} 무시됨.")

    def finish(self):
        # JSON 파일 저장 (cipher만 해시 체인)
        with open("encrypted_log.json", "w", encoding="utf-8") as f:
            json.dump(self.encrypted_log, f, indent=2)

        combined_bytes = b''.join(bytes.fromhex(e["cipher"]) for e in self.encrypted_log)
        final_hash = hashlib.sha256(combined_bytes).hexdigest()
        print("\n[암호문+nonce JSON 저장 완료 → encrypted_log.json]")
        print(f"encrpytion[최종 암호문 해시] {final_hash}")

# ---------- FastAPI + WebSocket ----------
app = FastAPI()
clients: Set[WebSocket] = set()
PROC = psutil.Process()
PROC.cpu_percent(interval=None)  # 초기화

# encryptor 인스턴스는 main에서 생성 후 주입
_encryptor: Optional[RealTimeEncryptor] = None

@app.get("/")
def index():
    return HTMLResponse(DASHBOARD_HTML)

@app.get("/mapping")
def mapping():
    return JSONResponse(_encryptor.mapping if _encryptor else {})

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    try:
        # 수신은 하지 않지만 연결 유지
        while True:
            await asyncio.sleep(1.0)
    except Exception:
        pass
    finally:
        clients.discard(ws)

async def broadcaster_task():
    """키 이벤트와 CPU 메트릭을 주기적으로 브로드캐스트."""
    last_cpu_push = 0.0
    while True:
        # 1) 키 이벤트가 있으면 즉시 전송
        try:
            ev = await asyncio.wait_for(_encryptor.event_q.get(), timeout=0.2)
            dead = []
            for ws in clients:
                try:
                    await ws.send_text(json.dumps(ev))
                except Exception:
                    dead.append(ws)
            for d in dead:
                clients.discard(d)
        except asyncio.TimeoutError:
            pass

        # 2) CPU/암호화구간(ms) 메트릭 0.5초 간격으로 전송
        now = time.time()
        if now - last_cpu_push >= 0.5:
            cpu_proc = PROC.cpu_percent(interval=None)
            payload = {"type":"cpu", "proc_cpu": cpu_proc,
                       "crypto_ms": (_encryptor.last_crypto_ms if _encryptor else 0.0)}
            dead = []
            for ws in clients:
                try:
                    await ws.send_text(json.dumps(payload))
                except Exception:
                    dead.append(ws)
            for d in dead:
                clients.discard(d)
            last_cpu_push = now

# ---------- 실행 ----------
if __name__ == "__main__":
    async def main():
        global _encryptor
        loop = asyncio.get_running_loop()

        # 암호화기 초기화 (이 루프에 귀속)
        _encryptor = RealTimeEncryptor(loop)

        # 브로드캐스터 태스크 시작 (같은 루프)
        task_broadcaster = asyncio.create_task(broadcaster_task())

        print("대시보드: http://127.0.0.1:8765/  (브라우저로 열기)")
        print("키보드 입력 대기 중입니다. 종료하려면 ESC를 누르세요.")

        # uvicorn 서버 구성 (같은 이벤트 루프에서 실행)
        config = uvicorn.Config(app, host="127.0.0.1", port=8765,
                                log_level="warning", loop="asyncio")
        server = uvicorn.Server(config)

        # pynput Listener는 블로킹 → 별도 스레드에서 실행
        def listen():
            with keyboard.Listener(on_press=_encryptor.on_press) as listener:
                listener.join()
            # ESC로 종료되면 uvicorn 서버 종료 신호
            server.should_exit = True

        lt = threading.Thread(target=listen, daemon=True)
        lt.start()

        # 서버 실행(should_exit True가 되면 반환)
        await server.serve()

        # 브로드캐스터 종료
        task_broadcaster.cancel()
        try:
            await task_broadcaster
        except asyncio.CancelledError:
            pass

    asyncio.run(main())