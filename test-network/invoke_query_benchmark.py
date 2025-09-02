import subprocess
import time
import csv
import json

def run_command(command: str) -> float:
    start = time.time()
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        print("❌ 실패:", e.stderr.decode())
    end = time.time()
    return round(end - start, 3)

def main():
    user_id = "benchmark_user"
    ascii_mapping = {
        "a": "X1", "b": "X2", "c": "X3",
        "d": "X4", "e": "X5", "f": "X6",
        "g": "X7", "h": "X8", "i": "X9",
    }
    # JSON 문자열 직렬화
    mapping_json = json.dumps(ascii_mapping)

    invoke_cmd = f'''peer chaincode invoke \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile $ORDERER_CA \
  -C userchannel \
  -n ascii_cc \
  --peerAddresses localhost:7051 \
  --tlsRootCertFiles $PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt \
  --peerAddresses localhost:11051 \
  --tlsRootCertFiles $PWD/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt \
  -c '{{"function":"SetMapping","Args":["{user_id}",{json.dumps(mapping_json)}]}}' '''

    query_cmd = f'''peer chaincode query \
  -C userchannel \
  -n ascii_cc \
  --peerAddresses localhost:11051 \
  --tlsRootCertFiles $PWD/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt \
  -c '{{"function":"GetMapping","Args":["{user_id}"]}}' '''

    invoke_times, query_times = [], []

    print("🔄 Invoke 10회 측정 중...")
    for i in range(10):
        t = run_command(invoke_cmd)
        print(f"Invoke ⏱️ {t}초")
        invoke_times.append(t)
        time.sleep(2)

    print("\n🔎 Query 10회 측정 중...")
    for i in range(10):
        t = run_command(query_cmd)
        print(f"Query ⏱️ {t}초")
        query_times.append(t)
        time.sleep(1)

    with open("invoke_query_times.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Operation", "TimeSeconds"])
        for t in invoke_times:
            writer.writerow(["Invoke", t])
        for t in query_times:
            writer.writerow(["Query", t])

    print("\n✅ 결과가 'invoke_query_times.csv' 파일에 저장되었습니다.")

if __name__ == "__main__":
    main()
