import subprocess
import time
import csv
import os

# 조직 정보 설정
orgs = {
    "Org1MSP": {
        "CORE_PEER_LOCALMSPID": "Org1MSP",
        "CORE_PEER_ADDRESS": "localhost:7051",
        "CORE_PEER_TLS_ROOTCERT_FILE": "organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
        "CORE_PEER_MSPCONFIGPATH": "organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
    },
    "Org2MSP": {
        "CORE_PEER_LOCALMSPID": "Org2MSP",
        "CORE_PEER_ADDRESS": "localhost:9051",
        "CORE_PEER_TLS_ROOTCERT_FILE": "organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt",
        "CORE_PEER_MSPCONFIGPATH": "organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
    },
    "Org3MSP": {
        "CORE_PEER_LOCALMSPID": "Org3MSP",
        "CORE_PEER_ADDRESS": "localhost:11051",
        "CORE_PEER_TLS_ROOTCERT_FILE": "organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt",
        "CORE_PEER_MSPCONFIGPATH": "organizations/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp"
    }
}

# 상수 정보
CHANNEL_NAME = "userchannel"
CHAINCODE_NAME = "ascii_cc"
VERSION = "1.0"
SEQUENCE = "3"  # 현재 sequence보다 1 크게 (예: 2였다면 3)
PACKAGE_ID = "ascii_cc_1:ee6763e653c45c22c000b0193d32934bcbff83e7e32798d3b773dce272749164"
ORDERER_CA = "organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem"

results = []

for org, env in orgs.items():
    print(f"🔍 Measuring approval time for {org}...")

    # 환경변수 설정
    base_env = {
        "CORE_PEER_LOCALMSPID": env["CORE_PEER_LOCALMSPID"],
        "CORE_PEER_ADDRESS": env["CORE_PEER_ADDRESS"],
        "CORE_PEER_TLS_ROOTCERT_FILE": env["CORE_PEER_TLS_ROOTCERT_FILE"],
        "CORE_PEER_MSPCONFIGPATH": env["CORE_PEER_MSPCONFIGPATH"],
        "FABRIC_CFG_PATH": "../config"
    }

    # 승인 명령 실행 및 시간 측정
    start_time = time.time()

    cmd = [
        "peer", "lifecycle", "chaincode", "approveformyorg",
        "--orderer", "localhost:7050",
        "--ordererTLSHostnameOverride", "orderer.example.com",
        "--channelID", CHANNEL_NAME,
        "--name", CHAINCODE_NAME,
        "--version", VERSION,
        "--package-id", PACKAGE_ID,
        "--sequence", SEQUENCE,
        "--tls", "--cafile", ORDERER_CA
    ]

    try:
        subprocess.run(cmd, env={**base_env, **dict(os.environ)}, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        end_time = time.time()
        duration = round(end_time - start_time, 2)
        print(f"✅ {org} approval took {duration} seconds")
        results.append([org, duration])
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to approve for {org}")
        results.append([org, -1])

# 결과 CSV 저장
with open("approval_times.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Organization", "ApprovalTimeSeconds"])
    writer.writerows(results)

print("📁 Saved to approval_times.csv")
