import time
from scapy.all import AsyncSniffer, Ether, IP, get_if_hwaddr
import requests

# 1. 대상 가상 어댑터 이름
TARGET_IFACE = "로컬 영역 연결* 2"

# 2. 대시보드 API
DASHBOARD_API = "https://sat-center.zuni.kim/api/v1/track/wifi"

# 3. 훈련용 AP 정보 (SSID는 실제 핫스팟 이름으로 수정)
AP_SSID = "Ransom 0"

# BSSID: 핫스팟 가상 어댑터의 MAC 주소를 자동으로 가져옴
# 자동 조회가 실패하면 아래 AP_BSSID_FALLBACK에 직접 입력 (예: "aa:bb:cc:dd:ee:ff")
AP_BSSID_FALLBACK = None
try:
    AP_BSSID = get_if_hwaddr(TARGET_IFACE).lower()
except Exception:
    AP_BSSID = AP_BSSID_FALLBACK.lower() if AP_BSSID_FALLBACK else None

# 단말 관리
seen_devices = set()      # 로컬에서 처음 감지된 단말 (콘솔 알림 중복 방지)
sent_devices = set()      # 대시보드 서버 전송에 성공한 단말
last_attempt = {}         # 최근 서버 전송 시도 시각 {mac: timestamp}
RETRY_COOLDOWN = 30       # 전송 실패 시 재시도 대기 시간 (초)

# 제외할 MAC (브로드캐스트, 멀티캐스트 시작 대역, AP 자신)
IGNORE_MACS = {"ff:ff:ff:ff:ff:ff"}
if AP_BSSID:
    IGNORE_MACS.add(AP_BSSID)


def process_packet(packet):
    if not (packet.haslayer(Ether) and packet.haslayer(IP)):
        return

    mac_addr = packet[Ether].src.lower()

    # 제외 대상이거나 이미 대시보드 전송에 성공한 단말은 무시
    if mac_addr in IGNORE_MACS or mac_addr in sent_devices:
        return

    now = time.time()
    # 최근에 전송 시도 후 실패한 단말은 쿨다운 시간 동안 재시도 보류
    if mac_addr in last_attempt and (now - last_attempt[mac_addr]) < RETRY_COOLDOWN:
        return

    # 처음 발견된 단말인 경우 1회만 콘솔에 감지 출력
    if mac_addr not in seen_devices:
        seen_devices.add(mac_addr)
        print(f"[+] 새 단말 감지 | MAC: {mac_addr}")

    last_attempt[mac_addr] = now

    payload = {
        "bssid": AP_BSSID,
        "mac_or_serial": mac_addr,
        "ssid": AP_SSID,
    }

    try:
        response = requests.post(DASHBOARD_API, json=payload, timeout=5)
        if 200 <= response.status_code < 300:
            sent_devices.add(mac_addr)
            print(f"    [OK] 대시보드 전송 성공 | MAC: {mac_addr} | 상태코드: {response.status_code}")
        else:
            print(f"    [-] 대시보드 전송 실패 | MAC: {mac_addr} | 상태코드: {response.status_code} ({RETRY_COOLDOWN}초 후 재시도)")
            if response.text.strip():
                print(f"        응답: {response.text.strip()}")
    except Exception as e:
        print(f"    [-] 대시보드 통신 오류 | MAC: {mac_addr} | {e} ({RETRY_COOLDOWN}초 후 재시도)")


print(f"[{TARGET_IFACE}] 접속 단말 탐지 시작 | SSID: {AP_SSID} | BSSID: {AP_BSSID}")
print("[*] 종료하려면 Ctrl+C를 누르세요.")

sniffer = AsyncSniffer(iface=TARGET_IFACE, prn=process_packet, store=False)
sniffer.start()

try:
    while sniffer.running:
        time.sleep(0.5)
except KeyboardInterrupt:
    print("\n[!] 탐지를 중단합니다...")
finally:
    if sniffer.running:
        sniffer.stop()
    print("[*] 안전하게 종료되었습니다.")