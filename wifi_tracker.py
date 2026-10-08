from scapy.all import sniff, Ether, IP, get_if_hwaddr
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

# 이미 전송한 단말 MAC 저장 (중복 전송 방지)
detected_devices = set()

# 제외할 MAC (브로드캐스트, 멀티캐스트 시작 대역, AP 자신)
IGNORE_MACS = {"ff:ff:ff:ff:ff:ff"}
if AP_BSSID:
    IGNORE_MACS.add(AP_BSSID)


def process_packet(packet):
    if not (packet.haslayer(Ether) and packet.haslayer(IP)):
        return

    mac_addr = packet[Ether].src.lower()

    # 제외 대상 / 이미 전송한 단말은 무시
    if mac_addr in IGNORE_MACS or mac_addr in detected_devices:
        return

    detected_devices.add(mac_addr)

    payload = {
        "bssid": AP_BSSID,
        "mac_or_serial": mac_addr,
        "ssid": AP_SSID,
    }

    try:
        response = requests.post(DASHBOARD_API, json=payload, timeout=5)
        print(f"[+] 새 단말 탐지 | MAC: {mac_addr} | 상태코드: {response.status_code}")
        if response.status_code >= 400:
            # 전송 실패 시 다음 패킷에서 재시도할 수 있도록 제거
            detected_devices.discard(mac_addr)
            print(f"    응답: {response.text}")
    except Exception as e:
        detected_devices.discard(mac_addr)
        print(f"[-] 대시보드 서버와 통신 실패: {e}")


print(f"[{TARGET_IFACE}] 접속 단말 탐지 시작 | SSID: {AP_SSID} | BSSID: {AP_BSSID}")
sniff(iface=TARGET_IFACE, prn=process_packet, store=False)