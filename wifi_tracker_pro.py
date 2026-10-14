import time
from scapy.all import AsyncSniffer, Ether, IP, ARP, UDP, DNS, DNSQR, DHCP, get_if_hwaddr
import requests

# 1. 대상 가상 어댑터 이름
TARGET_IFACE = "로컬 영역 연결* 2"

# 2. 대시보드 API
DASHBOARD_API     = "https://rguard.store/api/v1/track/wifi"      # 최초 1회
DASHBOARD_API_PRO = "https://rguard.store/api/v1/track/wifi-pro"  # 이후 갱신

# 3. 훈련용 AP 정보
AP_SSID = "Ransom 0"

AP_BSSID_FALLBACK = None
try:
    AP_BSSID = get_if_hwaddr(TARGET_IFACE).lower()
except Exception:
    AP_BSSID = AP_BSSID_FALLBACK.lower() if AP_BSSID_FALLBACK else None

# 단말 관리
seen_devices = set()   # 처음 감지된 단말 (콘솔 중복 방지)
sent_devices = set()   # wifi API 최초 전송 성공 단말
last_attempt = {}      # 최근 wifi 전송 시도 시각 {mac: timestamp}
RETRY_COOLDOWN = 30

# 단말별 부가 정보
device_info = {}

IGNORE_MACS = {"ff:ff:ff:ff:ff:ff"}
if AP_BSSID:
    IGNORE_MACS.add(AP_BSSID)


def get_info(mac):
    if mac not in device_info:
        device_info[mac] = {
            "ip":         None,
            "hostname":   None,
            "dns":        set(),
            "first_seen": time.time(),   # 최초 감지 시각
            "last_seen":  time.time(),   # 마지막 패킷 시각
            "packets":    0,             # 패킷 수
            "bytes":      0,             # 누적 바이트
        }
    return device_info[mac]


# ─── wifi-pro 갱신 전송 ───────────────────────────────────────────────────────
def send_pro_update(mac, info, reason=""):
    elapsed = time.time() - info["first_seen"]
    payload = {
        "bssid":            AP_BSSID,
        "mac_or_serial":    mac,
        "ssid":             AP_SSID,
        "ip":               info["ip"],
        "hostname":         info["hostname"],
        "dns_queries":      list(info["dns"]),
        "packets":          info["packets"],
        "bytes":            info["bytes"],
        "connected_seconds": round(elapsed, 1),
    }
    tag = f":{reason}" if reason else ""
    try:
        response = requests.post(DASHBOARD_API_PRO, json=payload, timeout=5)
        if 200 <= response.status_code < 300:
            print(f"    [PRO{tag}] 갱신 전송 성공 | MAC: {mac} | 상태코드: {response.status_code}")
        else:
            print(f"    [PRO{tag}] 갱신 전송 실패 | MAC: {mac} | 상태코드: {response.status_code}")
            if response.text.strip():
                print(f"        응답: {response.text.strip()}")
    except Exception as e:
        print(f"    [PRO{tag}] 통신 오류 | MAC: {mac} | {e}")


# ─── 패킷에서 정보 추출 및 갱신 ──────────────────────────────────────────────
def update_info(packet, mac):
    info = get_info(mac)
    ip_changed       = False
    hostname_changed = False

    # 통신량 갱신
    info["last_seen"] = time.time()
    info["packets"]  += 1
    info["bytes"]    += len(packet)

    # IP 주소
    new_ip = None
    if packet.haslayer(IP) and packet[IP].src != "0.0.0.0":
        new_ip = packet[IP].src
    elif packet.haslayer(ARP) and packet[ARP].op in (1, 2):
        if packet[ARP].psrc != "0.0.0.0":
            new_ip = packet[ARP].psrc

    if new_ip and new_ip != info["ip"]:
        info["ip"] = new_ip
        ip_changed = True

    # 호스트명 (DHCP Option 12)
    if packet.haslayer(DHCP):
        for opt in packet[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "hostname":
                val = opt[1]
                val = val.decode(errors="ignore") if isinstance(val, bytes) else val
                if val and val != info["hostname"]:
                    info["hostname"] = val
                    hostname_changed = True

    # IP/호스트명 변경 → 콘솔 출력 + wifi-pro 갱신 전송
    if ip_changed or hostname_changed:
        elapsed = time.time() - info["first_seen"]
        reason  = ("IP변경" if ip_changed else "") + ("Host변경" if hostname_changed else "")
        print(f"    [INFO] 단말 정보 갱신 | MAC: {mac} | IP: {info['ip']} | Host: {info['hostname']} | "
              f"접속시간: {round(elapsed)}초 | 통신량: {info['bytes']}B / {info['packets']}pkt")
        if mac in sent_devices:
            send_pro_update(mac, info, reason=reason)

    # DNS 쿼리 → 새 도메인이면 콘솔 출력 + wifi-pro 갱신 전송
    if packet.haslayer(DNSQR) and packet.haslayer(UDP) and packet[UDP].dport == 53:
        qname = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
        if qname and qname not in info["dns"]:
            info["dns"].add(qname)
            elapsed = time.time() - info["first_seen"]
            print(f"    [DNS] 새 도메인 접속 | MAC: {mac} | IP: {info['ip']} | Domain: {qname} | "
                  f"접속시간: {round(elapsed)}초 | 통신량: {info['bytes']}B / {info['packets']}pkt")
            if mac in sent_devices:
                send_pro_update(mac, info, reason="DNS추가")


# ─── 메인 패킷 처리 ───────────────────────────────────────────────────────────
def process_packet(packet):
    if not packet.haslayer(Ether):
        return

    mac_addr = packet[Ether].src.lower()

    if mac_addr in IGNORE_MACS:
        return

    update_info(packet, mac_addr)

    # 처음 발견 시 감지 로그 출력
    if mac_addr not in seen_devices:
        seen_devices.add(mac_addr)
        info = get_info(mac_addr)
        print(f"[+] 새 단말 감지 | MAC: {mac_addr} | IP: {info['ip']} | Host: {info['hostname']}")

    # 최초 전송 성공 이후는 update_info() 안에서 wifi-pro로 갱신 전송하므로 여기서 종료
    if mac_addr in sent_devices:
        return

    if not packet.haslayer(IP):
        return

    now = time.time()
    if mac_addr in last_attempt and (now - last_attempt[mac_addr]) < RETRY_COOLDOWN:
        return

    last_attempt[mac_addr] = now
    info    = get_info(mac_addr)
    elapsed = time.time() - info["first_seen"]

    payload = {
        "bssid":            AP_BSSID,
        "mac_or_serial":    mac_addr,
        "ssid":             AP_SSID,
        "ip":               info["ip"],
        "hostname":         info["hostname"],
        "dns_queries":      list(info["dns"]),
        "packets":          info["packets"],
        "bytes":            info["bytes"],
        "connected_seconds": round(elapsed, 1),
    }

    try:
        response = requests.post(DASHBOARD_API, json=payload, timeout=5)
        if 200 <= response.status_code < 300:
            sent_devices.add(mac_addr)
            print(f"    [OK] 최초 전송 성공 | MAC: {mac_addr} | IP: {info['ip']} | "
                  f"Host: {info['hostname']} | 접속시간: {round(elapsed)}초 | "
                  f"통신량: {info['bytes']}B / {info['packets']}pkt | 상태코드: {response.status_code}")
        else:
            print(f"    [-] 최초 전송 실패 | MAC: {mac_addr} | 상태코드: {response.status_code} ({RETRY_COOLDOWN}초 후 재시도)")
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
