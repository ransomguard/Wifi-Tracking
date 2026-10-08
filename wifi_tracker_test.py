import requests

DASHBOARD_API = "https://sat-center.zuni.kim/api/v1/track/wifi"
AP_SSID = "Ransom 0"

# 테스트용 가짜 데이터 (단말 MAC)
TEST_DATA = [
    "aa:aa:aa:aa:aa:aa",
    "bb:bb:bb:bb:bb:bb",
    "cc:cc:cc:cc:cc:cc"
]

for mac in TEST_DATA:
    payload = {
        "mac_or_serial": mac,
        "ssid": AP_SSID,
    }
    try:
        r = requests.post(DASHBOARD_API, json=payload, timeout=5)
        print(f"[+] 새 단말 탐지 | MAC: {mac} | 상태코드: {r.status_code}")
        if r.status_code >= 400:
            print(f"    응답: {r.text}")
    except Exception as e:
        print(f"[-] 통신 실패 (BSSID: {bssid}): {e}")