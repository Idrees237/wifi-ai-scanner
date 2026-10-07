import platform
import subprocess
from datetime import datetime
import pandas as pd

from parser import parse_windows, parse_linux, parse_macos

COLUMNS = [
    "SSID",
    "BSSID",
    "channel",
    "signal",
    "security",
    "timestamp"
]


def mock_scan():

    now = datetime.now().isoformat()

    data = [
        ["Home_2G", "AA:BB:CC:00:00:01", 1, -42, "WPA2", now],
        ["Coffee_WiFi", "AA:BB:CC:00:00:02", 1, -67, "Open", now],
        ["Office", "AA:BB:CC:00:00:03", 6, -55, "WPA2", now],
        ["Guest", "AA:BB:CC:00:00:04", 6, -72, "WEP", now],
        ["Home_5G", "AA:BB:CC:00:00:05", 36, -48, "WPA3", now],
        ["Campus", "AA:BB:CC:00:00:06", 40, -61, "WPA2", now],
        ["Library", "AA:BB:CC:00:00:07", 44, -70, "WPA", now],
    ]

    return pd.DataFrame(data, columns=COLUMNS)


def scan_wifi(mock=False):

    if mock:
        return mock_scan()

    system = platform.system()

    try:

        if system == "Windows":

            result = subprocess.run(
                [
                    "netsh",
                    "wlan",
                    "show",
                    "networks",
                    "mode=bssid"
                ],
                capture_output=True,
                text=True,
                timeout=20
            )

            rows = parse_windows(result.stdout)

        elif system == "Linux":

            result = subprocess.run(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    "SSID,BSSID,CHAN,SIGNAL,SECURITY",
                    "dev",
                    "wifi"
                ],
                capture_output=True,
                text=True,
                timeout=20
            )

            rows = parse_linux(result.stdout)

        elif system == "Darwin":

            result = subprocess.run(
                ["airport", "-s"],
                capture_output=True,
                text=True,
                timeout=20
            )

            rows = parse_macos(result.stdout)

        else:

            return pd.DataFrame(columns=COLUMNS)

        timestamp = datetime.now().isoformat()

        for row in rows:
            row["timestamp"] = timestamp

        return pd.DataFrame(rows, columns=COLUMNS)

    except Exception as e:

        print("Scan error:", e)

        return pd.DataFrame(columns=COLUMNS)