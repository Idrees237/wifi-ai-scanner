import re


def security_type(value):

    value = str(value).upper()

    if not value or value in ["NONE", "--", "OPEN"]:
        return "Open"

    if "WEP" in value:
        return "WEP"

    if "WPA3" in value or "SAE" in value:
        return "WPA3"

    if "WPA2" in value:
        return "WPA2"

    if "WPA" in value:
        return "WPA"

    return "Open"


def parse_windows(text):

    rows = []

    ssid = ""
    security = "Open"
    channel = None

    for line in text.splitlines():

        line = line.strip()

        if line.startswith("SSID ") and "BSSID" not in line:

            if ":" in line:
                ssid = line.split(":", 1)[1].strip()

            security = "Open"
            channel = None

        elif line.startswith("Authentication"):

            security = security_type(
                line.split(":", 1)[1].strip()
            )

        elif line.startswith("Channel"):

            numbers = re.findall(r"\d+", line)

            if numbers:
                channel = int(numbers[0])

        elif line.startswith("BSSID") and ":" in line:

            bssid = line.split(":", 1)[1].strip()

            rows.append({
                "SSID": ssid or "<hidden>",
                "BSSID": bssid,
                "channel": channel,
                "signal": None,
                "security": security
            })

        elif line.startswith("Signal") and rows:

            match = re.search(r"(\d+)%", line)

            if match:
                rows[-1]["signal"] = int(match.group(1))

    return rows


def parse_linux(text):

    rows = []

    for line in text.splitlines():

        parts = line.split(":")

        if len(parts) < 5:
            continue

        ssid, bssid, channel, signal, security = parts[:5]

        try:
            channel = int(channel)
        except:
            channel = None

        try:
            signal = int(signal)
        except:
            signal = None

        rows.append({
            "SSID": ssid or "<hidden>",
            "BSSID": bssid,
            "channel": channel,
            "signal": signal,
            "security": security_type(security)
        })

    return rows


def parse_macos(text):

    rows = []

    for line in text.splitlines()[1:]:

        match = re.search(
            r"^\s*(.*?)\s+([0-9A-Fa-f:]{17})\s+(-?\d+)\s+(\d+)",
            line
        )

        if not match:
            continue

        rows.append({
            "SSID": match.group(1).strip(),
            "BSSID": match.group(2),
            "signal": int(match.group(3)),
            "channel": int(match.group(4)),
            "security": "Unknown"
        })

    return rows