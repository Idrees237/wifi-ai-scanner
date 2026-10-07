import pandas as pd
from db import load_scans

try:
    from sklearn.ensemble import IsolationForest
except Exception:
    IsolationForest = None


WEAK_SECURITY = {
    "Open",
    "WEP",
    "WPA"
}


def get_band(channel):

    if pd.isna(channel):
        return "Unknown"

    channel = int(channel)

    if 1 <= channel <= 14:
        return "2.4 GHz"

    if 15 <= channel <= 200:
        return "5 GHz"

    return "Other"


def analyze():

    df = load_scans()

    if df.empty:

        return {
            "summary": "No scans available.",
            "df": df,
            "weak": pd.DataFrame(),
            "channel_counts": pd.DataFrame()
        }

    df["band"] = df["channel"].apply(get_band)

    df["anomaly"] = False

    numeric = df[["signal", "channel"]].copy()

    numeric["signal"] = pd.to_numeric(
        numeric["signal"],
        errors="coerce"
    )

    numeric["channel"] = pd.to_numeric(
        numeric["channel"],
        errors="coerce"
    )

    valid = numeric.dropna()

    if len(valid) >= 5 and IsolationForest is not None:

        try:

            model = IsolationForest(
                contamination="auto",
                random_state=42
            )

            result = model.fit_predict(valid)

            df.loc[valid.index, "anomaly"] = (
                result == -1
            )

        except Exception:
            pass

    weak = df[
        df["security"].isin(WEAK_SECURITY)
    ].copy()

    channel_counts = (
        df.groupby(
            ["band", "channel"]
        )
        .size()
        .reset_index(
            name="networks"
        )
    )

    summary = f"""
WiFi AI Scanner Report

Total observations: {len(df)}

Unique networks: {df["BSSID"].nunique()}

Weak security networks: {len(weak)}

Anomalies detected: {int(df["anomaly"].sum())}

2.4 GHz networks:
{len(df[df["band"] == "2.4 GHz"])}

5 GHz networks:
{len(df[df["band"] == "5 GHz"])}
"""

    return {
        "summary": summary,
        "df": df,
        "weak": weak,
        "channel_counts": channel_counts
    }