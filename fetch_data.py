import json
import os
import requests
from datetime import datetime, timezone, timedelta

# Beer Sheva city name variants in Hebrew (all quadrants + main)
BEER_SHEVA_NAMES = {
    "באר שבע",
    "באר שבע - צפון",
    "באר שבע - דרום",
    "באר שבע - מזרח",
    "באר שבע - מערב",
    "באר שבע - כלל העיר",
}

NEGEV_CITIES = {
    "ערד", "דימונה", "נתיבות", "שדרות", "אופקים",
    "קריית גת", "קריית מלאכי", "אשקלון",
}

HISTORY_LIMIT = 200   # max alerts to keep in data.json


def israel_now():
    """Current time in Israel (IST = UTC+2, IDT = UTC+3)."""
    utc_now = datetime.now(timezone.utc)
    # Israel springs forward last Friday before April 2, falls back last Sunday before Nov 1
    # Approximate: DST active roughly March 24 – Oct 25
    month = utc_now.month
    is_dst = 4 <= month <= 10 or (month == 3 and utc_now.day >= 24)
    offset = timedelta(hours=3 if is_dst else 2)
    return utc_now + offset


def fetch_alerts():
    """
    Fetch current / recent alerts from Tzeva Adom + Pikud HaOref.
    Returns list of alert dicts with: id, unix_time, cities, beer_sheva (bool)
    """
    alerts = []
    seen_ids = set()

    sources = [
        {
            "url": "https://api.tzevaadom.co.il/notifications",
            "headers": {"User-Agent": "Mozilla/5.0", "Accept": "application/json"},
        },
        {
            "url": "https://www.oref.org.il/WarningMessages/alert/alerts.json",
            "headers": {
                "Referer": "https://www.oref.org.il/",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
            },
        },
    ]

    for src in sources:
        try:
            res = requests.get(src["url"], headers=src["headers"], timeout=10)
            if res.status_code != 200 or not res.text.strip():
                continue
            data = res.json()
            if isinstance(data, dict):
                data = [data]
            for item in data:
                aid = item.get("notificationId") or item.get("id") or str(item.get("time", ""))
                if not aid or aid in seen_ids:
                    continue
                seen_ids.add(aid)
                cities = item.get("cities", [])
                alerts.append({
                    "id":          aid,
                    "unix_time":   item.get("time", 0),
                    "cities":      cities,
                    "beer_sheva":  any(c in BEER_SHEVA_NAMES for c in cities),
                    "negev":       any(c in NEGEV_CITIES or c in BEER_SHEVA_NAMES for c in cities),
                    "threat":      item.get("threat", 0),
                    "is_drill":    item.get("isDrill", False),
                })
        except Exception as e:
            print(f"Fetch error ({src['url']}): {e}")

    print(f"Fetched {len(alerts)} new alerts from APIs")
    return alerts


def fetch_history():
    """Fetch alert history from Pikud HaOref history endpoint."""
    history = []
    try:
        res = requests.get(
            "https://www.oref.org.il/WarningMessages/History/AlertsHistory.json",
            headers={
                "Referer": "https://www.oref.org.il/",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": "Mozilla/5.0",
            },
            timeout=15,
        )
        if res.status_code == 200 and len(res.text) > 1000:
            raw = res.json()
            for item in raw[:50]:  # take last 50 history items
                cities_str = item.get("data", "")
                cities = [c.strip() for c in cities_str.split(",") if c.strip()]
                dt_str  = item.get("datetime", "")
                try:
                    dt = datetime.fromisoformat(dt_str)
                    unix = int(dt.replace(tzinfo=timezone(timedelta(hours=2))).timestamp())
                except Exception:
                    unix = 0
                aid = f"hist_{dt_str}"
                history.append({
                    "id":        aid,
                    "unix_time": unix,
                    "cities":    cities,
                    "beer_sheva": any(c in BEER_SHEVA_NAMES for c in cities),
                    "negev":     any(c in NEGEV_CITIES or c in BEER_SHEVA_NAMES for c in cities),
                    "threat":    0,
                    "is_drill":  False,
                })
            print(f"Fetched {len(history)} history items")
    except Exception as e:
        print(f"History fetch error: {e}")
    return history


def load_existing():
    try:
        with open("data.json") as f:
            return json.load(f)
    except Exception:
        return {"alert_history": []}


def compute_prediction(alert_history, now_utc):
    """
    Compute quiet time prediction for Beer Sheva.
    Returns dict with risk_level, quiet_confidence, factors.
    """
    now_ts = now_utc.timestamp()

    # Beer Sheva alerts only, exclude drills
    bs_alerts = [a for a in alert_history if a.get("beer_sheva") and not a.get("is_drill")]
    bs_alerts.sort(key=lambda a: a["unix_time"], reverse=True)

    # ── Factor 1: Time since last Beer Sheva alert ──
    if bs_alerts:
        last_ts    = bs_alerts[0]["unix_time"]
        mins_since = (now_ts - last_ts) / 60
    else:
        mins_since = 9999

    if   mins_since < 15:    recency_score = 0.0
    elif mins_since < 60:    recency_score = 0.3
    elif mins_since < 180:   recency_score = 0.55
    elif mins_since < 720:   recency_score = 0.75
    else:                    recency_score = 0.90

    # ── Factor 2: Time of day (Israel time) ──
    il_hour = (datetime.utcfromtimestamp(now_ts) + timedelta(hours=3)).hour
    if   2  <= il_hour < 6:  tod_score = 0.85   # pre-dawn, historically quiet
    elif 6  <= il_hour < 9:  tod_score = 0.55
    elif 9  <= il_hour < 14: tod_score = 0.50
    elif 14 <= il_hour < 18: tod_score = 0.45
    elif 18 <= il_hour < 22: tod_score = 0.40
    else:                    tod_score = 0.70   # late night

    # ── Factor 3: Alerts in past 24 hours (Beer Sheva) ──
    cutoff_24h = now_ts - 86400
    bs_24h = sum(1 for a in bs_alerts if a["unix_time"] > cutoff_24h)
    if   bs_24h == 0:  volume_score = 0.90
    elif bs_24h <= 2:  volume_score = 0.65
    elif bs_24h <= 6:  volume_score = 0.40
    elif bs_24h <= 15: volume_score = 0.20
    else:              volume_score = 0.10

    # ── Factor 4: Alerts in past 3 hours (Beer Sheva) ──
    cutoff_3h = now_ts - 10800
    bs_3h = sum(1 for a in bs_alerts if a["unix_time"] > cutoff_3h)
    if   bs_3h == 0: burst_score = 0.85
    elif bs_3h <= 2: burst_score = 0.45
    elif bs_3h <= 5: burst_score = 0.20
    else:            burst_score = 0.05

    # ── Weighted average ──
    confidence = round(
        recency_score  * 0.40 +
        burst_score    * 0.25 +
        volume_score   * 0.20 +
        tod_score      * 0.15,
        2
    )

    if   confidence >= 0.75: risk = "low"
    elif confidence >= 0.45: risk = "medium"
    elif confidence >= 0.20: risk = "high"
    else:                    risk = "critical"

    last_alert_str = None
    if bs_alerts:
        last_dt = datetime.utcfromtimestamp(bs_alerts[0]["unix_time"]) + timedelta(hours=3)
        last_alert_str = last_dt.strftime("%d/%m/%Y %H:%M") + " (IL)"

    return {
        "risk_level":       risk,
        "quiet_confidence": round(confidence * 100),
        "last_bs_alert":    last_alert_str,
        "mins_since_last":  round(mins_since) if mins_since < 9999 else None,
        "bs_alerts_24h":    bs_24h,
        "bs_alerts_3h":     bs_3h,
        "factors": {
            "recency_score": round(recency_score * 100),
            "tod_score":     round(tod_score * 100),
            "volume_score":  round(volume_score * 100),
            "burst_score":   round(burst_score * 100),
        }
    }


def main():
    now_utc  = datetime.now(timezone.utc)
    existing = load_existing()

    # Merge existing history
    history_map = {a["id"]: a for a in existing.get("alert_history", [])}

    # Fetch fresh data
    new_alerts  = fetch_alerts()
    hist_alerts = fetch_history()

    for a in new_alerts + hist_alerts:
        if a["id"] not in history_map:
            history_map[a["id"]] = a

    # Sort by time desc, keep most recent HISTORY_LIMIT
    alert_history = sorted(history_map.values(), key=lambda a: a["unix_time"], reverse=True)
    alert_history = alert_history[:HISTORY_LIMIT]

    # Current Beer Sheva status
    now_ts   = now_utc.timestamp()
    cutoff_active = now_ts - 300   # alert in last 5 min = active
    cutoff_recent = now_ts - 3600  # alert in last 1 hour = recent

    bs_active = any(
        a["beer_sheva"] and not a["is_drill"] and a["unix_time"] >= cutoff_active
        for a in alert_history
    )
    bs_recent = any(
        a["beer_sheva"] and not a["is_drill"] and a["unix_time"] >= cutoff_recent
        for a in alert_history
    )

    if bs_active:
        status = "alert"
    elif bs_recent:
        status = "recent"
    else:
        status = "clear"

    prediction = compute_prediction(alert_history, now_utc)

    # Israel time
    il_time = israel_now()

    # Recent 20 alerts for display
    display_alerts = []
    for a in alert_history[:20]:
        if a["is_drill"]:
            continue
        dt = datetime.utcfromtimestamp(a["unix_time"]) + timedelta(hours=3)
        display_alerts.append({
            "time_il":    dt.strftime("%d/%m %H:%M"),
            "cities":     a["cities"][:8],   # cap city list length
            "beer_sheva": a["beer_sheva"],
            "negev":      a.get("negev", False),
        })

    # Daily stats
    cutoff_today = now_ts - 86400
    alerts_today    = sum(1 for a in alert_history if a["unix_time"] > cutoff_today and not a["is_drill"])
    bs_today        = sum(1 for a in alert_history if a["unix_time"] > cutoff_today and a["beer_sheva"] and not a["is_drill"])

    output = {
        "updated_at":      now_utc.isoformat(),
        "israel_time":     il_time.strftime("%d/%m/%Y %H:%M:%S"),
        "beer_sheva_status": status,
        "prediction":      prediction,
        "recent_alerts":   display_alerts,
        "daily_stats": {
            "alerts_today": alerts_today,
            "bs_today":     bs_today,
        },
        "alert_history":   alert_history,
    }

    with open("data.json", "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"Done. Status: {status} | Confidence: {prediction['quiet_confidence']}% quiet | Alerts today: {alerts_today}")


if __name__ == "__main__":
    main()
