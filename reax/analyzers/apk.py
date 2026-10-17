"""APK analyzer: manifest, permissions risk, trackers, DEX APIs, native libs, strings.

Batteries included — pure pip dependencies, no external tools to install.
"""

from __future__ import annotations

import re
from typing import Any

# permission -> (severity 1-3, why it matters)
PERMISSION_RISK: dict[str, tuple[int, str]] = {
    "android.permission.READ_SMS": (3, "can read all SMS, incl. OTP codes"),
    "android.permission.RECEIVE_SMS": (3, "can intercept incoming SMS/OTP"),
    "android.permission.SEND_SMS": (3, "can send SMS (premium-rate abuse)"),
    "android.permission.READ_CONTACTS": (3, "full address-book access"),
    "android.permission.WRITE_CONTACTS": (2, "can modify address book"),
    "android.permission.READ_CALL_LOG": (3, "call history access"),
    "android.permission.READ_PHONE_STATE": (2, "device/phone identifiers"),
    "android.permission.READ_PHONE_NUMBERS": (3, "reads the device phone number"),
    "android.permission.ACCESS_FINE_LOCATION": (3, "precise GPS location"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (3, "location even when app is closed"),
    "android.permission.ACCESS_COARSE_LOCATION": (2, "approximate location"),
    "android.permission.CAMERA": (2, "camera access"),
    "android.permission.RECORD_AUDIO": (3, "microphone access"),
    "android.permission.READ_EXTERNAL_STORAGE": (2, "reads shared storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": (2, "writes shared storage"),
    "android.permission.READ_MEDIA_IMAGES": (2, "reads photo library"),
    "android.permission.READ_MEDIA_VIDEO": (2, "reads videos"),
    "android.permission.READ_MEDIA_AUDIO": (2, "reads audio files"),
    "android.permission.REQUEST_INSTALL_PACKAGES": (3, "can install other apps (malware vector)"),
    "android.permission.SYSTEM_ALERT_WINDOW": (2, "draw over other apps (tapjacking)"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (3, "accessibility = full UI control"),
    "android.permission.BIND_DEVICE_ADMIN": (3, "device-admin powers"),
    "android.permission.GET_ACCOUNTS": (2, "lists on-device accounts"),
    "android.permission.USE_CREDENTIALS": (2, "uses stored credentials"),
    "android.permission.AUTHENTICATE_ACCOUNTS": (2, "account authenticator"),
    "android.permission.PROCESS_OUTGOING_CALLS": (2, "intercepts outgoing calls"),
    "android.permission.CALL_PHONE": (2, "places calls"),
    "android.permission.BODY_SENSORS": (2, "health sensor data"),
    "android.permission.ACTIVITY_RECOGNITION": (2, "physical activity tracking"),
    "android.permission.NEARBY_WIFI_DEVICES": (2, "Wi-Fi scanning (location proxy)"),
    "android.permission.BLUETOOTH_SCAN": (2, "BLE scanning (location proxy)"),
    "android.permission.POST_NOTIFICATIONS": (1, "push notifications"),
    "android.permission.SCHEDULE_EXACT_ALARM": (1, "exact alarms"),
}

# tracker SDK package prefix -> tracker name (subset of the Exodus Privacy list)
TRACKERS: dict[str, str] = {
    "com/google/android/gms/ads": "Google AdMob",
    "com/google/android/gms/analytics": "Google Analytics",
    "com/google/firebase/analytics": "Firebase Analytics",
    "com/google/firebase/crashlytics": "Firebase Crashlytics",
    "com/facebook/ads": "Facebook Ads",
    "com/facebook/appevents": "Facebook App Events",
    "com/facebook/login": "Facebook Login",
    "com/appsflyer": "AppsFlyer",
    "com/adjust/sdk": "Adjust",
    "com/flurry": "Flurry",
    "com/mopub": "MoPub",
    "com/applovin": "AppLovin",
    "com/unity3d/ads": "Unity Ads",
    "com/ironsource": "ironSource",
    "com/chartboost": "Chartboost",
    "com/vungle": "Vungle / Liftoff",
    "com/inmobi": "InMobi",
    "com/startapp": "StartApp",
    "com/airship": "Airship",
    "com/onesignal": "OneSignal",
    "com/amplitude": "Amplitude",
    "com/mixpanel": "Mixpanel",
    "com/segment/analytics": "Segment",
    "com/leanplum": "Leanplum / CleverTap",
    "com/localytics": "Localytics",
    "com/kochava": "Kochava",
    "com/tune": "Tune",
    "com/singular": "Singular",
    "com/fyber": "Fyber",
    "com/adcolony": "AdColony",
    "com/appnext": "AppNext",
    "com/revmob": "RevMob",
    "com/smaato": "Smaato",
    "com/criteo": "Criteo",
    "com/ogury": "Ogury",
    "com/myfitnesspal": "MyFitnessPal",
    "io/branch": "Branch Metrics",
    "com/branch": "Branch Metrics",
    "com/yandex/metrica": "Yandex Metrica",
    "com/huawei/hms/ads": "Huawei Ads",
    "com/bytedance": "ByteDance / TikTok SDK",
    "com/apptimize": "Apptimize",
    "com/optimizely": "Optimizely",
    "com/tealium": "Tealium",
    "com/mparticle": "mParticle",
    "com/urbanairship": "Urban Airship",
    "com/exponea": "Exponea / Bloomreach",
    "com/batch": "Batch",
    "com/pushwoosh": "Pushwoosh",
    "com/radar": "Radar",
    "com/mapbox": "Mapbox",
}

# dex class prefix -> (severity 1-3, what it suggests)
SUSPICIOUS_APIS: dict[str, tuple[int, str]] = {
    "Ljava/lang/Runtime;": (2, "executes shell commands"),
    "Ljava/lang/ProcessBuilder;": (2, "spawns processes"),
    "Ldalvik/system/DexClassLoader;": (3, "loads code dynamically (hidden payloads)"),
    "Ldalvik/system/PathClassLoader;": (2, "dynamic code loading"),
    "Ljava/net/HttpURLConnection;": (1, "raw HTTP networking"),
    "Lokhttp3/": (1, "HTTP client usage"),
    "Landroid/telephony/SmsManager;": (3, "sends SMS programmatically"),
    "Landroid/telephony/TelephonyManager;": (2, "reads device identifiers"),
    "Landroid/location/LocationManager;": (2, "location access"),
    "Ljavax/crypto/": (1, "crypto usage (could hide payloads)"),
    "Ljava/security/MessageDigest;": (1, "hashing"),
    "Landroid/os/Debug;": (2, "anti-debug checks"),
    "Ljava/lang/reflect/": (1, "reflection (obfuscation-friendly)"),
    "Landroid/app/admin/DevicePolicyManager;": (3, "device-admin control"),
    "Landroid/accessibilityservice/": (3, "accessibility service (full UI control)"),
    "Ljava/net/Socket;": (1, "raw sockets"),
    "Landroid/net/VpnService;": (2, "VPN interception"),
    "Lde/robv/android/xposed/": (3, "Xposed hooking framework"),
    "Lfrida/": (2, "Frida instrumentation artifacts"),
}

_URL_RE = re.compile(r"https?://[^\s'\"<>\\]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CLASS_REF_RE = re.compile(r"L([\w/$]+);")


def _short(perm: str) -> str:
    return perm.split(".")[-1]


def analyze_apk(path: str) -> dict[str, Any]:
    from androguard.core.apk import APK

    # silence androguard's very chatty debug logs
    try:
        from loguru import logger
        logger.remove()
    except Exception:
        pass

    apk = APK(path)
    ev: dict[str, Any] = {}
    import zipfile
    zf = zipfile.ZipFile(path)
    zip_names = zf.namelist()
    zip_sizes = {n: zf.getinfo(n).file_size for n in zip_names}

    # ---- identity ----
    ev["identity"] = {
        "package": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "max_sdk": apk.get_max_sdk_version(),
        "debuggable": bool(apk.get_attribute_value("debuggable", "application")),
        "allow_backup": apk.get_attribute_value("allowBackup", "application"),
        "main_activity": apk.get_main_activity(),
    }

    # ---- permissions with risk ----
    perms = sorted(set(apk.get_permissions()))
    perm_rows = []
    risk_points = 0
    for p in perms:
        sev, why = PERMISSION_RISK.get(p, (0, "normal / signature permission"))
        risk_points += sev
        perm_rows.append({"permission": _short(p), "full": p, "severity": sev, "why": why})
    perm_rows.sort(key=lambda r: -r["severity"])
    ev["permissions"] = {"count": len(perms), "risk_points": risk_points, "items": perm_rows}

    # ---- components ----
    ev["components"] = {
        "activities": len(apk.get_activities() or []),
        "services": len(apk.get_services() or []),
        "receivers": len(apk.get_receivers() or []),
        "providers": len(apk.get_providers() or []),
        "features": sorted(apk.get_features() or []),
    }

    # ---- native libraries (from the actual package, with sizes — not just manifest) ----
    so_files = sorted(
        ((n, zip_sizes[n]) for n in zip_names if n.endswith(".so")),
        key=lambda x: -x[1],
    )
    ev["native_libraries"] = {
        "count": len(so_files),
        "items": [n for n, _ in so_files],
        "largest": [{"file": n, "size_mb": round(s / 1e6, 1)} for n, s in so_files[:10]],
    }

    # ---- interesting bundled files: big blobs hidden in assets/ etc. ----
    big_files = sorted(
        ((n, zip_sizes[n]) for n in zip_names if zip_sizes[n] > 1_000_000),
        key=lambda x: -x[1],
    )
    ev["bundled_files"] = {
        "count": len(big_files),
        "items": [{"file": n, "size_mb": round(s / 1e6, 1)} for n, s in big_files[:15]],
    }

    # ---- signing ----
    certs = apk.get_certificates() or []
    ev["signing"] = {
        "signed": bool(apk.is_signed()),
        "v1": bool(apk.is_signed_v1()),
        "v2": bool(apk.is_signed_v2()),
        "v3": bool(apk.is_signed_v3()),
        "cert_count": len(certs),
    }

    # ---- dex: classes, trackers, suspicious APIs, strings ----
    class_names: set[str] = set()
    api_hits: dict[str, int] = {}
    urls: set[str] = set()
    ips: set[str] = set()
    dex_count = 0
    method_count = 0

    for dex_bytes in apk.get_all_dex():
        dex_count += 1
        try:
            from androguard.core.dex import DEX
            dex = DEX(dex_bytes)
        except Exception:
            continue
        for cls in dex.get_classes():
            name = cls.get_name().replace(".", "/")
            class_names.add(name)
            for method in cls.get_methods():
                method_count += 1
                try:
                    code = method.get_code()
                    if code is None:
                        continue
                    for ins in code.get_bc().get_instructions():
                        if not ins.get_name().startswith("invoke"):
                            continue
                        try:
                            out = ins.get_output()
                        except Exception:
                            continue
                        for ref in _CLASS_REF_RE.findall(out):
                            for prefix, (sev, what) in SUSPICIOUS_APIS.items():
                                pfx = prefix[1:-1] if prefix.endswith(";") else prefix[1:]
                                if ref.startswith(pfx):
                                    key = f"{prefix} :: {what}"
                                    info = api_hits.setdefault(key, {"hits": 0, "sev": sev})
                                    info["hits"] += 1
                                    break
                except Exception:
                    continue
        try:
            for s in dex.get_strings():
                if "http://" in s or "https://" in s:
                    for u in _URL_RE.findall(s):
                        if len(u) < 200:
                            urls.add(u)
                for ip in _IP_RE.findall(s):
                    parts = ip.split(".")
                    if all(p.isdigit() and int(p) < 256 for p in parts):
                        if not ip.startswith(("0.", "127.", "255.")):
                            ips.add(ip)
        except Exception:
            pass

    # trackers from class names
    found_trackers: dict[str, list[str]] = {}
    for cls in class_names:
        for prefix, tname in TRACKERS.items():
            if cls.startswith(prefix):
                found_trackers.setdefault(tname, []).append(cls)
                break

    ev["dex"] = {
        "dex_files": dex_count,
        "classes": len(class_names),
        "methods": method_count,
    }
    ev["trackers"] = {
        "count": len(found_trackers),
        "items": sorted(found_trackers),
    }
    ev["suspicious_apis"] = {
        "count": len(api_hits),
        "items": [
            {"api": k, "hits": v["hits"], "severity": v["sev"]}
            for k, v in sorted(api_hits.items(), key=lambda kv: (-kv[1]["sev"], -kv[1]["hits"]))
        ],
    }
    ev["network_indicators"] = {
        "urls": sorted(urls)[:100],
        "url_count": len(urls),
        "ips": sorted(ips)[:50],
        "ip_count": len(ips),
    }

    # ---- risk verdict ----
    score = 0
    findings: list[dict[str, Any]] = []
    score += min(risk_points * 2, 40)
    if risk_points >= 15:
        findings.append({"level": "high", "text": f"{len([p for p in perm_rows if p['severity'] >= 2])} high-risk permissions requested"})
    score += min(len(found_trackers) * 4, 20)
    if found_trackers:
        findings.append({"level": "medium", "text": f"{len(found_trackers)} tracker SDKs embedded"})
    api_score = sum(info["sev"] * 3 for info in api_hits.values())
    score += min(api_score, 30)
    for k, info in sorted(api_hits.items(), key=lambda kv: -kv[1]["sev"]):
        if info["sev"] >= 2:
            findings.append({"level": "high" if info["sev"] >= 3 else "medium",
                             "text": f"Suspicious API in use: {k} ({info['hits']} call sites)"})
    # hidden native payloads in assets/
    for f in ev["bundled_files"]["items"]:
        if f["file"].startswith("assets/") and f["file"].endswith(".so") and f["size_mb"] > 10:
            score += 18
            findings.append({"level": "high",
                             "text": f"{f['size_mb']} MB native payload bundled in assets/ ({f['file']}) — classic hidden-payload pattern"})
            break
    if ev["identity"]["debuggable"]:
        score += 8
        findings.append({"level": "medium", "text": "APK is debuggable"})
    if not ev["signing"]["signed"]:
        score += 10
        findings.append({"level": "high", "text": "APK is not signed"})
    score = min(score, 100)
    grade = "low" if score < 25 else "medium" if score < 50 else "high" if score < 75 else "critical"
    ev["risk"] = {"score": score, "grade": grade, "findings": findings}

    return ev
