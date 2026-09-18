import streamlit as st
import requests
import ipaddress
import re
import json
import hashlib
import html
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, getaddresses
import pandas as pd

# Optional MSG support
try:
    import extract_msg
except ImportError:
    extract_msg = None

# Optional OpenAI support
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# ============================================================
# REGEX & CONSTANTS
# ============================================================
URL_RE = re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', re.I)
IPV4_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
IPV6_PATTERN = r"(?:(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})"
EMAIL_RE = re.compile(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}')
HASH_RE = re.compile(r'\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b')

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta',
    '.docm', '.xlsm', '.pptm', '.iso', '.img', '.vhd', '.dll', '.cpl', '.jar'
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def safe_dt(value):
    try:
        return parsedate_to_datetime(value).isoformat()
    except Exception:
        return value or "Not available"

def header_values(msg, name):
    vals = msg.get_all(name, [])
    return [str(v) for v in vals]

def is_public_ip(ip: str) -> bool:
    """Check if an IP address is globally routable (not private, loopback, or reserved)."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False

def extract_ip_addresses(text: str):
    """Extract and validate both IPv4 and IPv6 addresses from text."""
    if not text:
        return []
    found = []
    found.extend(re.findall(IPV4_PATTERN, text))
    found.extend(re.findall(IPV6_PATTERN, text))
    valid = []
    for candidate in found:
        try:
            ip_obj = ipaddress.ip_address(candidate)
            ip_str = str(ip_obj)
            if ip_str not in valid:
                valid.append(ip_str)
        except ValueError:
            continue
    return valid

def extract_urls(text: str):
    urls = set(URL_RE.findall(text or ""))
    cleaned = set()
    for u in urls:
        u = u.rstrip(".,);]}>")
        if u.lower().startswith("www."):
            u = "http://" + u
        cleaned.add(u)
    return sorted(cleaned)

def parse_auth(auth_headers):
    results = []
    for h in auth_headers:
        low = h.lower()
        spf_m = re.search(r'\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b', low)
        dkim_m = re.search(r'\bdkim=(pass|fail|none|neutral|temperror|permerror)\b', low)
        dmarc_m = re.search(r'\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b', low)
        results.append({
            "raw": h,
            "spf": spf_m.group(1) if spf_m else "none",
            "dkim": dkim_m.group(1) if dkim_m else "none",
            "dmarc": dmarc_m.group(1) if dmarc_m else "none",
        })
    return results

# ============================================================
# GEOLOCATION ENGINE
# ============================================================
@st.cache_data(ttl=3600, show_spinner=False)
def get_geolocation(ip: str):
    """Look up IP geolocation using ipwho.is with caching."""
    if not is_public_ip(ip):
        return {
            "success": False,
            "ip": ip,
            "error": "Private, loopback, or non-globally routable address"
        }

    url = f"https://ipwho.is/{ip}"
    try:
        response = requests.get(url, timeout=8)
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            return {
                "success": False,
                "ip": ip,
                "error": data.get("message", "Geolocation lookup failed")
            }

        conn = data.get("connection", {})
        return {
            "success": True,
            "ip": data.get("ip"),
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "flag_emoji": data.get("flag", {}).get("emoji", "🌐") if isinstance(data.get("flag"), dict) else "🌐",
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone", {}).get("id") if isinstance(data.get("timezone"), dict) else None,
            "isp": conn.get("isp"),
            "organization": conn.get("org"),
            "asn": conn.get("asn"),
            "domain": conn.get("domain")
        }
    except requests.RequestException as err:
        return {
            "success": False,
            "ip": ip,
            "error": str(err)
        }

# ============================================================
# EMAIL PARSING (EML & MSG)
# ============================================================
def get_body_from_msg(msg):
    chunks = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_disposition() == "attachment":
                continue
            try:
                payload = part.get_content()
            except Exception:
                try:
                    raw = part.get_payload(decode=True) or b""
                    payload = raw.decode(part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    payload = ""
            if isinstance(payload, str):
                chunks.append(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            raw = msg.get_payload(decode=True) or b""
            payload = raw.decode(msg.get_content_charset() or "utf-8", errors="replace")
        if isinstance(payload, str):
            chunks.append(payload)
    return "\n".join(chunks)

def parse_msg_file(file_bytes):
    if extract_msg is None:
        raise RuntimeError("The 'extract-msg' library is required to parse .msg files. Install with: pip install extract-msg")

    with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as temp:
        temp.write(file_bytes)
        temp_path = temp.name

    try:
        msg = extract_msg.Message(temp_path)
        headers = {}
        if msg.sender:
            headers["From"] = [str(msg.sender)]
        if msg.to:
            headers["To"] = [str(msg.to)]
        if msg.subject:
            headers["Subject"] = [str(msg.subject)]
        if msg.date:
            headers["Date"] = [str(msg.date)]

        body = msg.body or ""
        return headers, body, msg
    finally:
        try:
            Path(temp_path).unlink(missing_ok=True)
        except Exception:
            pass

# ============================================================
# COMPREHENSIVE EMAIL ANALYSIS
# ============================================================
def analyze_email(msg, raw_bytes, is_msg_format=False, msg_obj=None):
    if is_msg_format and msg_obj is not None:
        sender = msg_obj.sender or ""
        reply_to = ""
        return_path = ""
        message_id = ""
        subject = msg_obj.subject or ""
        date_header = str(msg_obj.date or "")
        received = []
        auth = []
        body = msg_obj.body or ""
        mime_parts = []
        attachments = []
        if hasattr(msg_obj, "attachments"):
            for att in msg_obj.attachments:
                data = att.data if hasattr(att, "data") else b""
                filename = att.longFilename or att.shortFilename or "attachment.bin"
                attachments.append({
                    "filename": filename,
                    "content_type": getattr(att, "mimetype", "application/octet-stream"),
                    "content_disposition": "attachment",
                    "size": len(data) if data else 0,
                    "sha256": sha256_bytes(data) if data else "n/a",
                })
    else:
        sender = msg.get("From", "")
        reply_to = msg.get("Reply-To", "")
        return_path = msg.get("Return-Path", "")
        message_id = msg.get("Message-ID", "")
        subject = msg.get("Subject", "")
        date_header = msg.get("Date", "")
        received = header_values(msg, "Received")
        auth = header_values(msg, "Authentication-Results")
        body = get_body_from_msg(msg)

        attachments = []
        mime_parts = []
        for part in msg.walk():
            ct = part.get_content_type()
            disp = part.get_content_disposition() or "none"
            fn = part.get_filename() or ""
            if part.get_content_maintype() == "multipart":
                mime_parts.append({
                    "content_type": ct,
                    "disposition": disp,
                    "filename": fn,
                    "charset": part.get_content_charset() or "",
                })
                continue

            if disp == "attachment" or fn:
                data = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": fn or "unnamed",
                    "content_type": ct,
                    "content_disposition": disp,
                    "size": len(data),
                    "sha256": sha256_bytes(data),
                })
            else:
                mime_parts.append({
                    "content_type": ct,
                    "disposition": disp,
                    "filename": fn,
                    "charset": part.get_content_charset() or "",
                })

    # Searchable text
    x_headers = header_values(msg, "X-Mailer") + header_values(msg, "User-Agent") if not is_msg_format else []
    all_text = "\n".join([subject, body] + x_headers)
    urls = extract_urls(all_text)

    # Contextual IP Extraction
    ip_records = []
    # 1. Received headers (hop tracking)
    for idx, r in enumerate(received):
        ips = extract_ip_addresses(r)
        for ip in ips:
            ip_records.append({
                "ip": ip,
                "source": f"Received Header (Hop {len(received) - idx})",
                "raw_context": r[:160] + "..." if len(r) > 160 else r
            })
    # 2. X-Originating-IP / X-Sender-IP
    for hdr_name in ["X-Originating-IP", "X-Sender-IP", "X-Real-IP"]:
        for val in header_values(msg, hdr_name) if not is_msg_format else []:
            for ip in extract_ip_addresses(val):
                ip_records.append({
                    "ip": ip,
                    "source": f"Header: {hdr_name}",
                    "raw_context": val
                })
    # 3. Body IPs
    for ip in extract_ip_addresses(body):
        ip_records.append({
            "ip": ip,
            "source": "Email Body",
            "raw_context": ""
        })

    # Deduplicate IPs while combining sources
    unique_ips = {}
    for item in ip_records:
        ip = item["ip"]
        if ip not in unique_ips:
            unique_ips[ip] = {
                "ip": ip,
                "sources": [item["source"]],
                "is_public": is_public_ip(ip),
                "geo": get_geolocation(ip) if is_public_ip(ip) else {"success": False, "ip": ip, "error": "Internal/Private Network"}
            }
        else:
            if item["source"] not in unique_ips[ip]["sources"]:
                unique_ips[ip]["sources"].append(item["source"])

    ip_list = list(unique_ips.values())
    public_ips = [x for x in ip_list if x["is_public"] and x["geo"].get("success")]

    auth_parsed = parse_auth(auth)

    # Risk Scoring Model
    score = 0
    reasons = []

    sender_domains = re.findall(r'@([A-Za-z0-9.-]+)', sender.lower())
    reply_domains = re.findall(r'@([A-Za-z0-9.-]+)', reply_to.lower())
    if sender_domains and reply_domains and sender_domains[0] != reply_domains[0]:
        score += 25
        reasons.append(f"Reply-To domain (@{reply_domains[0]}) differs from Sender domain (@{sender_domains[0]})")

    if any("fail" in x.lower() for x in auth):
        score += 25
        reasons.append("Email Authentication-Results contains failure (SPF/DKIM/DMARC)")

    suspicious_words = re.findall(r'\b(urgent|verify|password|credential|payment|invoice|bank|account|wire|gift card|click|suspended|login)\b', all_text, re.I)
    if suspicious_words:
        added_score = min(25, 5 * len(set(x.lower() for x in suspicious_words)))
        score += added_score
        reasons.append(f"Urgent / credential-targeted wording detected ({len(set(suspicious_words))} distinct keywords)")

    if urls:
        score += min(15, 3 * len(urls))
        reasons.append(f"{len(urls)} external URL(s) detected")

    # Attachment threat checks
    high_risk_att = []
    for a in attachments:
        ext = Path(a["filename"]).suffix.lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            high_risk_att.append(a["filename"])

    if high_risk_att:
        score += 35
        reasons.append(f"High-risk executable/macro attachment detected: {', '.join(high_risk_att)}")
    elif attachments:
        score += 10
        reasons.append(f"{len(attachments)} attachment(s) present")

    score = min(score, 100)
    if score >= 60:
        verdict = "HIGH RISK"
        verdict_status = "danger"
    elif score >= 30:
        verdict = "SUSPICIOUS"
        verdict_status = "warning"
    else:
        verdict = "SAFE"
        verdict_status = "safe"

    # IOC Extraction
    domains = set()
    for u in urls:
        try:
            h_name = urlparse(u).hostname
            if h_name:
                domains.add(h_name)
        except Exception:
            pass

    iocs = []
    for u in urls:
        iocs.append({"type": "URL", "value": u, "source": "Email Content", "note": "Hyperlink"})
    for d in sorted(domains):
        iocs.append({"type": "DOMAIN", "value": d, "source": "URL Host", "note": "Extracted Hostname"})
    for item in ip_list:
        if item["geo"].get("success"):
            g = item["geo"]
            geo_info = f"{g.get('city', '')}, {g.get('country', '')} (ASN: {g.get('asn', 'N/A')} - {g.get('isp', 'N/A')})"
        else:
            geo_info = "Private / Non-routable IP"
        iocs.append({
            "type": "IP",
            "value": item["ip"],
            "source": ", ".join(item["sources"]),
            "note": geo_info
        })
    for a in attachments:
        iocs.append({
            "type": "FILE_SHA256",
            "value": a["sha256"],
            "source": f"Attachment: {a['filename']}",
            "note": f"Size: {a['size']} bytes"
        })

    return {
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "subject": subject,
        "date": safe_dt(date_header),
        "received": received,
        "auth_raw": auth,
        "auth_parsed": auth_parsed,
        "urls": urls,
        "domains": list(domains),
        "attachments": attachments,
        "mime_parts": mime_parts,
        "score": score,
        "verdict": verdict,
        "verdict_status": verdict_status,
        "reasons": reasons or ["No significant threat indicators detected by deterministic rules"],
        "iocs": iocs,
        "all_ips": ip_list,
        "public_ips": public_ips,
        "email_sha256": sha256_bytes(raw_bytes),
        "body_preview": body[:5000],
        "full_body": body,
        "all_text": all_text
    }

# ============================================================
# AI ANALYSIS HELPER
# ============================================================
def run_ai_analysis(client, email_text, public_ips):
    if client is None:
        return "OpenAI API key was not provided or OpenAI client is unconfigured. Geolocation & deterministic findings are still fully available."

    location_blocks = []
    for item in public_ips:
        geo = item["geo"]
        if geo.get("success"):
            location_blocks.append(f"""
IP: {geo.get('ip')}
Source in Email: {', '.join(item['sources'])}
Country: {geo.get('country')} ({geo.get('country_code')})
City / Region: {geo.get('city')}, {geo.get('region')}
Coordinates: Lat {geo.get('latitude')}, Long {geo.get('longitude')}
ISP / Org: {geo.get('isp')} / {geo.get('organization')}
ASN: {geo.get('asn')}
Domain: {geo.get('domain')}
Timezone: {geo.get('timezone')}
""")

    prompt = f"""
You are an email security forensics and cyber-threat intelligence assistant.
Analyze the following email and the public-IP geolocation information extracted from its headers and content.

Provide your investigative report using these sections:
1. Email Overview & Claimed Identity
2. Routing Path & Public IP Origin Analysis
3. Geographic Intelligence & Anomaly Assessment
4. ASN / Infrastructure Provider Analysis
5. Header Authentication & Trust Significance
6. Potential Threat & Phishing Indicators
7. Forensics Limitations & Caveats
8. Executive Investigator Verdict

EMAIL EXCERPT:
{email_text[:12000]}

RESOLVED PUBLIC IP ROUTING & GEOLOCATION:
{''.join(location_blocks) if location_blocks else 'No public IPs resolved.'}
"""
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a professional email forensics and incident response investigator."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return response.choices[0].message.content
    except Exception as err:
        return f"AI Analysis failed: {err}"

# ============================================================
# CSS INJECTION (DARK-THEME OVERRIDE + VIBRANT SIDEBAR & ANIMATIONS)
# ============================================================
def inject_custom_styles():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    /* =======================================================
       1. GLOBAL RESET & WHITE/LIGHT PAGE ENFORCEMENT
       (Guarantees consistent clean white background even if
       the user has Dark Theme active in browser or Streamlit)
       ======================================================= */
    html, body, [class*="css"], .stApp {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
        background-color: #f4f7fb !important;
        color: #172033 !important;
    }

    [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
        background-color: #f4f7fb !important;
    }

    /* Force dark text on all main app elements */
    .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
        color: #0f172a !important;
    }
    .stApp p, .stApp label, .stApp span:not([data-testid="stSidebar"] *) {
        color: #334155;
    }

    /* Main Container Padding */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 3rem !important;
        max-width: 1280px !important;
    }

    /* =======================================================
       2. SIDEBAR STYLING & LARGER, COLORFUL ANIMATED BUTTONS
       ======================================================= */
    section[data-testid="stSidebar"] {
        background-color: #0f172a !important;
        background: linear-gradient(180deg, #0f172a 0%, #111827 100%) !important;
        padding: 20px 14px !important;
        border-right: 1px solid rgba(255, 255, 255, 0.08) !important;
    }

    .sidebar-brand {
        font-size: 26px;
        font-weight: 800;
        color: #ffffff !important;
        margin-bottom: 24px;
        display: flex;
        align-items: center;
        gap: 10px;
        letter-spacing: -0.5px;
        padding: 6px 12px;
        background: rgba(255, 255, 255, 0.04);
        border-radius: 12px;
        border: 1px solid rgba(255, 255, 255, 0.08);
    }
    .sidebar-brand span {
        color: #38bdf8 !important;
        text-shadow: 0 0 16px rgba(56, 189, 248, 0.4);
    }

    /* Target the Radio Buttons to make them big, colorful, animated navigation tabs */
    div[data-testid="stRadio"] > div[role="radiogroup"] {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }

    /* Hide the ugly native radio circle */
    div[data-testid="stRadio"] div[role="radiogroup"] label > div:first-child {
        display: none !important;
    }

    /* Beautiful Colorful Large Navigation Buttons */
    div[data-testid="stRadio"] div[role="radiogroup"] label {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.08) !important;
        border-radius: 12px !important;
        padding: 14px 18px !important;
        margin: 0 !important;
        cursor: pointer !important;
        display: flex !important;
        align-items: center !important;
        transition: all 0.28s cubic-bezier(0.4, 0, 0.2, 1) !important;
        position: relative !important;
        overflow: hidden !important;
    }

    /* Button Text Styling */
    div[data-testid="stRadio"] div[role="radiogroup"] label p,
    div[data-testid="stRadio"] div[role="radiogroup"] label span {
        font-size: 16px !important;
        font-weight: 600 !important;
        color: #e2e8f0 !important;
        letter-spacing: 0.2px !important;
        transition: all 0.25s ease !important;
    }

    /* Hover Animation: Scale, Shift right, Glow and Vibrant Blue Gradient */
    div[data-testid="stRadio"] div[role="radiogroup"] label:hover {
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.8), rgba(14, 165, 233, 0.8)) !important;
        border-color: #38bdf8 !important;
        transform: translateX(8px) scale(1.02) !important;
        box-shadow: 0 6px 20px rgba(14, 165, 233, 0.35) !important;
    }
    div[data-testid="stRadio"] div[role="radiogroup"] label:hover p {
        color: #ffffff !important;
        font-weight: 700 !important;
    }

    /* Active / Selected Tab Style */
    div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) {
        background: linear-gradient(135deg, #1d4ed8 0%, #2563eb 50%, #0284c7 100%) !important;
        border-color: #60a5fa !important;
        box-shadow: 0 8px 24px rgba(37, 99, 235, 0.45) !important;
        transform: translateX(6px) !important;
    }
    div[data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) p {
        color: #ffffff !important;
        font-weight: 800 !important;
    }

    /* =======================================================
       3. INTERACTIVE BUTTON ANIMATIONS (Hover / Click)
       ======================================================= */
    .stButton > button, div[data-testid="stDownloadButton"] > button {
        background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important;
        color: #ffffff !important;
        border: none !important;
        border-radius: 10px !important;
        padding: 13px 26px !important;
        font-weight: 700 !important;
        font-size: 15px !important;
        cursor: pointer !important;
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
        box-shadow: 0 4px 14px rgba(37, 99, 235, 0.3) !important;
        display: inline-flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 8px !important;
    }
    .stButton > button:hover, div[data-testid="stDownloadButton"] > button:hover {
        transform: translateY(-3px) scale(1.02) !important;
        box-shadow: 0 8px 24px rgba(37, 99, 235, 0.5) !important;
        background: linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%) !important;
    }
    .stButton > button:active, div[data-testid="stDownloadButton"] > button:active {
        transform: translateY(0px) scale(0.98) !important;
    }

    /* =======================================================
       4. TECHOASTRA DASHBOARD PANELS & CARDS
       ======================================================= */
    .techastra-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 24px;
        padding-bottom: 14px;
        border-bottom: 2px solid #e2e8f0;
    }
    .techastra-header h1 {
        font-size: 29px !important;
        font-weight: 800 !important;
        color: #0f172a !important;
        margin: 0 !important;
        letter-spacing: -0.6px !important;
    }
    .techastra-header p {
        color: #64748b !important;
        margin: 4px 0 0 0 !important;
        font-size: 14px !important;
    }

    /* Metric Cards Grid */
    .cards-container {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 18px;
        margin-bottom: 24px;
    }
    .kpi-card {
        background: #ffffff !important;
        padding: 22px;
        border-radius: 14px;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.04);
        border: 1px solid #e2e8f0;
        transition: transform 0.25s ease, box-shadow 0.25s ease;
    }
    .kpi-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.08);
        border-color: #cbd5e1;
    }
    .kpi-title {
        color: #64748b !important;
        font-size: 13px !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }
    .kpi-value {
        font-size: 29px !important;
        font-weight: 800 !important;
        margin-top: 10px !important;
        color: #0f172a !important;
    }
    .kpi-info {
        margin-top: 8px !important;
        font-size: 13px !important;
        font-weight: 600 !important;
    }

    /* Status Colors */
    .safe { color: #15803d !important; }
    .warning { color: #d97706 !important; }
    .danger { color: #dc2626 !important; }

    /* Verdict Box */
    .verdict-wrapper {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: #ffffff !important;
        padding: 24px;
        border-radius: 14px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.04);
        margin-bottom: 20px;
    }
    .verdict-box {
        padding: 20px;
        border-radius: 12px;
        width: 55%;
    }
    .verdict-box.safe-bg {
        background: #ecfdf5 !important;
        border: 1px solid #86efac !important;
    }
    .verdict-box.warning-bg {
        background: #fffbeb !important;
        border: 1px solid #fde68a !important;
    }
    .verdict-box.danger-bg {
        background: #fef2f2 !important;
        border: 1px solid #fecaca !important;
    }
    .verdict-box h3 {
        font-size: 24px !important;
        font-weight: 800 !important;
        margin: 0 !important;
    }
    .score-box {
        text-align: right;
    }
    .score-number {
        font-size: 48px !important;
        font-weight: 900 !important;
        line-height: 1 !important;
        margin: 6px 0 !important;
    }

    /* Auth Badges */
    .auth-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 14px;
    }
    .auth-card {
        padding: 18px;
        border-radius: 10px;
        background: #f8fafc !important;
        border: 1px solid #e2e8f0 !important;
        text-align: center;
    }
    .auth-card strong {
        display: block;
        font-size: 14px !important;
        color: #475569 !important;
        margin-bottom: 6px;
    }
    .auth-badge {
        font-weight: 800 !important;
        font-size: 15px !important;
    }

    /* Explanation list */
    .reason-box {
        background: #f8fafc !important;
        padding: 18px;
        border-radius: 10px;
        border: 1px solid #e2e8f0;
        font-size: 14px;
        line-height: 1.8;
        color: #334155 !important;
    }

    /* Connection Flow Diagram */
    .connection-flow {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
        padding: 20px 10px;
        background: #f8fafc !important;
        border-radius: 12px;
        border: 1px solid #e2e8f0;
        flex-wrap: wrap;
    }
    .flow-node {
        padding: 10px 18px;
        border-radius: 20px;
        background: #eff6ff !important;
        border: 1px solid #bfdbfe !important;
        font-weight: 700 !important;
        color: #1e40af !important;
        font-size: 13px !important;
    }
    .flow-arrow {
        font-size: 20px !important;
        color: #94a3b8 !important;
        font-weight: bold;
    }

    /* Threat Graph Visualizer */
    .cyber-graph {
        height: 200px;
        background: radial-gradient(circle, #f1f5f9 10%, #f8fafc 90%) !important;
        border-radius: 12px;
        position: relative;
        overflow: hidden;
        border: 1px solid #e2e8f0;
    }
    .cnode {
        position: absolute;
        padding: 8px 14px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 700;
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.05);
    }
    .cn-center { left: 42%; top: 40%; background: #2563eb !important; color: white !important; }
    .cn-topleft { left: 15%; top: 18%; background: #ffffff !important; border: 1px solid #cbd5e1; color: #334155; }
    .cn-topright { right: 15%; top: 18%; background: #ffffff !important; border: 1px solid #cbd5e1; color: #334155; }
    .cn-botleft { left: 18%; bottom: 18%; background: #ffffff !important; border: 1px solid #cbd5e1; color: #334155; }
    .cn-botright { right: 18%; bottom: 18%; background: #ffffff !important; border: 1px solid #cbd5e1; color: #334155; }

    /* Timeline */
    .forensic-timeline {
        border-left: 3px solid #2563eb;
        margin-left: 12px;
        padding-left: 20px;
    }
    .ft-event {
        position: relative;
        margin-bottom: 18px;
    }
    .ft-event::before {
        content: '';
        position: absolute;
        left: -27px;
        top: 4px;
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: #2563eb;
    }
    .ft-event strong {
        display: block;
        font-size: 14px !important;
        color: #0f172a !important;
    }
    .ft-event small {
        color: #64748b !important;
        font-size: 12px !important;
    }

    /* Expander & File Uploader Polish */
    [data-testid="stExpander"] {
        background-color: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 12px !important;
    }
    [data-testid="stFileUploader"] {
        background-color: #ffffff !important;
        border: 2px dashed #cbd5e1 !important;
        border-radius: 14px !important;
        padding: 16px !important;
    }

    @media (max-width: 992px) {
        .cards-container { grid-template-columns: repeat(2, 1fr); }
        .verdict-wrapper { flex-direction: column; gap: 15px; }
        .verdict-box { width: 100%; }
        .score-box { text-align: left; }
    }
    </style>
    """, unsafe_allow_html=True)

# ============================================================
# MAIN APPLICATION INTERFACE
# ============================================================
def main():
    st.set_page_config(
        page_title="TechAstra | Email Security Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    inject_custom_styles()

    # ----------------------------------------------------
    # SIDEBAR
    # ----------------------------------------------------
    with st.sidebar:
        st.markdown("""
        <div class="sidebar-brand">
            🛡️ Tech<span>Astra</span>
        </div>
        """, unsafe_allow_html=True)
        st.caption("AI Email Forensics & Threat Intelligence")

        # Navigation Options with large colorful items & animation
        active_tab = st.radio(
            "Navigation",
            [
                "📊 Dashboard Overview",
                "🌍 GeoLocation & Cartography",
                "📨 SMTP Header Forensics",
                "🔗 IOCs & URL Extraction",
                "📎 Attachment Threat Vault",
                "📄 AI Forensic Investigation"
            ],
            label_visibility="collapsed"
        )

        st.divider()

        # OpenAI Configuration
        openai_api_key = None
        try:
            openai_api_key = st.secrets.get("OPENAI_API_KEY", None)
        except Exception:
            openai_api_key = None

        if not openai_api_key:
            openai_api_key = st.text_input(
                "OpenAI API Key (Optional)",
                type="password",
                help="Enable automated GPT-powered deep incident forensics."
            )

        ai_client = None
        if openai_api_key and OpenAI is not None:
            try:
                ai_client = OpenAI(api_key=openai_api_key)
            except Exception as e:
                st.error(f"OpenAI error: {e}")

        st.divider()
        st.markdown("""
        <div style="font-size: 13px; color: #94a3b8; line-height: 1.6;">
            <strong style="color: #f1f5f9;">Active Capabilities:</strong><br>
            • Public IP Cartography<br>
            • SPF / DKIM / DMARC Verification<br>
            • Phishing & Urgency Linguistic Triage<br>
            • SHA-256 Custody Integrity Seal
        </div>
        """, unsafe_allow_html=True)

    # ----------------------------------------------------
    # HEADER & UPLOADER
    # ----------------------------------------------------
    st.markdown("""
    <div class="techastra-header">
        <div>
            <h1>Email Security Dashboard</h1>
            <p>AI-powered email threat detection & forensic intelligence</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_upload, col_hint = st.columns([2, 1])
    with col_upload:
        uploaded = st.file_uploader("Upload an email file (.eml or .msg) for forensic triage", type=["eml", "msg"])
    with col_hint:
        st.markdown("""
        <div style="background: #ffffff; padding: 16px 20px; border-radius: 12px; border: 1px solid #e2e8f0; font-size: 13px; color: #475569; margin-top: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.03);">
            <strong style="color: #0f172a;">Quick Analysis Guide:</strong><br>
            • Drag and drop any raw <code>.eml</code> or <code>.msg</code><br>
            • Full MIME & multi-hop extraction runs automatically<br>
            • Geolocation maps & IOCs generate instantly
        </div>
        """, unsafe_allow_html=True)

    if not uploaded:
        st.info("👆 Upload an **.eml** or **.msg** file above to begin the security investigation.")
        
        # Default placeholder overview preview matching the HTML template
        st.markdown("""
        <div class="cards-container">
            <div class="kpi-card">
                <div class="kpi-title">📧 Emails Monitored</div>
                <div class="kpi-value">1,248</div>
                <div class="kpi-info safe">↑ 12% this week</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">🛡️ System Status</div>
                <div class="kpi-value safe">ACTIVE</div>
                <div class="kpi-info">All sensors operational</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">📊 Threat Ratio</div>
                <div class="kpi-value">87 / 9 / 4</div>
                <div class="kpi-info"><span class="safe">Safe</span> / <span class="warning">Suspicious</span> / <span class="danger">Phishing</span></div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">🎯 Detection Engine</div>
                <div class="kpi-value safe">v2.4</div>
                <div class="kpi-info">Geo-caching enabled</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    # Parse and Analyze Email
    raw_bytes = uploaded.getvalue()
    filename = uploaded.name.lower()

    try:
        if filename.endswith(".msg"):
            headers_dict, body_text, msg_obj = parse_msg_file(raw_bytes)
            result = analyze_email(None, raw_bytes, is_msg_format=True, msg_obj=msg_obj)
        else:
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
            result = analyze_email(msg, raw_bytes, is_msg_format=False)
    except Exception as e:
        st.error(f"Error parsing email file: {e}")
        st.stop()

    # ----------------------------------------------------
    # DYNAMIC METRIC CARDS
    # ----------------------------------------------------
    v_status = result["verdict_status"]
    v_color_class = "safe" if v_status == "safe" else ("warning" if v_status == "warning" else "danger")
    
    st.markdown(f"""
    <div class="cards-container">
        <div class="kpi-card">
            <div class="kpi-title">📧 File Analyzed</div>
            <div class="kpi-value" style="font-size: 20px; word-break: break-all;">{html.escape(uploaded.name[:20])}</div>
            <div class="kpi-info">{len(raw_bytes)/1024:.1f} KB</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">🛡️ Threat Verdict</div>
            <div class="kpi-value {v_color_class}">{result['verdict']}</div>
            <div class="kpi-info">Deterministic rule engine</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">🌍 Public IPs Resolved</div>
            <div class="kpi-value">{len(result['public_ips'])}</div>
            <div class="kpi-info">{len(result['all_ips'])} total network hops</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-title">🔗 URLs & Attachments</div>
            <div class="kpi-value">{len(result['urls'])} / {len(result['attachments'])}</div>
            <div class="kpi-info">Extracted indicators</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ----------------------------------------------------
    # VIEW: 📊 DASHBOARD OVERVIEW
    # ----------------------------------------------------
    if active_tab == "📊 Dashboard Overview":
        # Verdict + Explanation
        col_verdict, col_explain = st.columns([3, 2])
        
        with col_verdict:
            bg_class = f"{v_status}-bg"
            v_icon = "🟢" if v_status == "safe" else ("🟡" if v_status == "warning" else "🚨")
            
            st.markdown(f"""
            <div class="verdict-wrapper">
                <div class="verdict-box {bg_class}">
                    <h3 class="{v_color_class}">{v_icon} {result['verdict']}</h3>
                    <p style="margin-top: 10px; color: #334155; font-size: 14px;">
                        {"No significant threat indicators detected." if v_status == 'safe' else "Elevated risk signals identified during header and content scan."}
                    </p>
                </div>
                <div class="score-box">
                    <div class="kpi-title">Risk Score</div>
                    <div class="score-number {v_color_class}">{result['score']:02d}</div>
                    <span class="{v_color_class}" style="font-weight: 700; font-size: 14px;">
                        {result['score']}/100 Risk Index
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Email Key Identity
            with st.expander("📬 Key Email Metadata", expanded=True):
                st.markdown(f"**From:** `{result['sender'] or 'Unknown'}`")
                if result['reply_to']:
                    st.markdown(f"**Reply-To:** `{result['reply_to']}`")
                st.markdown(f"**Subject:** {result['subject'] or '(No Subject)'}")
                st.markdown(f"**Timestamp:** {result['date']}")
                if result['message_id']:
                    st.markdown(f"**Message-ID:** `{result['message_id']}`")

        with col_explain:
            reasons_html = "".join([f"<div>{'⚠️' if v_status != 'safe' else '✓'} {html.escape(r)}</div>" for r in result["reasons"]])
            st.markdown(f"""
            <div style="background: white; padding: 22px; border-radius: 14px; border: 1px solid #e2e8f0; box-shadow: 0 4px 14px rgba(0,0,0,0.04);">
                <h3 style="font-size: 17px; font-weight: 700; margin-bottom: 14px; color: #0f172a;">
                    💡 Assessment Rationale
                </h3>
                <div class="reason-box">
                    {reasons_html}
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Authentication & Correlation Rows
        col_auth, col_corr = st.columns([1, 1])
        
        with col_auth:
            st.markdown("""
            <div style="background: white; padding: 22px; border-radius: 14px; border: 1px solid #e2e8f0; box-shadow: 0 4px 14px rgba(0,0,0,0.04); height: 100%;">
                <h3 style="font-size: 17px; font-weight: 700; margin-bottom: 16px; color: #0f172a;">
                    🔐 Email Authentication Checks
                </h3>
            """, unsafe_allow_html=True)
            
            spf_val = result["auth_parsed"][0]["spf"] if result["auth_parsed"] else "none"
            dkim_val = result["auth_parsed"][0]["dkim"] if result["auth_parsed"] else "none"
            dmarc_val = result["auth_parsed"][0]["dmarc"] if result["auth_parsed"] else "none"

            def get_auth_badge(val):
                v = val.lower()
                if "pass" in v:
                    return f'<span class="auth-badge safe">✓ {val.upper()}</span>'
                elif "fail" in v:
                    return f'<span class="auth-badge danger">✗ {val.upper()}</span>'
                return f'<span class="auth-badge warning">? {val.upper()}</span>'

            st.markdown(f"""
                <div class="auth-grid">
                    <div class="auth-card">
                        <strong>SPF</strong>
                        {get_auth_badge(spf_val)}
                    </div>
                    <div class="auth-card">
                        <strong>DKIM</strong>
                        {get_auth_badge(dkim_val)}
                    </div>
                    <div class="auth-card">
                        <strong>DMARC</strong>
                        {get_auth_badge(dmarc_val)}
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_corr:
            origin_ip = result["public_ips"][0]["geo"]["ip"] if result["public_ips"] else "127.0.0.1"
            domain_sample = result["domains"][0] if result["domains"] else "mail.server"
            st.markdown(f"""
            <div style="background: white; padding: 22px; border-radius: 14px; border: 1px solid #e2e8f0; box-shadow: 0 4px 14px rgba(0,0,0,0.04); height: 100%;">
                <h3 style="font-size: 17px; font-weight: 700; margin-bottom: 16px; color: #0f172a;">
                    🔗 IP–Domain–URL Correlation
                </h3>
                <div class="connection-flow">
                    <div class="flow-node">🌐 {origin_ip}</div>
                    <div class="flow-arrow">→</div>
                    <div class="flow-node">🔗 {domain_sample}</div>
                    <div class="flow-arrow">→</div>
                    <div class="flow-node">🎯 {len(result['urls'])} Links</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Visual Threat Graph + Timeline
        col_graph, col_time = st.columns([3, 2])
        with col_graph:
            st.markdown("""
            <div style="background: white; padding: 22px; border-radius: 14px; border: 1px solid #e2e8f0; box-shadow: 0 4px 14px rgba(0,0,0,0.04);">
                <h3 style="font-size: 17px; font-weight: 700; margin-bottom: 14px; color: #0f172a;">
                    🕸️ Interactive Threat / Campaign Graph
                </h3>
                <div class="cyber-graph">
                    <div class="cnode cn-center">📧 Email Object</div>
                    <div class="cnode cn-topleft">🌐 Relay IPs</div>
                    <div class="cnode cn-topright">🔗 Extracted Domains</div>
                    <div class="cnode cn-botleft">🎯 Web URLs</div>
                    <div class="cnode cn-botright">🛡️ Auth Policies</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_time:
            st.markdown(f"""
            <div style="background: white; padding: 22px; border-radius: 14px; border: 1px solid #e2e8f0; box-shadow: 0 4px 14px rgba(0,0,0,0.04); height: 100%;">
                <h3 style="font-size: 17px; font-weight: 700; margin-bottom: 14px; color: #0f172a;">
                    ⏱️ Forensic Evidence Timeline
                </h3>
                <div class="forensic-timeline">
                    <div class="ft-event">
                        <strong>Raw File Ingestion</strong>
                        <small>{uploaded.name} (SHA-256 seal computed)</small>
                    </div>
                    <div class="ft-event">
                        <strong>Header Hop Deconstruction</strong>
                        <small>{len(result['received'])} SMTP hops identified</small>
                    </div>
                    <div class="ft-event">
                        <strong>Authentication & Geocoding</strong>
                        <small>{len(result['public_ips'])} public IP locations mapped</small>
                    </div>
                    <div class="ft-event">
                        <strong>Threat Verdict Formulation</strong>
                        <small>Risk Index: {result['score']}/100 ({result['verdict']})</small>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

    # ----------------------------------------------------
    # VIEW: 🌍 GEOLOCATION & CARTOGRAPHY
    # ----------------------------------------------------
    elif active_tab == "🌍 GeoLocation & Cartography":
        st.subheader("🌍 Domain IP & Geographic Network Intelligence")
        public_ips = result["public_ips"]

        if public_ips:
            # Map plotting
            map_data = []
            for item in public_ips:
                g = item["geo"]
                if g.get("latitude") and g.get("longitude"):
                    map_data.append({
                        "latitude": float(g["latitude"]),
                        "longitude": float(g["longitude"]),
                        "ip": g.get("ip"),
                        "city": g.get("city", "Unknown"),
                        "country": g.get("country", "Unknown")
                    })
            if map_data:
                st.map(pd.DataFrame(map_data), latitude="latitude", longitude="longitude", zoom=2)

            st.markdown("<br>", unsafe_allow_html=True)
            
            # Geolocation Cards
            for idx, item in enumerate(public_ips, 1):
                g = item["geo"]
                st.markdown(f"""
                <div style="background: white; padding: 20px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 4px 12px rgba(0,0,0,0.04); margin-bottom: 14px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <h4 style="margin: 0; color: #0f172a; font-size: 17px;">
                            {g.get('flag_emoji', '🌐')} {g.get('ip')} — {g.get('city', 'Unknown City')}, {g.get('country', 'Unknown Country')}
                        </h4>
                        <span style="background: #eff6ff; color: #1e40af; padding: 4px 12px; border-radius: 12px; font-weight: 600; font-size: 12px;">
                            Hop #{idx}
                        </span>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; font-size: 14px; color: #475569;">
                        <div>
                            <strong>ISP / Org:</strong> {g.get('isp') or 'N/A'}<br>
                            <strong>ASN:</strong> {g.get('asn') or 'N/A'}
                        </div>
                        <div>
                            <strong>Coordinates:</strong> {g.get('latitude')}, {g.get('longitude')}<br>
                            <strong>Timezone:</strong> {g.get('timezone') or 'N/A'}
                        </div>
                        <div>
                            <strong>Origin in Header:</strong> {', '.join(item['sources'])}
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.warning("No public routable IP addresses resolved. The email may have originated entirely from private networks or internal relays.")

    # ----------------------------------------------------
    # VIEW: 📨 SMTP HEADER FORENSICS
    # ----------------------------------------------------
    elif active_tab == "📨 SMTP Header Forensics":
        st.subheader("📨 SMTP Received Headers & Routing Trace")
        if result["received"]:
            for idx, h in enumerate(result["received"], 1):
                hop_num = len(result["received"]) - idx + 1
                with st.expander(f"Relay Hop #{hop_num}", expanded=(idx == 1)):
                    st.code(h, language="text")
        else:
            st.info("No Received headers found in this message.")

    # ----------------------------------------------------
    # VIEW: 🔗 IOCS & URL EXTRACTION
    # ----------------------------------------------------
    elif active_tab == "🔗 IOCs & URL Extraction":
        st.subheader("🔗 Indicators of Compromise (IOCs)")
        if result["iocs"]:
            df_iocs = pd.DataFrame(result["iocs"])
            st.dataframe(df_iocs, use_container_width=True)
            
            json_str = json.dumps(result["iocs"], indent=2)
            st.download_button(
                "📥 Download IOCs as Valid JSON",
                data=json_str,
                file_name="mailtrace_iocs.json",
                mime="application/json"
            )
        else:
            st.info("No threat indicators extracted.")

    # ----------------------------------------------------
    # VIEW: 📎 ATTACHMENT THREAT VAULT
    # ----------------------------------------------------
    elif active_tab == "📎 Attachment Threat Vault":
        st.subheader("📎 Attachment Inventory & Cryptographic Hashes")
        if result["attachments"]:
            st.dataframe(pd.DataFrame(result["attachments"]), use_container_width=True)
        else:
            st.info("No attachments found in this email.")

    # ----------------------------------------------------
    # VIEW: 📄 AI FORENSIC INVESTIGATION
    # ----------------------------------------------------
    elif active_tab == "📄 AI Forensic Investigation":
        st.subheader("📄 AI Forensic Incident Report")
        st.caption("Automated threat analysis powered by LLM forensics & network correlation.")
        
        if ai_client is None:
            st.warning("Enter an OpenAI API Key in the sidebar to generate an automated AI threat report.")
        else:
            if st.button("Generate Forensic Intelligence Report", type="primary"):
                with st.spinner("Analyzing email headers, relay routes, and geographical indicators..."):
                    report = run_ai_analysis(ai_client, result["all_text"], result["public_ips"])
                st.markdown(report)

        st.divider()
        st.markdown(f"**Chain of Custody SHA-256 Seal:** `{result['email_sha256']}`")


if __name__ == "__main__":
    main()

