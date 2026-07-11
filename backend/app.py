from flask import Flask, request, jsonify
import requests
from flask_cors import CORS
import time
import re
import logging
import os

# ===========================
# SETUP
# ===========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

app = Flask(__name__)

# ===========================
# CORS CONFIGURATION
# ===========================
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type"],
        "supports_credentials": False,
        "max_age": 3600
    }
})

# ===========================
# TOKEN CACHE
# ===========================
token_cache = {
    "token": None,
    "expiry": 0
}

# ===========================
# HELPERS
# ===========================

def _base_url(data):
    return data.get("baseUrl", "https://api.services.mimecast.com").rstrip("/")

def _bearer(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

def _to_mimecast_date(date_str, end_of_day=False):
    """
    Accept either:
      - bare date  "2024-01-15"          → "2024-01-15T00:00:00+0000"
      - already ISO "2024-01-15T..."     → pass through unchanged
    """
    if not date_str:
        return None
    if "T" in str(date_str):
        return date_str  # already formatted
    suffix = "T23:59:59+0000" if end_of_day else "T00:00:00+0000"
    return str(date_str) + suffix


# ===========================
# GET TOKEN
# ===========================

@app.route("/api/token", methods=["POST", "OPTIONS"])
def get_token():
    if request.method == "OPTIONS":
        return "", 204
    
    data = request.json or {}
    client_id     = data.get("clientId")
    client_secret = data.get("clientSecret")
    base_url      = _base_url(data)

    if not client_id or not client_secret:
        return jsonify({"error": "Missing clientId or clientSecret"}), 400

    # Reuse cached token (with 60 s safety margin)
    if token_cache["token"] and time.time() < token_cache["expiry"] - 60:
        log.info("Returning cached token")
        return jsonify({"access_token": token_cache["token"], "cached": True})

    try:
        resp = requests.post(
            f"{base_url}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type":    "client_credentials",
                "client_id":     client_id,
                "client_secret": client_secret,
            },
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        log.error("Token request failed: %s", e)
        return jsonify({"error": "Token request failed", "detail": str(e)}), 502

    result = resp.json()
    if resp.status_code != 200:
        log.warning("Token error %d: %s", resp.status_code, result)
        return jsonify(result), resp.status_code

    token_cache["token"]  = result["access_token"]
    token_cache["expiry"] = time.time() + result.get("expires_in", 1800)
    log.info("New token acquired, expires in %ds", result.get("expires_in", 1800))
    return jsonify({"access_token": result["access_token"], "cached": False})


# ===========================
# SECURITY ANALYSIS (server-side)
# ===========================

def analyze_security(transmission: str, from_header: str) -> dict:
    """
    Parse Authentication-Results headers from transmissionInfo and
    cross-check domains against the envelope sender domain.
    """
    result = {
        "senderDomain":   None,
        "spf":            None,   # "pass" | "fail" | None
        "dkim":           None,
        "dmarc":          None,
        "spfDomain":      None,
        "dkimDomain":     None,
        "dmarcDomain":    None,
        "spfDomainMatch": False,
        "dkimDomainMatch":False,
        "dmarcDomainMatch":False,
        "finalStatus":    "UNKNOWN",
    }

    # --- Extract sender domain from From header ---
    m = re.search(r'[\w.\-+]+@([\w.\-]+)', from_header or "")
    if m:
        result["senderDomain"] = m.group(1).lower()

    sd = result["senderDomain"]

    # --- SPF ---
    # e.g.  spf=pass (google.com: domain of noreply@google.com ...) smtp.mailfrom=noreply@google.com
    spf_m = re.search(r'\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)', transmission, re.I)
    if spf_m:
        result["spf"] = spf_m.group(1).lower()
        spf_domain_m = re.search(r'smtp\.mailfrom=.*?@([\w.\-]+)', transmission, re.I)
        if not spf_domain_m:
            # fallback: pull domain from the parenthetical comment
            spf_domain_m = re.search(r'spf=\w+\s+\([\w.\-]+:\s+domain\s+of\s+[\w.+\-]+@([\w.\-]+)', transmission, re.I)
        if spf_domain_m:
            result["spfDomain"] = spf_domain_m.group(1).lower()
            result["spfDomainMatch"] = (result["spfDomain"] == sd)

    # --- DKIM ---
    # e.g.  dkim=pass header.i=@google.com header.d=google.com
    dkim_m = re.search(r'\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)', transmission, re.I)
    if dkim_m:
        result["dkim"] = dkim_m.group(1).lower()
        # header.d= is the signing domain
        dkim_d = re.search(r'header\.d=([\w.\-]+)', transmission, re.I)
        if not dkim_d:
            dkim_d = re.search(r'header\.i=@([\w.\-]+)', transmission, re.I)
        if dkim_d:
            result["dkimDomain"] = dkim_d.group(1).lower()
            result["dkimDomainMatch"] = (result["dkimDomain"] == sd)

    # --- DMARC ---
    # e.g.  dmarc=pass (p=NONE sp=QUARANTINE ...) header.from=google.com
    dmarc_m = re.search(r'\bdmarc=(pass|fail|none|temperror|permerror)', transmission, re.I)
    if dmarc_m:
        result["dmarc"] = dmarc_m.group(1).lower()
        dmarc_d = re.search(r'header\.from=([\w.\-]+)', transmission, re.I)
        if dmarc_d:
            result["dmarcDomain"] = dmarc_d.group(1).lower()
            result["dmarcDomainMatch"] = (result["dmarcDomain"] == sd)

    # --- Final verdict ---
    passes = [result["spf"] == "pass", result["dkim"] == "pass", result["dmarc"] == "pass"]
    if all(passes):
        result["finalStatus"] = "SAFE"
    elif not any(passes):
        result["finalStatus"] = "FAILED"
    else:
        result["finalStatus"] = "PARTIAL"

    return result


# ===========================
# SEARCH  (returns all tracked emails, not just one)
# ===========================

@app.route("/api/search", methods=["POST", "OPTIONS"])
def search():
    if request.method == "OPTIONS":
        return "", 204
    
    data     = request.json or {}
    token    = data.get("token")
    base_url = _base_url(data)
    domain   = data.get("value", "").strip()
    page_size = int(data.get("pageSize", 25))

    if not token:
        return jsonify({"error": "Missing token"}), 400
    if not domain:
        return jsonify({"error": "Missing search value"}), 400

    # Fix: convert bare YYYY-MM-DD dates to Mimecast ISO format
    start = _to_mimecast_date(data.get("start"), end_of_day=False)
    end   = _to_mimecast_date(data.get("end"),   end_of_day=True)

    body = {
        "meta": {"pagination": {"pageSize": page_size}},
        "data": [{
            "advancedTrackAndTraceOptions": {
                "from":  domain,
                "start": start,
                "end":   end,
            },
            "searchReason": "Security investigation of vendor email traffic",
        }]
    }

    try:
        resp = requests.post(
            f"{base_url}/api/message-finder/search",
            headers=_bearer(token),
            json=body,
            timeout=20,
        )
    except requests.exceptions.RequestException as e:
        log.error("Search failed: %s", e)
        return jsonify({"error": "Search request failed", "detail": str(e)}), 502

    log.info("Search status=%d domain=%s start=%s end=%s", resp.status_code, domain, start, end)
    search_result = resp.json()

    if resp.status_code != 200:
        return jsonify(search_result), resp.status_code

    # Mimecast wraps results: data[0].trackedEmails[]
    tracked = (
        search_result
        .get("data", [{}])[0]
        .get("trackedEmails", [])
    )

    return jsonify({
        "trackedEmails": tracked,
        "total": len(tracked),
    })


# ===========================
# GET MESSAGE INFO  (fixed + guarded)
# ===========================

@app.route("/api/message-info", methods=["POST", "OPTIONS"])
def message_info():
    if request.method == "OPTIONS":
        return "", 204
    
    data     = request.json or {}
    token    = data.get("token")
    base_url = _base_url(data)
    msg_id   = data.get("id", "").strip()

    if not token:
        return jsonify({"error": "Missing token"}), 400
    if not msg_id:
        return jsonify({"error": "Missing message id"}), 400

    log.info("Fetching message info id=%s", msg_id)

    try:
        resp = requests.post(
            f"{base_url}/api/message-finder/get-message-info",
            headers=_bearer(token),
            json={"data": [{"id": msg_id}]},
            timeout=20,
        )
    except requests.exceptions.RequestException as e:
        log.error("Message-info failed: %s", e)
        return jsonify({"error": "Message-info request failed", "detail": str(e)}), 502

    log.info("Message-info status=%d", resp.status_code)
    info = resp.json()

    if resp.status_code != 200:
        return jsonify(info), resp.status_code

    # Safe extraction with full null guarding
    data_arr = info.get("data")
    if not data_arr:
        return jsonify({"error": "Empty data in message-info response", "raw": info}), 404

    record = data_arr[0]

    # recipientInfo can be a list or a dict depending on Mimecast version
    recipient_info = record.get("recipientInfo")
    if isinstance(recipient_info, list):
        recipient_info = recipient_info[0] if recipient_info else {}

    msg = (recipient_info or {}).get("messageInfo", {}) if recipient_info else {}

    # transmissionInfo lives here
    transmission = msg.get("transmissionInfo", "")
    from_header  = msg.get("fromHeader", "")

    security = analyze_security(transmission, from_header)

    return jsonify({
        "messageInfo": msg,
        "security":    security,
        "raw":         info,
    })


# ===========================
# HEALTH CHECK
# ===========================

@app.route("/")
def home():
    return jsonify({"status": "ok", "service": "Mimecast Analyzer API"})


if __name__ == "__main__":
    # Production: disable debug mode, use environment variable for port
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)

