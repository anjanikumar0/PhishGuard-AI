import time
from urllib.parse import urlparse
import joblib, pandas as pd, requests
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from db import clear_history, fetch_history, init_db, save_scan
from features import FEATURE_COLUMNS, extract_url_features

app = FastAPI(title="PhishGuard AI")
templates = Jinja2Templates(directory="templates")
init_db()
model = joblib.load("phishing_rf_model.pkl")

LIVE_FEED_CACHE = {"urls": set(), "domains": set(), "last_updated": 0}

def get_live_threat_feed():
    now = time.time()
    if now - LIVE_FEED_CACHE["last_updated"] > 1800 or not LIVE_FEED_CACHE["urls"]:
        try:
            resp = requests.get("https://openphish.com/feed.txt", timeout=10)
            if resp.status_code == 200:
                urls, domains = set(), set()
                for line in resp.text.splitlines():
                    u = line.strip().lower().rstrip("/")
                    if u.startswith("http"):
                        urls.add(u)
                        parsed = urlparse(u)
                        if parsed.netloc: domains.add(parsed.netloc)
                LIVE_FEED_CACHE.update({"urls": urls, "domains": domains, "last_updated": now})
        except Exception:
            pass
    return LIVE_FEED_CACHE["urls"], LIVE_FEED_CACHE["domains"]

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    history = fetch_history(limit=20)
    live_urls, _ = get_live_threat_feed()
    return templates.TemplateResponse("index.html", {"request": request, "result": None, "history": history, "feed_count": len(live_urls)})

@app.post("/scan", response_class=HTMLResponse)
async def scan_url(request: Request, url: str = Form(...)):
    features, norm_url, reg_domain = extract_url_features(url)
    input_df = pd.DataFrame([features])[FEATURE_COLUMNS]
    ml_prob = float(model.predict_proba(input_df)[0][1])

    live_urls, live_domains = get_live_threat_feed()
    clean_check_url = norm_url.lower().rstrip("/")
    parsed_host = urlparse(clean_check_url).netloc

    if clean_check_url in live_urls or parsed_host in live_domains:
        final_prob, label, source = 0.995, "Suspicious", "Live Threat Feed (OpenPhish) + ML"
    else:
        final_prob = ml_prob
        label = "Suspicious" if final_prob >= 0.50 else "Legitimate"
        source = "Random Forest ML Engine"

    save_scan(url.strip(), norm_url, reg_domain, label, source, final_prob, features)
    result_data = {"raw_url": url.strip(), "domain": reg_domain, "label": label, "source": source, "risk_percent": round(final_prob * 100, 1), "features": features}
    return templates.TemplateResponse("index.html", {"request": request, "result": result_data, "history": fetch_history(limit=20), "feed_count": len(live_urls)})

@app.post("/clear")
async def reset_history():
    clear_history()
    return RedirectResponse(url="/", status_code=303)
