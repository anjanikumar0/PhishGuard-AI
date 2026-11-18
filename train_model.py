import io, zipfile, joblib, pandas as pd, requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from features import FEATURE_COLUMNS, extract_url_features

def fetch_realtime_phishing(limit=500):
    print("Fetching real-time active phishing URLs from OpenPhish...")
    resp = requests.get("https://openphish.com/feed.txt", timeout=15)
    resp.raise_for_status()
    urls = [line.strip() for line in resp.text.splitlines() if line.strip().startswith("http")]
    print(f"Fetched {len(urls)} live phishing URLs.")
    return urls[:limit]

def fetch_realtime_legitimate(limit=500):
    print("Fetching top verified legitimate domains...")
    try:
        resp = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=15)
        resp.raise_for_status()
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            with zf.open(zf.namelist()[0]) as f:
                df = pd.read_csv(f, header=None, names=["rank", "domain"], nrows=limit)
                return [f"https://www.{d.strip()}" for d in df["domain"].dropna()]
    except Exception:
        base = ["google.com", "youtube.com", "github.com", "microsoft.com", "amazon.in", "wikipedia.org", "stackoverflow.com", "linkedin.com", "apple.com", "aktu.ac.in", "sbi.co.in", "hdfcbank.com", "icicibank.com", "irctc.co.in", "flipkart.com", "netflix.com", "python.org", "openai.com", "geeksforgeeks.org"]
        return [f"https://www.{d}" for d in base] * (limit // len(base) + 1)

def train():
    phish_urls = fetch_realtime_phishing(limit=500)
    legit_urls = fetch_realtime_legitimate(limit=len(phish_urls))
    df_raw = pd.DataFrame([(u, 1) for u in phish_urls] + [(u, 0) for u in legit_urls], columns=["url", "label"]).drop_duplicates(subset=["url"])
    feature_rows = [extract_url_features(u)[0] for u in df_raw["url"]]
    X = pd.DataFrame(feature_rows)[FEATURE_COLUMNS]
    y = df_raw["label"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=200, max_depth=14, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(f"\nReal-World Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
    print(classification_report(y_test, y_pred))
    joblib.dump(model, "phishing_rf_model.pkl")
    print("Saved 'phishing_rf_model.pkl' successfully!")

if __name__ == "__main__":
    train()
