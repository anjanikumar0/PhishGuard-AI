import random
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from features import FEATURE_COLUMNS, extract_url_features

def generate_dataset(n_samples=1000):
    random.seed(42)
    legit_domains = [
        "google.com", "youtube.com", "github.com", "microsoft.com", "amazon.in",
        "wikipedia.org", "stackoverflow.com", "linkedin.com", "apple.com",
        "aktu.ac.in", "sbi.co.in", "hdfcbank.com", "icicibank.com", "irctc.co.in",
        "flipkart.com", "netflix.com", "python.org", "openai.com", "geeksforgeeks.org"
    ]
    legit_paths = ["", "/about", "/contact", "/products", "/docs/guide", "/news/latest", "/help", "/courses"]

    phish_brands = ["paypal", "sbi", "hdfc", "amazon", "google", "appleid", "netflix", "microsoft", "metamask"]
    phish_lures = ["login", "verify", "secure", "update", "account", "confirm", "banking", "wallet", "kyc"]
    bad_tlds = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "click", "work"]

    data = []

    # Generate Legitimate URLs (Label 0)
    for _ in range(n_samples):
        dom = random.choice(legit_domains)
        path = random.choice(legit_paths)
        prefix = random.choice(["https://www.", "https://"])
        url = f"{prefix}{dom}{path}"
        data.append((url, 0))

    # Generate Phishing URLs (Label 1)
    for _ in range(n_samples):
        brand = random.choice(phish_brands)
        lure1 = random.choice(phish_lures)
        lure2 = random.choice(phish_lures)
        tld = random.choice(bad_tlds)
        rand_num = random.randint(10, 9999)
        pattern_type = random.randint(1, 4)

        if pattern_type == 1:
            url = f"http://{brand}-{lure1}-{rand_num}.{tld}/{lure2}?token={random.randint(10000,99999)}"
        elif pattern_type == 2:
            url = f"http://{lure1}.{brand}.com.{lure2}-alert.{tld}/auth/signin"
        elif pattern_type == 3:
            url = f"http://192.168.{random.randint(1,254)}.{random.randint(1,254)}/{brand}/{lure1}.php?id={rand_num}"
        else:
            url = f"http://{brand}-support.{tld}/redirect//http://evil-{lure1}.com/@{lure2}"

        data.append((url, 1))

    return pd.DataFrame(data, columns=["url", "label"])

def train():
    print("Generating balanced URL dataset (2,000 samples)...")
    df_raw = generate_dataset(n_samples=1000)

    print("Extracting 15 lexical features...")
    feature_rows = []
    for url in df_raw["url"]:
        feats, _, _ = extract_url_features(url)
        feature_rows.append(feats)

    X = pd.DataFrame(feature_rows)[FEATURE_COLUMNS]
    y = df_raw["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        random_state=42
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {acc * 100:.2f}%")
    print("\n--- Classification Report ---")
    print(classification_report(y_test, y_pred))

    joblib.dump(model, "phishing_rf_model.pkl")
    print("Saved trained model as 'phishing_rf_model.pkl'")

if __name__ == "__main__":
    train()
    