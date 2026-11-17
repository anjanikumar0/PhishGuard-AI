import joblib
import pandas as pd
import streamlit as st
from db import clear_history, fetch_history, init_db, save_scan
from features import FEATURE_COLUMNS, extract_url_features

st.set_page_config(
    page_title="PhishGuard AI - URL Scanner",
    page_icon="🛡️",
    layout="wide"
)

init_db()

@st.cache_resource
def load_model():
    return joblib.load("phishing_rf_model.pkl")

try:
    model = load_model()
except FileNotFoundError:
    st.error("Model file nahi mili! Pehle terminal mein `python train_model.py` chalayein.")
    st.stop()

# Sidebar for Quick Demo URLs (Presentation/Viva mein kaam aayega)
with st.sidebar:
    st.header("🧪 Quick Test URLs")
    st.caption("Viva demo ke liye in URLs ko copy karke test karein:")
    st.code("https://www.github.com/login", language="text")
    st.code("http://sbi-kyc-update99.xyz/verify?id=4512", language="text")
    st.code("http://192.168.1.10/paypal-secure/login.php", language="text")
    st.divider()
    st.markdown("**Tech Stack:**\n- Python & Streamlit\n- Scikit-Learn (Random Forest)\n- SQLite3 Database")

# Main Header
st.title("🛡️ PhishGuard AI: Phishing Website Detection System")
st.markdown("Enter any website URL below to analyse its lexical structure and detect potential phishing threats using Machine Learning.")

# Input Box
with st.form("scan_form"):
    url_input = st.text_input(
        "Website URL:",
        placeholder="e.g., https://www.amazon.in or http://secure-login-update.xyz/verify"
    )
    submitted = st.form_submit_button("🔍 Analyse URL", use_container_width=True)

if submitted:
    if not url_input.strip():
        st.warning("Kripya pehle ek URL enter karein.")
    else:
        features, norm_url, reg_domain = extract_url_features(url_input)
        input_df = pd.DataFrame([features])[FEATURE_COLUMNS]

        prediction = model.predict(input_df)[0]
        probabilities = model.predict_proba(input_df)[0]
        phishing_prob = float(probabilities[1])

        label = "Suspicious" if prediction == 1 else "Legitimate"
        save_scan(url_input.strip(), norm_url, reg_domain, label, phishing_prob, features)

        st.divider()
        col1, col2 = st.columns([1, 2])

        with col1:
            st.subheader("Detection Result")
            if label == "Suspicious":
                st.error(f"🚨 **{label.upper()} WEBSITE**")
            else:
                st.success(f"✅ **POTENTIALLY {label.upper()}**")

            st.metric(label="Phishing Risk Score", value=f"{phishing_prob * 100:.1f}%")
            st.progress(phishing_prob)
            st.info(f"**Target Domain:** `{reg_domain}`")

        with col2:
            st.subheader("Extracted URL Indicators (15 Features)")
            feat_display = pd.DataFrame({
                "Feature Name": list(features.keys()),
                "Extracted Value": list(features.values())
            })
            st.dataframe(feat_display, use_container_width=True, height=340, hide_index=True)

# Scan History Section
st.divider()
hist_col1, hist_col2 = st.columns([4, 1])
with hist_col1:
    st.subheader("📜 Scan History (Stored in SQLite)")
with hist_col2:
    if st.button("🗑️ Clear History", use_container_width=True):
        clear_history()
        st.rerun()

history_df = fetch_history(limit=25)
if history_df.empty:
    st.info("Abhi tak koi URL scan nahi hua hai. Upar koi URL daal kar test karein.")
else:
    st.dataframe(history_df, use_container_width=True, hide_index=True)