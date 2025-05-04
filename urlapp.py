import streamlit as st
import pandas as pd
import joblib
import sqlite3
import re
import tldextract
from io import BytesIO
import requests

# ---------- Constants ----------
MODEL_URL = "https://github.com/yourusername/malicious-url-app/raw/main/model/rf_url_model.pkl"  # Optional remote model URL
DB_PATH = "malicious_urls.db"

# ---------- Feature Extraction ----------
def extract_features(url):
    ext = tldextract.extract(url)
    domain = ext.domain
    suffix = ext.suffix
    return {
        "url_length": len(url),
        "hostname_length": len(domain),
        "has_https": int("https" in url),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_digits": sum(c.isdigit() for c in url),
        "has_ip": int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        "has_at_symbol": int("@" in url),
        "has_exe": int(".exe" in url),
        "suffix_length": len(suffix)
    }

# ---------- Model Loader ----------
@st.cache_resource
def load_model():
    try:
        response = requests.get(MODEL_URL)
        return joblib.load(BytesIO(response.content))
    except Exception:
        return None

# ---------- SQLite Database ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS malicious_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE
        )
    """)
    conn.commit()
    conn.close()

def insert_url(url):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR IGNORE INTO malicious_urls (url) VALUES (?)", (url,))
    conn.commit()
    conn.close()

def get_logged_urls():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("SELECT url FROM malicious_urls", conn)
    conn.close()
    return df

# ---------- Streamlit App ----------
def main():
    st.set_page_config(page_title="Malicious URL Detector", page_icon="🛡️")
    st.title("🛡️ Malicious URL Detection")
    
    init_db()

    with st.sidebar:
        st.header("📥 Upload Trained Model")
        model_file = st.file_uploader("Upload a .pkl model", type=["pkl"])
        if model_file:
            model = joblib.load(model_file)
            st.success("✅ Model uploaded successfully")
        else:
            model = load_model()
            if model:
                st.info("📡 Using model from remote URL")
            else:
                st.warning("⚠️ No model available. Please upload one.")

    tab1, tab2, tab3 = st.tabs(["🔍 Check URL", "📁 Upload CSV", "🧾 View Logs"])

    # --------- Tab 1: Manual URL Check ---------
    with tab1:
        url = st.text_input("Enter a URL to check:")
        if url and model:
            features = pd.DataFrame([extract_features(url)])
            prediction = model.predict(features)[0]
            label = "🟥 Malicious" if prediction == 1 else "🟩 Safe"
            st.subheader(f"Prediction: {label}")
            st.write("Extracted Features", features)

            if prediction == 1:
                insert_url(url)
                st.success("🚨 Malicious URL logged in database.")

    # --------- Tab 2: CSV Upload ---------
    with tab2:
        uploaded_csv = st.file_uploader("Upload CSV with a column named 'url'", type=["csv"])
        if uploaded_csv and model:
            try:
                df = pd.read_csv(uploaded_csv)
                if "url" not in df.columns:
                    st.error("❌ The CSV must contain a 'url' column.")
                else:
                    features = pd.DataFrame([extract_features(u) for u in df['url']])
                    df['prediction'] = model.predict(features)
                    st.dataframe(df[['url', 'prediction']])

                    malicious_urls = df[df['prediction'] == 1]['url']
                    for u in malicious_urls:
                        insert_url(u)
                    st.success(f"🔒 Stored {len(malicious_urls)} malicious URLs.")
            except Exception as e:
                st.error(f"Error processing file: {e}")

    # --------- Tab 3: Logs ---------
    with tab3:
        if st.button("🔍 Show Logged Malicious URLs"):
            logs = get_logged_urls()
            st.dataframe(logs)

if __name__ == "__main__":
    main()
