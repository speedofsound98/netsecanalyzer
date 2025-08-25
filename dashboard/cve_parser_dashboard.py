# NetSecAnalyzer 
# File : cve_parser_dashboard.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :
# dashboard/cve_dashboard.py

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.title("🛡️ CVE Dashboard")

uploaded_file = st.file_uploader("Upload CVE CSV", type="csv")

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.success(f"Loaded {len(df)} CVEs")

    high = df[df["cvss_score"] >= 8.0]
    st.metric("High Severity CVEs", len(high))

    top_vendors = df["vendor"].value_counts().head(10)
    st.bar_chart(top_vendors)

    st.subheader("Data Preview")
    st.dataframe(df.head(25))

    st.download_button("Download Filtered CSV", data=high.to_csv(index=False),
                       file_name="high_severity.csv")
