# NetSecAnalyzer 
# File : main_gui.py
# Writer : Nadav Hardof , java98
# Description :
# Notes :

import streamlit as st
import pandas as pd
import os
import json
from glob import glob
import matplotlib.pyplot as plt

st.set_page_config(page_title="NetSecAnalyzer Dashboard", layout="wide")
st.title("📊 NetSecAnalyzer Threat Dashboard")


# --- Helper to load latest report ---
def load_latest_report():
    files = sorted(glob("reports/output/*_alerts_*.json"), reverse=True)
    if not files:
        st.warning("No reports found in reports/output/")
        return None, None
    latest_file = files[0]
    with open(latest_file) as f:
        data = json.load(f)
    return pd.DataFrame(data), latest_file


# --- Sidebar ---
st.sidebar.header("Navigation")
view_mode = st.sidebar.radio("Choose View", ["Latest Report", "All Available"])

# --- Main Display ---
if view_mode == "Latest Report":
    df_data, report_path = load_latest_report()
    if df_data is not None:
        st.success(f"Loaded: {os.path.basename(report_path)}")

        # Filters
        if "Event" in df_data.columns:
            event_types = df_data["Event"].unique().tolist()
            selected_events = st.sidebar.multiselect("Filter by Event Type",
                                                     event_types, default=event_types)
            df_data = df_data[df_data["Event"].isin(selected_events)]

        if "Source IP" in df_data.columns:
            ips = df_data["Source IP"].unique().tolist()
            selected_ips = st.sidebar.multiselect("Filter by Source IP", ips,
                                                  default=ips)
            df_data = df_data[df_data["Source IP"].isin(selected_ips)]

        if "MITRE" in df_data.columns:
            mitres = sorted({m for mitre in df_data.MITRE.dropna() for m in ([mitre] if isinstance(mitre, str) else mitre)})
            selected_mitres = st.sidebar.multiselect("Filter by MITRE Technique", mitres, default=mitres)
            df_data = df_data[df_data["MITRE"].apply(lambda m: any(t in m for t in selected_mitres) if isinstance(m, list) else m in selected_mitres)]

        st.dataframe(df_data)

        # MITRE section
        with st.expander("📋 MITRE Mappings"):
            st.json(df_data.MITRE.dropna().tolist(), expanded=False)

        # Chart: Event Type Distribution
        st.subheader("📊 Event Type Distribution")
        if "Event" in df_data.columns:
            event_counts = df_data["Event"].value_counts()
            fig, ax = plt.subplots()
            event_counts.plot(kind="bar", ax=ax, color="skyblue")
            ax.set_ylabel("Count")
            ax.set_title("Event Types")
            st.pyplot(fig)

        # Chart: Top Source IPs
        if "Source IP" in df_data.columns:
            st.subheader("🌍 Top Source IPs")
            src_counts = df_data["Source IP"].value_counts().head(10)
            fig2, ax2 = plt.subplots()
            src_counts.plot(kind="bar", ax=ax2, color="orange")
            ax2.set_ylabel("Count")
            ax2.set_title("Top Source IPs")
            st.pyplot(fig2)

elif view_mode == "All Available":
    all_files = sorted(glob("reports/output/*_alerts_*.json"))
    selected = st.selectbox("Choose a report to view", all_files[::-1])
    if selected:
        with open(selected) as f:
            data = json.load(f)
        df = pd.DataFrame(data)
        st.dataframe(df)
        if "MITRE" in df:
            with st.expander("📋 MITRE Mappings"):
                st.json(df.MITRE.dropna().tolist(), expanded=False)
