
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(
    page_title="Cybersecurity Analytics",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Cybersecurity Threat & Incident Analytics")
st.caption("Security event analysis | Local portfolio project")

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


@st.cache_data
def create_demo_data():
    rng = np.random.default_rng(42)
    count = 1500

    event_types = [
        "Failed Login",
        "Successful Login",
        "Port Scan Alert",
        "Malware Alert",
        "Privilege Change",
        "Firewall Block",
    ]

    events = rng.choice(
        event_types,
        count,
        p=[0.35, 0.20, 0.12, 0.08, 0.05, 0.20],
    )

    severity_map = {
        "Failed Login": ["Low", "Medium", "High"],
        "Successful Login": ["Low", "Medium"],
        "Port Scan Alert": ["Medium", "High"],
        "Malware Alert": ["High", "Critical"],
        "Privilege Change": ["Medium", "High"],
        "Firewall Block": ["Low", "Medium"],
    }

    severities = [
        rng.choice(severity_map[event])
        for event in events
    ]

    start = pd.Timestamp("2026-09-01")
    timestamps = start + pd.to_timedelta(
        rng.integers(0, 30 * 24 * 60, count), unit="m"
    )

    ips = [
        f"198.51.100.{i}" for i in range(1, 16)
    ]

    return pd.DataFrame({
        "timestamp": timestamps,
        "event_type": events,
        "source_ip": rng.choice(ips, count),
        "username": rng.choice(
            ["admin", "user01", "user02", "service", "guest"],
            count,
        ),
        "severity": severities,
        "status": rng.choice(
            ["Open", "Investigating", "Closed"],
            count,
            p=[0.25, 0.20, 0.55],
        ),
    })


def prepare_data(df):
    required = {
        "timestamp", "event_type", "source_ip",
        "username", "severity", "status"
    }

    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            "CSV is missing columns: " + ", ".join(sorted(missing))
        )

    df = df.copy()
    df["timestamp"] = pd.to_datetime(
        df["timestamp"], errors="coerce", utc=True
    )
    df = df.dropna(subset=["timestamp"])

    for col in required - {"timestamp"}:
        df[col] = df[col].fillna("Unknown").astype(str)

    df["hour"] = df["timestamp"].dt.hour
    df["date"] = df["timestamp"].dt.date

    return df


st.sidebar.header("Data source")

uploaded = st.sidebar.file_uploader(
    "Upload a security events CSV",
    type=["csv"],
)

try:
    if uploaded is not None:
        raw_df = pd.read_csv(uploaded)
        data_source = "Uploaded CSV"
    else:
        raw_df = create_demo_data()
        data_source = "Synthetic demo data"

    df = prepare_data(raw_df)

except Exception as exc:
    st.error(f"Could not load the data: {exc}")
    st.info(
        "The CSV must contain timestamp, event_type, source_ip, "
        "username, severity, and status columns."
    )
    st.stop()

st.sidebar.caption(f"Data source: {data_source}")

st.sidebar.header("Filters")

severity_options = sorted(df["severity"].unique())
selected_severity = st.sidebar.multiselect(
    "Severity",
    severity_options,
    default=severity_options,
)

event_options = sorted(df["event_type"].unique())
selected_events = st.sidebar.multiselect(
    "Event type",
    event_options,
    default=event_options,
)

min_date = df["timestamp"].min().date()
max_date = df["timestamp"].max().date()

date_range = st.sidebar.date_input(
    "Date range",
    value=(min_date, max_date),
    min_value=min_date,
    max_value=max_date,
)

filtered = df[
    df["severity"].isin(selected_severity)
    & df["event_type"].isin(selected_events)
].copy()

if isinstance(date_range, (tuple, list)) and len(date_range) == 2:
    first_date, last_date = date_range
    filtered = filtered[
        filtered["timestamp"].dt.date.between(first_date, last_date)
    ]

if filtered.empty:
    st.warning("No events match your filters.")
    st.stop()

# Key performance indicators
total = len(filtered)
high_critical = filtered["severity"].isin(
    ["High", "Critical"]
).sum()
failed_logins = filtered["event_type"].eq("Failed Login").sum()
open_incidents = filtered["status"].isin(
    ["Open", "Investigating"]
).sum()

a, b, c, d = st.columns(4)
a.metric("Total Events", f"{total:,}")
b.metric("High / Critical", f"{high_critical:,}")
c.metric("Failed Logins", f"{failed_logins:,}")
d.metric("Open / Investigating", f"{open_incidents:,}")

st.divider()

left, right = st.columns(2)

with left:
    st.subheader("Events by Severity")
    severity_counts = (
        filtered["severity"].value_counts().rename_axis("Severity")
        .reset_index(name="Events")
    )
    fig = px.pie(
        severity_counts,
        names="Severity",
        values="Events",
        hole=0.45,
        title="Severity distribution",
    )
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Most Common Event Types")
    event_counts = (
        filtered["event_type"].value_counts().head(10)
        .rename_axis("Event Type")
        .reset_index(name="Events")
    )
    fig = px.bar(
        event_counts,
        x="Events",
        y="Event Type",
        orientation="h",
        title="Event frequency",
    )
    fig.update_layout(yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig, use_container_width=True)

left, right = st.columns(2)

with left:
    st.subheader("Events Over Time")
    timeline = (
        filtered.set_index("timestamp")
        .resample("D")
        .size()
        .rename("Events")
        .reset_index()
    )
    fig = px.line(
        timeline,
        x="timestamp",
        y="Events",
        markers=True,
        title="Daily event volume",
    )
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("Top Source IPs")
    ip_counts = (
        filtered["source_ip"].value_counts().head(10)
        .rename_axis("Source IP")
        .reset_index(name="Events")
    )
    fig = px.bar(
        ip_counts,
        x="Events",
        y="Source IP",
        orientation="h",
        title="Sources generating the most events",
    )
    fig.update_layout(yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig, use_container_width=True)

st.divider()
st.subheader("Security Event Explorer")

st.caption(
    "Use the filters on the left to investigate individual records."
)

st.dataframe(
    filtered.sort_values("timestamp", ascending=False),
    use_container_width=True,
    hide_index=True,
)

st.download_button(
    "Download filtered events as CSV",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="filtered_security_events.csv",
    mime="text/csv",
)

st.subheader("Initial Findings")

st.write(
    f"- **{high_critical:,}** events are classified as High or Critical."
)
st.write(
    f"- **{failed_logins:,}** failed-login events appear in the selected data."
)

if not ip_counts.empty:
    top_ip = ip_counts.iloc[0]
    st.write(
        f"- The most frequent source in this selection is "
        f"`{top_ip['Source IP']}`, with {top_ip['Events']:,} events."
    )

st.caption(
    "Educational analysis only. Event frequency does not by itself "
    "prove malicious activity. Validate findings before taking action."
)
