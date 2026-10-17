
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st


st.set_page_config(
    page_title="Cybersecurity Threat Analytics",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Cybersecurity Threat Analytics")
st.caption("Flexible security data analysis | Local portfolio project")

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


# --------------------------------------------------
# Demo data: used when no CSV is uploaded
# --------------------------------------------------

@st.cache_data
def create_demo_data():
    rng = np.random.default_rng(42)
    count = 1000

    return pd.DataFrame({
        "timestamp": pd.date_range(
            "2026-09-01", periods=count, freq="30min"
        ),
        "source_ip": rng.choice(
            [f"198.51.100.{i}" for i in range(1, 16)],
            count,
        ),
        "destination_port": rng.choice(
            [22, 53, 80, 443, 3389], count
        ),
        "flow_duration": rng.integers(1, 100000, count),
        "packets": rng.integers(1, 500, count),
        "severity": rng.choice(
            ["Low", "Medium", "High", "Critical"], count
        ),
        "Label": rng.choice(
            ["BENIGN", "BENIGN", "BENIGN",
             "PortScan", "BruteForce"], count
        ),
    })


# --------------------------------------------------
# Load and prepare any CSV dataset
# --------------------------------------------------

def load_csv(uploaded_file):
    # sep=None attempts to detect common delimiters.
    # UTF-8 BOMs and encoding issues are handled as well.
    df = pd.read_csv(
        uploaded_file,
        sep=None,
        engine="python",
        encoding="utf-8-sig",
        encoding_errors="replace",
        on_bad_lines="error",
    )

    # Clean column names without changing their meaning.
    df.columns = [
        str(col).replace("\ufeff", "").strip()
        for col in df.columns
    ]

    # Drop completely empty rows and columns.
    df = df.dropna(how="all").dropna(axis=1, how="all")

    if df.empty or len(df.columns) == 0:
        raise ValueError("The CSV contains no usable data.")

    # Convert numeric-looking text columns to numbers where
    # nearly all non-empty values can be converted.
    for col in df.columns:
        if df[col].dtype == "object":
            values = df[col].astype("string").str.strip()
            converted = pd.to_numeric(values, errors="coerce")
            nonempty = values.notna() & values.ne("")

            if nonempty.sum() > 0:
                ratio = (
                    converted[nonempty].notna().sum()
                    / nonempty.sum()
                )

                if ratio >= 0.95:
                    df[col] = converted

    return df


def normalise_name(name):
    """Create a consistent form for matching column names."""
    return "".join(
        char.lower()
        for char in str(name)
        if char.isalnum()
    )


def find_column(columns, keywords):
    """Find a column whose normalised name matches a keyword."""
    normalised = {
        col: normalise_name(col) for col in columns
    }

    # Prefer exact matches.
    for keyword in keywords:
        target = normalise_name(keyword)
        for col, name in normalised.items():
            if name == target:
                return col

    # Otherwise accept partial matches.
    for keyword in keywords:
        target = normalise_name(keyword)
        for col, name in normalised.items():
            if target in name:
                return col

    return None


def is_ip_column(name):
    value = normalise_name(name)
    return (
        value in {"ip", "srcip", "dstip", "sourceip",
                  "destinationip", "sourceaddress",
                  "destinationaddress", "srcaddr", "dstaddr"}
        or value.endswith("ipaddress")
    )


# --------------------------------------------------
# Sidebar: data source
# --------------------------------------------------

st.sidebar.header("Data source")

uploaded = st.sidebar.file_uploader(
    "Upload any CSV dataset",
    type=["csv"],
    help="Columns are detected automatically. "
         "Security-specific charts appear when relevant fields exist.",
)

try:
    if uploaded is not None:
        df = load_csv(uploaded)
        source_name = uploaded.name
    else:
        df = create_demo_data()
        source_name = "Built-in demonstration dataset"

except Exception as exc:
    st.error(f"Could not read this CSV: {exc}")
    st.info(
        "Check that the file is a valid CSV with a header row "
        "and contains readable data."
    )
    st.stop()

if df.columns.duplicated().any():
    duplicates = df.columns[df.columns.duplicated()].tolist()
    st.error(
        "The CSV has duplicate column names: "
        + ", ".join(map(str, duplicates))
        + ". Rename duplicate columns and upload again."
    )
    st.stop()

st.sidebar.caption(f"Data source: {source_name}")
st.sidebar.caption(f"Rows: {len(df):,} | Columns: {len(df.columns):,}")


# --------------------------------------------------
# Automatically detect useful fields
# --------------------------------------------------

timestamp_col = find_column(
    df.columns,
    ["timestamp", "datetime", "date_time", "event_time",
     "time_stamp", "date"],
)

label_col = find_column(
    df.columns,
    ["label", "attack_type", "attack_category",
     "class", "target", "prediction", "category"],
)

severity_col = find_column(
    df.columns,
    ["severity", "risk_level", "priority"],
)

event_col = find_column(
    df.columns,
    ["event_type", "event_name", "event", "activity"],
)

status_col = find_column(
    df.columns,
    ["status", "incident_status", "investigation_status"],
)

ip_cols = [col for col in df.columns if is_ip_column(col)]

# Parse a date only if its column name suggests it contains one.
if timestamp_col is not None:
    parsed_time = pd.to_datetime(
        df[timestamp_col], errors="coerce", utc=True
    )

    if parsed_time.notna().sum() > 0:
        df[timestamp_col] = parsed_time
    else:
        timestamp_col = None

# Exclude datetime columns from numeric analysis.
numeric_cols = [
    col for col in df.select_dtypes(include="number").columns
    if col != timestamp_col
]

categorical_cols = [
    col for col in df.columns
    if col != timestamp_col
    and (
        pd.api.types.is_object_dtype(df[col])
        or isinstance(df[col].dtype, pd.CategoricalDtype)
        or pd.api.types.is_string_dtype(df[col])
        or pd.api.types.is_bool_dtype(df[col])
    )
]


# --------------------------------------------------
# Interactive filters
# --------------------------------------------------

st.sidebar.header("Filters")

filtered = df.copy()

# Allow filtering on useful categorical fields.
filter_candidates = []

for col in [label_col, severity_col, event_col, status_col]:
    if col is not None and col not in filter_candidates:
        filter_candidates.append(col)

# If none of those fields exist, offer another categorical field.
if not filter_candidates and categorical_cols:
    filter_candidates.append(categorical_cols[0])

for col in filter_candidates:
    values = sorted(
        filtered[col].dropna().astype(str).unique().tolist()
    )

    if 0 < len(values) <= 100:
        selected = st.sidebar.multiselect(
            f"Filter: {col}",
            values,
            default=values,
        )
        filtered = filtered[
            filtered[col].astype("string").isin(selected)
            | filtered[col].isna()
        ]

# Add a date range filter when valid timestamps are available.
if timestamp_col is not None:
    valid_dates = filtered[timestamp_col].dropna()

    if not valid_dates.empty:
        first_date = valid_dates.min().date()
        last_date = valid_dates.max().date()

        date_range = st.sidebar.date_input(
            "Date range",
            value=(first_date, last_date),
            min_value=first_date,
            max_value=last_date,
        )

        if isinstance(date_range, (tuple, list)) and len(date_range) == 2:
            start_date, end_date = date_range
            dates = filtered[timestamp_col].dt.date
            filtered = filtered[
                dates.between(start_date, end_date)
                | dates.isna()
            ]


if filtered.empty:
    st.warning("No rows match your selected filters.")
    st.stop()


# --------------------------------------------------
# Overview metrics
# --------------------------------------------------

st.subheader("Dataset Overview")

m1, m2, m3, m4 = st.columns(4)

m1.metric("Records", f"{len(filtered):,}")
m2.metric("Columns", f"{len(filtered.columns):,}")
m3.metric("Numeric Features", f"{len(numeric_cols):,}")
m4.metric(
    "Missing Values",
    f"{int(filtered.isna().sum().sum()):,}",
)

st.caption(
    "Fields detected automatically: "
    + ", ".join(
        f"{name} = {col}"
        for name, col in [
            ("Timestamp", timestamp_col),
            ("Label", label_col),
            ("Severity", severity_col),
            ("Event", event_col),
            ("Status", status_col),
        ]
        if col is not None
    )
    if any([timestamp_col, label_col, severity_col,
            event_col, status_col])
    else "No standard security fields detected. "
         "General-purpose analysis is available below."
)

st.divider()


# --------------------------------------------------
# General-purpose charts
# --------------------------------------------------

left, right = st.columns(2)

with left:
    st.subheader("Category Distribution")

    # Prefer labels, severity, or event types when available.
    category_col = (
        label_col or severity_col or event_col
        or (categorical_cols[0] if categorical_cols else None)
    )

    if category_col is not None:
        counts = (
            filtered[category_col]
            .fillna("Missing")
            .astype(str)
            .value_counts()
            .head(15)
            .rename_axis("Category")
            .reset_index(name="Records")
        )

        fig = px.bar(
            counts,
            x="Records",
            y="Category",
            orientation="h",
            title=f"Records by {category_col}",
        )
        fig.update_layout(
            yaxis={"categoryorder": "total ascending"}
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No categorical columns are available to chart.")

with right:
    st.subheader("Numerical Feature Distribution")

    if numeric_cols:
        chosen_numeric = st.selectbox(
            "Select a numerical feature",
            numeric_cols,
        )

        values = pd.to_numeric(
            filtered[chosen_numeric], errors="coerce"
        ).dropna()

        if not values.empty:
            fig = px.histogram(
                x=values,
                nbins=40,
                labels={"x": chosen_numeric, "count": "Records"},
                title=f"Distribution of {chosen_numeric}",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("This feature has no valid numeric values.")
    else:
        st.info("No numerical columns were detected.")


# --------------------------------------------------
# Time-series analysis
# --------------------------------------------------

st.divider()
st.subheader("Trend Analysis")

if timestamp_col is not None:
    trend_data = filtered.dropna(subset=[timestamp_col]).copy()

    if not trend_data.empty:
        trend_data["_period"] = (
            trend_data[timestamp_col].dt.floor("D")
        )

        trend = (
            trend_data.groupby("_period")
            .size()
            .reset_index(name="Records")
        )

        fig = px.line(
            trend,
            x="_period",
            y="Records",
            markers=True,
            title="Records over time",
            labels={"_period": "Date"},
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No valid timestamps remain after filtering.")
else:
    st.info(
        "No recognisable timestamp column was found. "
        "Time-series analysis is unavailable for this dataset."
    )


# --------------------------------------------------
# Network and security analysis
# --------------------------------------------------

st.divider()
st.subheader("Security Analysis")

sec_left, sec_right = st.columns(2)

with sec_left:
    st.markdown("**Security labels and severity**")

    security_col = label_col or severity_col or event_col

    if security_col is not None:
        counts = (
            filtered[security_col]
            .fillna("Missing")
            .astype(str)
            .value_counts()
            .head(20)
            .rename_axis("Value")
            .reset_index(name="Records")
        )

        fig = px.pie(
            counts,
            names="Value",
            values="Records",
            hole=0.4,
            title=f"Distribution of {security_col}",
        )
        st.plotly_chart(fig, use_container_width=True)

        if label_col is not None:
            st.caption(
                "Labels are dataset-provided categories, "
                "not independent confirmation of attacks."
            )
    else:
        st.info(
            "No label, severity, or event-type field was detected."
        )

with sec_right:
    st.markdown("**Source and destination analysis**")

    if ip_cols:
        ip_col = st.selectbox(
            "Select an IP address column", ip_cols
        )

        ip_counts = (
            filtered[ip_col]
            .fillna("Missing")
            .astype(str)
            .value_counts()
            .head(10)
            .rename_axis("Address")
            .reset_index(name="Records")
        )

        fig = px.bar(
            ip_counts,
            x="Records",
            y="Address",
            orientation="h",
            title=f"Most frequent values in {ip_col}",
        )
        fig.update_layout(
            yaxis={"categoryorder": "total ascending"}
        )
        st.plotly_chart(fig, use_container_width=True)

    elif numeric_cols:
        st.info(
            "No recognisable IP address column was found. "
            "Network features can still be analysed numerically."
        )
    else:
        st.info("No IP address columns were detected.")


# --------------------------------------------------
# Correlation analysis
# --------------------------------------------------

st.divider()
st.subheader("Feature Relationships")

if len(numeric_cols) >= 2:
    correlation = filtered[numeric_cols].corr()

    # Limit the heatmap to a manageable number of features.
    if len(numeric_cols) > 20:
        variance = (
            filtered[numeric_cols]
            .var()
            .sort_values(ascending=False)
        )
        heatmap_cols = variance.head(20).index.tolist()
        correlation = filtered[heatmap_cols].corr()

    fig = px.imshow(
        correlation,
        text_auto=False,
        aspect="auto",
        color_continuous_scale="RdBu_r",
        zmin=-1,
        zmax=1,
        title="Correlation between numerical features",
    )
    st.plotly_chart(fig, use_container_width=True)

    st.caption(
        "Correlation measures association, not causation or proof of malicious activity."
    )
else:
    st.info(
        "At least two numerical columns are needed for correlation analysis."
    )


# --------------------------------------------------
# Dataset summary and record explorer
# --------------------------------------------------

st.divider()
st.subheader("Data Quality")

quality = pd.DataFrame({
    "Column": filtered.columns,
    "Data Type": [
        str(filtered[col].dtype) for col in filtered.columns
    ],
    "Missing Values": [
        int(filtered[col].isna().sum()) for col in filtered.columns
    ],
    "Unique Values": [
        int(filtered[col].nunique(dropna=True))
        for col in filtered.columns
    ],
})

st.dataframe(quality, use_container_width=True, hide_index=True)

st.subheader("Data Explorer")
st.caption("Inspect and sort the records included by your filters.")

st.dataframe(
    filtered,
    use_container_width=True,
    hide_index=True,
)

st.download_button(
    "Download filtered data as CSV",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="filtered_security_data.csv",
    mime="text/csv",
)

st.caption(
    "Educational analytics only. Automated field detection can "
    "misclassify unusual columns. Validate results before using "
    "them for security decisions."
)
