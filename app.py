"""
╔═══════════════════════════════════════════════════╗
║   AEGIS LITE – Cyber Attack Detection Dashboard   ║
║   Rule-based anomaly detection | Hackathon MVP    ║
╚═══════════════════════════════════════════════════╝
"""

import base64
import pandas as pd
import plotly.express as px
import streamlit as st

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="AEGIS Lite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# CUSTOM CSS  (dark terminal aesthetic)
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #0a0e1a;
    color: #c8d6e5;
}
h1, h2, h3 { font-family: 'Share Tech Mono', monospace; }

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1120;
    border-right: 1px solid #1e2d45;
}

/* Metric cards */
div[data-testid="metric-container"] {
    background: #111827;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 10px 16px;
}

/* Alert box */
.alert-box {
    background: #1a0a0a;
    border-left: 4px solid #ff4444;
    border-radius: 4px;
    padding: 10px 14px;
    margin: 6px 0;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.85rem;
    color: #ff8080;
}

/* Section header */
.section-header {
    font-family: 'Share Tech Mono', monospace;
    color: #00e5ff;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 4px;
    margin-bottom: 12px;
    letter-spacing: 2px;
    font-size: 0.9rem;
}

/* Insight card */
.insight-card {
    background: #0d1a2d;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 10px 14px;
    margin: 6px 0;
    font-size: 0.88rem;
    color: #7ecbff;
}
.insight-card span.tag {
    background: #1a3a5f;
    border-radius: 3px;
    padding: 1px 6px;
    font-size: 0.75rem;
    color: #00e5ff;
    margin-right: 8px;
    font-family: 'Share Tech Mono', monospace;
}

/* Status badge */
.badge-threat  { color: #ff4444; font-weight: 700; }
.badge-normal  { color: #00e676; font-weight: 700; }

/* Scrollable dataframe area */
div[data-testid="stDataFrame"] { border: 1px solid #1e3a5f; border-radius: 6px; }

/* Upload button */
div[data-testid="stFileUploadDropzone"] {
    background: #111827 !important;
    border: 1px dashed #1e3a5f !important;
    border-radius: 6px !important;
}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────

def safe_b64_decode(val: str) -> str:
    """Decode a Base64 string safely; return '[invalid]' on failure."""
    try:
        padded = str(val) + "=" * (-len(str(val)) % 4)
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return "[invalid]"


def classify_threat(row) -> str:
    """Rule-based threat classification."""
    if pd.isna(row.get("response_time")) or pd.isna(row.get("status_code")):
        return "Suspicious"
    if int(row["response_time"]) > 500 or int(row["status_code"]) != 200:
        return "Suspicious"
    return "Normal"


def generate_insights(df: pd.DataFrame) -> list[str]:
    """Return AI-style rule-based insight strings."""
    insights = []
    high_lat = df[df["response_time"] > 500]
    non_200  = df[df["status_code"] != 200]
    total    = len(df)

    if len(high_lat) > 0:
        pct = round(len(high_lat) / total * 100)
        insights.append(
            f"[HIGH LATENCY] {len(high_lat)} node(s) ({pct}%) exceed 500 ms — "
            "possible DDoS pattern or resource exhaustion."
        )
    if len(non_200) > 0:
        codes = non_200["status_code"].value_counts().to_dict()
        code_str = ", ".join(f"{k}×{v}" for k, v in codes.items())
        insights.append(
            f"[STATUS ANOMALY] Non-200 responses detected ({code_str}) — "
            "indicates service disruption or unauthorized access attempts."
        )
    duplicates = df["decoded_id"].duplicated(keep=False)
    if duplicates.sum() > 0:
        insights.append(
            f"[ID COLLISION] {duplicates.sum()} nodes share duplicate decoded IDs — "
            "possible identity spoofing or replay attack."
        )
    if len(insights) == 0:
        insights.append("[ALL CLEAR] No anomalies detected. Network appears healthy.")
    return insights


def process_data(df: pd.DataFrame) -> pd.DataFrame:
    """Clean, decode, classify the raw dataframe."""
    df = df.copy()
    # Coerce types safely
    df["response_time"] = pd.to_numeric(df.get("response_time"), errors="coerce")
    df["status_code"]   = pd.to_numeric(df.get("status_code"),   errors="coerce")
    df["encoded_id"]    = df.get("encoded_id", "").fillna("")

    df["decoded_id"]    = df["encoded_id"].apply(safe_b64_decode)
    df["threat_status"] = df.apply(classify_threat, axis=1)
    return df


# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ AEGIS LITE")
    st.markdown("<small style='color:#7ecbff;font-family:monospace'>v1.0 · Cyber Detection MVP</small>",
                unsafe_allow_html=True)
    st.divider()

    uploaded = st.file_uploader(
        "Upload Network Log (CSV)",
        type=["csv"],
        help="CSV must contain: node_id, status_code, response_time, encoded_id"
    )
    st.divider()
    st.markdown("""
<small style='color:#3a5f80;font-family:monospace'>
DETECTION RULES<br>
• response_time > 500 ms → 🔴 Suspicious<br>
• status_code ≠ 200 → 🔴 Suspicious<br>
• otherwise → 🟢 Normal
</small>""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# MAIN CONTENT
# ─────────────────────────────────────────────
st.markdown("# 🛡️ AEGIS LITE")
st.markdown("<p style='color:#3a6f9f;font-family:monospace;margin-top:-12px'>"
            "CYBER ATTACK DETECTION DASHBOARD — RULE-BASED THREAT ANALYSIS</p>",
            unsafe_allow_html=True)

if uploaded is None:
    st.info("⬆️  Upload a CSV file in the sidebar to begin threat analysis.")
    st.stop()

# ── Load raw data ──────────────────────────────
try:
    raw_df = pd.read_csv(uploaded)
except Exception as e:
    st.error(f"❌ Failed to read CSV: {e}")
    st.stop()

# ── Process ────────────────────────────────────
proc_df = process_data(raw_df)

# ── KPI bar ───────────────────────────────────
total      = len(proc_df)
suspicious = (proc_df["threat_status"] == "Suspicious").sum()
normal     = total - suspicious
threat_pct = round(suspicious / total * 100) if total else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("🌐 Total Nodes",    total)
c2.metric("🔴 Suspicious",     suspicious, delta=f"{threat_pct}% of fleet",
          delta_color="inverse")
c3.metric("🟢 Normal",         normal)
c4.metric("⚡ Avg Latency",    f"{proc_df['response_time'].mean():.0f} ms")

st.divider()

# ─────────────────────────────────────────────
# SECTION 1 – RAW DATA
# ─────────────────────────────────────────────
st.markdown('<p class="section-header">📂 RAW DATA VIEW</p>', unsafe_allow_html=True)
with st.expander("Show raw uploaded data", expanded=False):
    st.dataframe(raw_df, use_container_width=True)

# ─────────────────────────────────────────────
# SECTION 2 – PROCESSED DATA
# ─────────────────────────────────────────────
st.markdown('<p class="section-header">🔬 PROCESSED DATA</p>', unsafe_allow_html=True)

display_cols = ["node_id", "status_code", "response_time",
                "decoded_id", "threat_status"]
disp_df = proc_df[[c for c in display_cols if c in proc_df.columns]]

st.dataframe(
    disp_df.style.apply(
        lambda col: [
            "color:#ff4444" if v == "Suspicious" else "color:#00e676"
            for v in col
        ] if col.name == "threat_status" else [""] * len(col),
        axis=0,
    ),
    use_container_width=True,
    height=280,
)

# ─────────────────────────────────────────────
# SECTION 3 – VISUALIZATION
# ─────────────────────────────────────────────
st.markdown('<p class="section-header">📡 THREAT VISUALIZATION</p>', unsafe_allow_html=True)

color_map = {"Suspicious": "#ff4444", "Normal": "#00e676"}

fig = px.scatter(
    proc_df,
    x="node_id",
    y="response_time",
    color="threat_status",
    color_discrete_map=color_map,
    size=[14] * len(proc_df),
    hover_data=["status_code", "decoded_id"],
    title="Network Node Response Time – Threat Classification",
    labels={"response_time": "Response Time (ms)", "node_id": "Node ID",
            "threat_status": "Threat Status"},
)
fig.add_hline(
    y=500,
    line_dash="dash",
    line_color="#ff8800",
    annotation_text="⚠ 500 ms threshold",
    annotation_font_color="#ff8800",
)
fig.update_layout(
    plot_bgcolor="#0a0e1a",
    paper_bgcolor="#0a0e1a",
    font_color="#c8d6e5",
    font_family="Share Tech Mono",
    xaxis=dict(showgrid=False, tickangle=45),
    yaxis=dict(gridcolor="#1e2d45"),
    legend=dict(bgcolor="#111827", bordercolor="#1e3a5f", borderwidth=1),
)
st.plotly_chart(fig, use_container_width=True)

# ─────────────────────────────────────────────
# SECTION 4 – ALERTS
# ─────────────────────────────────────────────
st.markdown('<p class="section-header">🚨 ACTIVE ALERTS</p>', unsafe_allow_html=True)

threat_nodes = proc_df[proc_df["threat_status"] == "Suspicious"]
if threat_nodes.empty:
    st.success("✅ No active threats detected.")
else:
    for _, row in threat_nodes.iterrows():
        reasons = []
        if pd.notna(row["response_time"]) and row["response_time"] > 500:
            reasons.append(f"latency {row['response_time']:.0f} ms")
        if pd.notna(row["status_code"]) and row["status_code"] != 200:
            reasons.append(f"HTTP {int(row['status_code'])}")
        reason_str = " | ".join(reasons) if reasons else "missing data"
        st.markdown(
            f'<div class="alert-box">⚠ THREAT DETECTED — Node: <b>{row["node_id"]}</b> '
            f'| ID: {row["decoded_id"]} | Reason: {reason_str}</div>',
            unsafe_allow_html=True,
        )

# ─────────────────────────────────────────────
# SECTION 5 – AI INSIGHT PANEL
# ─────────────────────────────────────────────
st.markdown('<p class="section-header">🤖 AI INSIGHT PANEL</p>', unsafe_allow_html=True)

for insight in generate_insights(proc_df):
    tag, _, body = insight.partition("]")
    tag = tag.lstrip("[")
    st.markdown(
        f'<div class="insight-card"><span class="tag">{tag}</span>{body.strip()}</div>',
        unsafe_allow_html=True,
    )

st.divider()
st.markdown(
    "<p style='text-align:center;color:#1e3a5f;font-family:monospace;font-size:0.75rem'>"
    "AEGIS LITE · Hackathon MVP · Rule-Based Detection Engine</p>",
    unsafe_allow_html=True,
)
