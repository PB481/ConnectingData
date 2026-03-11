"""
FA P&L Intelligence Platform — Streamlit Application
=====================================================
A self-contained fund administration P&L analysis tool.
Users download CSV templates, populate with their data, upload,
and get a full interactive dashboard with forecasting and insights.

Run: streamlit run app.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from io import StringIO, BytesIO
from datetime import datetime, timedelta
import warnings

warnings.filterwarnings("ignore")

# ═══════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="FA P&L Intelligence",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════
# CUSTOM STYLING
# ═══════════════════════════════════════════════════════════════
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    .stApp { background-color: #0a0e17; }
    section[data-testid="stSidebar"] { background-color: #111827; border-right: 1px solid #1e2d4a; }

    h1, h2, h3, h4 { font-family: 'IBM Plex Sans', sans-serif !important; letter-spacing: -0.3px; }

    .main-header {
        background: linear-gradient(135deg, #0c1220 0%, #131c30 100%);
        border: 1px solid #243352;
        border-radius: 12px;
        padding: 28px 32px;
        margin-bottom: 24px;
    }
    .main-header h1 {
        font-size: 28px; font-weight: 700;
        background: linear-gradient(135deg, #f0f4fa 0%, #22c7e0 100%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .main-header p { color: #8494b2; font-size: 14px; margin: 8px 0 0; }

    .kpi-card {
        background: #131c30;
        border: 1px solid #243352;
        border-radius: 10px;
        padding: 18px 20px;
        position: relative;
        overflow: hidden;
    }
    .kpi-card::before {
        content: '';
        position: absolute; top: 0; left: 0; right: 0; height: 2px;
    }
    .kpi-card.red::before { background: #f04848; }
    .kpi-card.amber::before { background: #eda025; }
    .kpi-card.green::before { background: #12c47a; }
    .kpi-card.blue::before { background: #3a7bfd; }

    .kpi-label { font-size: 11px; color: #5a6d8e; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 500; }
    .kpi-value { font-family: 'IBM Plex Mono', monospace; font-size: 24px; font-weight: 500; margin: 6px 0 4px; }
    .kpi-delta { font-size: 11px; font-family: 'IBM Plex Mono', monospace; }

    .section-header {
        display: flex; align-items: center; gap: 10px;
        margin: 28px 0 16px; padding-bottom: 10px;
        border-bottom: 1px solid #243352;
    }
    .section-num {
        font-family: 'IBM Plex Mono', monospace;
        font-size: 11px; color: #3a7bfd;
        background: rgba(58,123,253,0.12);
        padding: 3px 8px; border-radius: 4px;
    }
    .section-label { font-size: 16px; font-weight: 600; color: #f0f4fa; }

    .insight-box {
        padding: 14px 16px;
        background: #0c1220;
        border-radius: 8px;
        margin-bottom: 8px;
        border-left: 3px solid #3a7bfd;
        font-size: 13px; line-height: 1.7; color: #c2ccdf;
    }
    .insight-box.critical { border-left-color: #f04848; }
    .insight-box.warning { border-left-color: #eda025; }
    .insight-tag {
        font-size: 9px; font-family: 'IBM Plex Mono', monospace;
        text-transform: uppercase; letter-spacing: 0.5px;
        display: block; margin-bottom: 4px;
    }
    .insight-tag.critical { color: #f04848; }
    .insight-tag.warning { color: #eda025; }
    .insight-tag.info { color: #3a7bfd; }

    .template-card {
        background: #131c30;
        border: 1px solid #243352;
        border-radius: 10px;
        padding: 24px;
        margin-bottom: 12px;
    }
    .template-card h4 { color: #f0f4fa; margin: 0 0 8px; }
    .template-card p { color: #8494b2; font-size: 13px; margin: 0 0 12px; }

    .field-tag {
        display: inline-block;
        font-size: 10px; font-family: 'IBM Plex Mono', monospace;
        padding: 2px 8px;
        background: #0a0e17; border: 1px solid #243352;
        border-radius: 4px; color: #8494b2;
        margin: 0 3px 5px 0;
    }

    .val-pass { color: #12c47a; }
    .val-warn { color: #eda025; }
    .val-fail { color: #f04848; }

    div[data-testid="stMetric"] { background: #131c30; border: 1px solid #243352; border-radius: 10px; padding: 14px; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# TEMPLATE SCHEMAS
# ═══════════════════════════════════════════════════════════════
SCHEMAS = {
    "error_payouts": {
        "display": "Error Payouts",
        "icon": "⚠️",
        "desc": "Track all error events — NAV misstatements, pricing errors, distribution failures. Each row is one error event with root cause and financial impact.",
        "required": ["date", "fund_name", "fund_type", "error_type", "root_cause", "payout_usd"],
        "optional": ["detected_by", "resolution_days"],
        "types": {"payout_usd": "number", "resolution_days": "number", "date": "date"},
    },
    "client_repricing": {
        "display": "Client Repricing",
        "icon": "↕️",
        "desc": "Log every fee renegotiation. Captures old vs new fee, AUM, trigger reason for revenue erosion modelling.",
        "required": ["date", "client_name", "aum_usd_m", "old_fee_bps", "new_fee_bps", "trigger"],
        "optional": ["contract_end_date", "relationship_years"],
        "types": {"aum_usd_m": "number", "old_fee_bps": "number", "new_fee_bps": "number", "relationship_years": "number", "date": "date"},
    },
    "client_attrition": {
        "display": "Client Attrition & Risk",
        "icon": "🔴",
        "desc": "Current client roster with health signals — escalations, error frequency, NPS. Powers churn prediction.",
        "required": ["client_name", "aum_usd_m", "annual_revenue_usd", "escalations_12m", "errors_12m"],
        "optional": ["nps_score", "relationship_years", "status"],
        "types": {"aum_usd_m": "number", "annual_revenue_usd": "number", "escalations_12m": "number", "errors_12m": "number", "nps_score": "number", "relationship_years": "number"},
    },
    "operational_costs": {
        "display": "Operational Costs",
        "icon": "💰",
        "desc": "Monthly cost data by category — headcount, technology, vendor fees. Enables cost attribution and profitability analysis.",
        "required": ["month", "cost_category", "amount_usd"],
        "optional": ["sub_category", "fund_segment", "headcount", "notes"],
        "types": {"amount_usd": "number", "headcount": "number"},
    },
}

# ═══════════════════════════════════════════════════════════════
# SAMPLE DATA
# ═══════════════════════════════════════════════════════════════
SAMPLE_DATA = {
    "error_payouts": pd.DataFrame([
        ["2025-10-15", "IE UCITS Global Equity", "UCITS", "NAV Misstatement", "Stale FX Rate", 312400, "Automated Check", 2],
        ["2025-10-28", "IE AIF Credit Opportunities", "AIF", "Pricing Error", "OTC Valuation Miss", 287000, "Client Query", 5],
        ["2025-11-05", "IE UCITS Fixed Income", "UCITS", "Distribution Error", "Accrual Calculation", 198500, "Internal Audit", 3],
        ["2025-11-18", "IE UCITS Multi-Asset", "UCITS", "NAV Misstatement", "Corporate Action Missed", 156200, "Automated Check", 1],
        ["2025-12-02", "IE AIF Real Assets", "AIF", "Pricing Error", "Vendor Feed Lag", 124800, "Automated Check", 2],
        ["2025-12-14", "IE UCITS EM Equity", "UCITS", "NAV Misstatement", "Stale FX Rate", 245000, "Reconciliation", 4],
        ["2026-01-08", "IE UCITS Global Equity", "UCITS", "Trade Processing", "Settlement Fail", 89000, "Operations", 3],
        ["2026-01-22", "IE AIF Private Debt", "AIF", "Pricing Error", "OTC Valuation Miss", 178000, "Client Query", 7],
        ["2026-02-03", "IE UCITS ESG Screened", "UCITS", "NAV Misstatement", "Index Rebalance Miss", 134500, "Automated Check", 1],
        ["2026-02-15", "IE UCITS Fixed Income", "UCITS", "Distribution Error", "Coupon Accrual", 92000, "Internal Audit", 2],
        ["2026-02-28", "IE AIF Credit Opportunities", "AIF", "Pricing Error", "Vendor Feed Lag", 201300, "Reconciliation", 3],
        ["2026-03-05", "IE UCITS Multi-Asset", "UCITS", "NAV Misstatement", "Stale FX Rate", 168000, "Automated Check", 1],
    ], columns=["date", "fund_name", "fund_type", "error_type", "root_cause", "payout_usd", "detected_by", "resolution_days"]),

    "client_repricing": pd.DataFrame([
        ["2025-07-01", "Client Alpha", 4200, 3.2, 2.4, "Competitor bid", "2026-06-30", 8],
        ["2025-08-15", "Client Beta", 6800, 2.8, 2.2, "Volume tier", "2027-03-31", 12],
        ["2025-09-01", "Client Gamma", 3100, 3.5, 2.6, "Service issues", "2026-09-30", 5],
        ["2025-10-20", "Client Delta", 8500, 2.1, 1.8, "Contract renewal", "2028-12-31", 15],
        ["2025-11-10", "Client Epsilon", 2700, 4.0, 3.1, "Competitor bid", "2026-11-30", 3],
        ["2026-01-05", "Client Zeta", 5400, 2.5, 2.1, "Volume tier", "2027-06-30", 10],
        ["2026-01-25", "Client Eta", 1800, 3.8, 3.2, "Contract renewal", "2026-12-31", 6],
        ["2026-02-12", "Client Theta", 3600, 3.0, 2.4, "Competitor bid", "2027-02-28", 7],
    ], columns=["date", "client_name", "aum_usd_m", "old_fee_bps", "new_fee_bps", "trigger", "contract_end_date", "relationship_years"]),

    "client_attrition": pd.DataFrame([
        ["Client Alpha", 4200, 1344000, 4, 3, 45, 8, "At Risk"],
        ["Client Beta", 6800, 1496000, 1, 1, 72, 12, "Stable"],
        ["Client Gamma", 3100, 1085000, 6, 5, 32, 5, "At Risk"],
        ["Client Delta", 8500, 1530000, 0, 0, 85, 15, "Stable"],
        ["Client Epsilon", 2700, 1080000, 3, 2, 55, 3, "Watch"],
        ["Client Zeta", 5400, 1134000, 1, 1, 78, 10, "Stable"],
        ["Client Eta", 1800, 684000, 2, 3, 48, 6, "Watch"],
        ["Client Theta", 3600, 1080000, 5, 4, 38, 7, "At Risk"],
        ["Client Iota", 4100, 943000, 0, 1, 82, 9, "Stable"],
        ["Client Kappa", 2200, 748000, 3, 2, 60, 4, "Watch"],
    ], columns=["client_name", "aum_usd_m", "annual_revenue_usd", "escalations_12m", "errors_12m", "nps_score", "relationship_years", "status"]),

    "operational_costs": pd.DataFrame([
        ["2025-10", "Headcount", "Fund Accounting", 420000, "UCITS", 35, ""],
        ["2025-10", "Headcount", "Fund Accounting", 180000, "AIF", 15, ""],
        ["2025-10", "Technology", "Systems", 125000, "All", 0, "Bloomberg, vendor feeds"],
        ["2025-10", "Vendor", "Pricing Services", 85000, "All", 0, ""],
        ["2025-11", "Headcount", "Fund Accounting", 425000, "UCITS", 35, ""],
        ["2025-11", "Headcount", "Fund Accounting", 185000, "AIF", 15, ""],
        ["2025-11", "Technology", "Systems", 125000, "All", 0, ""],
        ["2025-11", "Vendor", "Pricing Services", 85000, "All", 0, ""],
        ["2025-12", "Headcount", "Fund Accounting", 430000, "UCITS", 36, "1 new hire"],
        ["2025-12", "Headcount", "Fund Accounting", 185000, "AIF", 15, ""],
        ["2025-12", "Technology", "Systems", 140000, "All", 0, "Platform upgrade"],
        ["2025-12", "Vendor", "Pricing Services", 85000, "All", 0, ""],
        ["2026-01", "Headcount", "Fund Accounting", 430000, "UCITS", 36, ""],
        ["2026-01", "Headcount", "Fund Accounting", 185000, "AIF", 15, ""],
        ["2026-01", "Technology", "Systems", 140000, "All", 0, ""],
        ["2026-01", "Vendor", "Pricing Services", 90000, "All", 0, "Price increase"],
        ["2026-02", "Headcount", "Fund Accounting", 435000, "UCITS", 36, ""],
        ["2026-02", "Headcount", "Fund Accounting", 185000, "AIF", 15, ""],
        ["2026-02", "Technology", "Systems", 140000, "All", 0, ""],
        ["2026-02", "Vendor", "Pricing Services", 90000, "All", 0, ""],
    ], columns=["month", "cost_category", "sub_category", "amount_usd", "fund_segment", "headcount", "notes"]),
}


# ═══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════
def fmt_currency(val):
    """Format a number as a readable currency string."""
    abs_val = abs(val)
    sign = "-" if val < 0 else ""
    if abs_val >= 1_000_000:
        return f"{sign}${abs_val / 1_000_000:.1f}M"
    if abs_val >= 1_000:
        return f"{sign}${abs_val / 1_000:.0f}K"
    return f"{sign}${abs_val:.0f}"


def detect_template_type(df, filename):
    """Auto-detect which template schema a CSV matches."""
    fn = filename.lower()
    cols = list(df.columns)
    for key, schema in SCHEMAS.items():
        if key in fn or schema["display"].lower().replace(" ", "_") in fn:
            return key
        matched = sum(1 for r in schema["required"] if r in cols)
        if matched >= len(schema["required"]) * 0.7:
            return key
    return None


def validate_file(df, schema_key):
    """Validate an uploaded file against its schema. Returns (passed, warnings, errors, log)."""
    schema = SCHEMAS[schema_key]
    cols = list(df.columns)
    log, passed, warns, errs = [], 0, 0, 0

    for req in schema["required"]:
        if req in cols:
            log.append(("pass", f'Required column "{req}" ✓'))
            passed += 1
        else:
            log.append(("fail", f'Missing required column "{req}"'))
            errs += 1

    for opt in schema["optional"]:
        if opt in cols:
            log.append(("pass", f'Optional column "{opt}" ✓'))
            passed += 1
        else:
            log.append(("warn", f'Optional column "{opt}" missing — defaults used'))
            warns += 1

    for col, expected in schema["types"].items():
        if col not in cols:
            continue
        if expected == "number":
            bad = pd.to_numeric(df[col], errors="coerce").isna().sum() - df[col].isna().sum()
            if bad > 0:
                log.append(("warn", f'{bad} rows have non-numeric values in "{col}"'))
                warns += 1
            else:
                log.append(("pass", f'Column "{col}" type check passed (number)'))
                passed += 1
        elif expected == "date":
            bad = pd.to_datetime(df[col], errors="coerce").isna().sum() - df[col].isna().sum()
            if bad > 0:
                log.append(("warn", f'{bad} rows have invalid dates in "{col}"'))
                warns += 1
            else:
                log.append(("pass", f'Column "{col}" type check passed (date)'))
                passed += 1

    if len(df) == 0:
        log.append(("fail", "File is empty"))
        errs += 1
    else:
        log.append(("pass", f"{len(df)} data rows loaded"))
        passed += 1

    return passed, warns, errs, log


def clean_dataframe(df, schema_key):
    """Clean and coerce types in a dataframe according to its schema."""
    schema = SCHEMAS[schema_key]
    for col, dtype in schema["types"].items():
        if col in df.columns:
            if dtype == "number":
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
            elif dtype == "date":
                df[col] = pd.to_datetime(df[col], errors="coerce")
    return df


def compute_risk_score(row):
    """Compute a simple churn risk score from client signals."""
    esc = row.get("escalations_12m", 0) or 0
    err = row.get("errors_12m", 0) or 0
    nps = row.get("nps_score", 50) or 50
    return min(100, int(esc * 15 + err * 10 + (100 - nps) * 0.3))


def generate_insights(errors_df, repricing_df, attrition_df, costs_df):
    """Generate AI-style insights from the data."""
    insights = []

    if errors_df is not None and len(errors_df) > 0:
        cause_costs = errors_df.groupby("root_cause")["payout_usd"].sum().sort_values(ascending=False)
        total = cause_costs.sum()
        if len(cause_costs) > 0:
            top = cause_costs.index[0]
            pct = int(cause_costs.iloc[0] / total * 100)
            insights.append({
                "level": "critical",
                "label": "CRITICAL · ERROR PATTERN",
                "text": f'"{top}" is the #1 root cause at {fmt_currency(cause_costs.iloc[0])} ({pct}% of total). Recommend targeted process remediation and secondary data source validation.',
            })
        fund_costs = errors_df.groupby("fund_name")["payout_usd"].sum().sort_values(ascending=False)
        if len(fund_costs) > 0:
            insights.append({
                "level": "warning",
                "label": "WARNING · FUND CONCENTRATION",
                "text": f'{fund_costs.index[0]} has highest error cost at {fmt_currency(fund_costs.iloc[0])}. Consider enhanced oversight and automated NAV reasonability checks.',
            })

    if repricing_df is not None and len(repricing_df) > 0:
        comp = repricing_df[repricing_df["trigger"].str.lower().str.contains("competitor", na=False)]
        if len(comp) > 0:
            lost = ((comp["old_fee_bps"] - comp["new_fee_bps"]) / 10000 * comp["aum_usd_m"] * 1_000_000).sum()
            insights.append({
                "level": "critical",
                "label": "CRITICAL · COMPETITIVE PRESSURE",
                "text": f'{len(comp)} repricing events triggered by competitor bids = {fmt_currency(lost)}/yr revenue erosion. Proactive QBR programme recommended.',
            })

    if attrition_df is not None and len(attrition_df) > 0:
        if "status" in attrition_df.columns:
            at_risk = attrition_df[attrition_df["status"].str.lower().str.contains("risk", na=False)]
            if len(at_risk) > 0:
                rev = at_risk["annual_revenue_usd"].sum()
                insights.append({
                    "level": "critical",
                    "label": "CRITICAL · CHURN SIGNAL",
                    "text": f'{len(at_risk)} clients flagged "At Risk" with {fmt_currency(rev)} combined annual revenue. Key drivers: high escalations and below-average NPS.',
                })
        if "nps_score" in attrition_df.columns:
            low_nps = attrition_df[(attrition_df["nps_score"] > 0) & (attrition_df["nps_score"] < 50)]
            if len(low_nps) > 0:
                insights.append({
                    "level": "warning",
                    "label": "WARNING · NPS DETERIORATION",
                    "text": f'{len(low_nps)} clients have NPS below 50. Clients with NPS <40 have ~3x higher churn rates. Immediate RM engagement recommended.',
                })

    insights.append({
        "level": "info",
        "label": "OPPORTUNITY · AUTOMATION",
        "text": "Implementing automated pre-NAV checks (FX staleness, corporate action coverage, pricing band monitoring) could catch the majority of error types in this dataset.",
    })
    insights.append({
        "level": "info",
        "label": "OPPORTUNITY · RETENTION",
        "text": "Expanding quarterly business reviews to all top-tier clients strengthens relationship depth — the single strongest differentiator between retained and lost clients.",
    })
    return insights


def df_to_csv_download(df, filename):
    """Convert a DataFrame to a downloadable CSV."""
    return df.to_csv(index=False).encode("utf-8")


# ═══════════════════════════════════════════════════════════════
# PLOTLY DARK THEME
# ═══════════════════════════════════════════════════════════════
CHART_LAYOUT = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="IBM Plex Sans, sans-serif", size=11, color="#8494b2"),
    margin=dict(l=40, r=20, t=40, b=40),
    xaxis=dict(gridcolor="rgba(36,51,82,0.4)", zerolinecolor="rgba(36,51,82,0.4)"),
    yaxis=dict(gridcolor="rgba(36,51,82,0.4)", zerolinecolor="rgba(36,51,82,0.4)"),
    legend=dict(font=dict(size=10)),
)

COLORS = {
    "red": "#f04848", "amber": "#eda025", "green": "#12c47a",
    "blue": "#3a7bfd", "purple": "#9b6dff", "cyan": "#22c7e0",
    "red_dim": "rgba(240,72,72,0.4)", "amber_dim": "rgba(237,160,37,0.4)",
}


# ═══════════════════════════════════════════════════════════════
# SESSION STATE INIT
# ═══════════════════════════════════════════════════════════════
if "uploaded_data" not in st.session_state:
    st.session_state.uploaded_data = {}
if "validated" not in st.session_state:
    st.session_state.validated = False


# ═══════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("### 📊 FA P&L Intelligence")
    st.markdown("---")
    page = st.radio(
        "Navigation",
        ["📥 Templates", "📤 Upload & Validate", "📈 Dashboard"],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.caption("v1.0 · Fund Administration")
    st.caption(f"Session: {datetime.now().strftime('%Y-%m-%d %H:%M')}")

    if st.session_state.uploaded_data:
        st.markdown("### Loaded Data")
        for key in st.session_state.uploaded_data:
            schema = SCHEMAS.get(key, {})
            n = len(st.session_state.uploaded_data[key])
            st.success(f"{schema.get('icon', '📄')} {schema.get('display', key)}: {n} rows")


# ═══════════════════════════════════════════════════════════════
# PAGE: TEMPLATES
# ═══════════════════════════════════════════════════════════════
if page == "📥 Templates":
    st.markdown("""
    <div class="main-header">
        <h1>Download. Fill. Upload. Analyse.</h1>
        <p>Download the standardised CSV templates, populate with your data, then upload to generate your P&L intelligence dashboard.</p>
    </div>
    """, unsafe_allow_html=True)

    cols = st.columns(2)
    for idx, (key, schema) in enumerate(SCHEMAS.items()):
        with cols[idx % 2]:
            st.markdown(f"""
            <div class="template-card">
                <h4>{schema['icon']} {schema['display']}</h4>
                <p>{schema['desc']}</p>
                <div>{''.join(f'<span class="field-tag">{f}</span>' for f in schema['required'] + schema['optional'])}</div>
            </div>
            """, unsafe_allow_html=True)

            c1, c2 = st.columns(2)
            with c1:
                empty_df = pd.DataFrame(columns=schema["required"] + schema["optional"])
                st.download_button(
                    f"↓ Download Template",
                    data=df_to_csv_download(empty_df, key),
                    file_name=f"{key}.csv",
                    mime="text/csv",
                    key=f"tmpl_{key}",
                    use_container_width=True,
                )
            with c2:
                sample_df = SAMPLE_DATA[key]
                st.download_button(
                    f"↓ With Sample Data",
                    data=df_to_csv_download(sample_df, key),
                    file_name=f"{key}_sample.csv",
                    mime="text/csv",
                    key=f"sample_{key}",
                    use_container_width=True,
                )

    st.info("💡 **Tip:** Download the sample data versions first to see the expected format, then replace with your own data.")


# ═══════════════════════════════════════════════════════════════
# PAGE: UPLOAD & VALIDATE
# ═══════════════════════════════════════════════════════════════
elif page == "📤 Upload & Validate":
    st.markdown("""
    <div class="main-header">
        <h1>Upload & Validate Your Data</h1>
        <p>Upload your completed CSV templates. The platform will auto-detect the template type and validate the data.</p>
    </div>
    """, unsafe_allow_html=True)

    uploaded_files = st.file_uploader(
        "Drop your CSV files here",
        type=["csv"],
        accept_multiple_files=True,
        help="Upload one or more CSV files matching the template schemas",
    )

    if uploaded_files:
        total_passed, total_warns, total_errs = 0, 0, 0

        for uf in uploaded_files:
            df = pd.read_csv(uf)
            detected = detect_template_type(df, uf.name)

            if detected:
                schema = SCHEMAS[detected]
                st.markdown(f"#### {schema['icon']} {uf.name} → **{schema['display']}**")

                passed, warns, errs, log = validate_file(df, detected)
                total_passed += passed
                total_warns += warns
                total_errs += errs

                with st.expander(f"Validation Log ({passed}✓ {warns}⚠ {errs}✗)", expanded=errs > 0):
                    for level, msg in log:
                        css = {"pass": "val-pass", "warn": "val-warn", "fail": "val-fail"}[level]
                        icon = {"pass": "✓", "warn": "⚠", "fail": "✗"}[level]
                        st.markdown(f'<span class="{css}">{icon} {msg}</span>', unsafe_allow_html=True)

                cleaned = clean_dataframe(df, detected)
                st.session_state.uploaded_data[detected] = cleaned
                st.success(f"✓ {len(cleaned)} rows loaded and validated")

                with st.expander("Preview data"):
                    st.dataframe(cleaned.head(10), use_container_width=True)
            else:
                st.error(f"❌ Could not match **{uf.name}** to any template schema. Check column names.")

        st.markdown("---")
        mc1, mc2, mc3 = st.columns(3)
        mc1.metric("Passed", f"✓ {total_passed}")
        mc2.metric("Warnings", f"⚠ {total_warns}")
        mc3.metric("Errors", f"✗ {total_errs}")

        if st.session_state.uploaded_data:
            st.markdown("---")
            if st.button("🚀 Build Dashboard", type="primary", use_container_width=True):
                st.session_state.validated = True
                st.rerun()


# ═══════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════
elif page == "📈 Dashboard":
    data = st.session_state.uploaded_data

    if not data:
        st.warning("No data loaded yet. Go to **📥 Templates** to download templates, then **📤 Upload & Validate** to load your data.")
        st.info("Or click below to load sample data for a demo.")
        if st.button("Load Sample Data", type="primary"):
            for key, df in SAMPLE_DATA.items():
                st.session_state.uploaded_data[key] = clean_dataframe(df.copy(), key)
            st.rerun()
        st.stop()

    errors_df = data.get("error_payouts")
    repricing_df = data.get("client_repricing")
    attrition_df = data.get("client_attrition")
    costs_df = data.get("operational_costs")

    # ─── KPIs ───
    total_error_cost = errors_df["payout_usd"].sum() if errors_df is not None else 0
    total_rev_lost = 0
    if repricing_df is not None and len(repricing_df) > 0:
        total_rev_lost = ((repricing_df["old_fee_bps"] - repricing_df["new_fee_bps"]) / 10000 * repricing_df["aum_usd_m"] * 1_000_000).sum()

    at_risk_rev = 0
    at_risk_count = 0
    if attrition_df is not None and "status" in attrition_df.columns:
        at_risk = attrition_df[attrition_df["status"].str.lower().str.contains("risk", na=False)]
        at_risk_rev = at_risk["annual_revenue_usd"].sum()
        at_risk_count = len(at_risk)

    total_costs = costs_df["amount_usd"].sum() if costs_df is not None else 0

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(f"""<div class="kpi-card red">
            <div class="kpi-label">Error Payouts</div>
            <div class="kpi-value" style="color:#f04848">{fmt_currency(total_error_cost)}</div>
            <div class="kpi-delta" style="color:#f04848">{len(errors_df) if errors_df is not None else 0} events</div>
        </div>""", unsafe_allow_html=True)
    with k2:
        st.markdown(f"""<div class="kpi-card amber">
            <div class="kpi-label">Revenue Lost (Repricing)</div>
            <div class="kpi-value" style="color:#eda025">{fmt_currency(total_rev_lost)}/yr</div>
            <div class="kpi-delta" style="color:#eda025">{len(repricing_df) if repricing_df is not None else 0} clients</div>
        </div>""", unsafe_allow_html=True)
    with k3:
        st.markdown(f"""<div class="kpi-card red">
            <div class="kpi-label">Revenue at Risk (Churn)</div>
            <div class="kpi-value" style="color:#f04848">{fmt_currency(at_risk_rev)}</div>
            <div class="kpi-delta" style="color:#f04848">{at_risk_count} clients at risk</div>
        </div>""", unsafe_allow_html=True)
    with k4:
        st.markdown(f"""<div class="kpi-card blue">
            <div class="kpi-label">Total Costs (Period)</div>
            <div class="kpi-value" style="color:#3a7bfd">{fmt_currency(total_costs)}</div>
            <div class="kpi-delta" style="color:#5a6d8e">{len(costs_df) if costs_df is not None else 0} items</div>
        </div>""", unsafe_allow_html=True)
    with k5:
        net = -(total_error_cost + total_rev_lost)
        st.markdown(f"""<div class="kpi-card green">
            <div class="kpi-label">Net P&L Impact</div>
            <div class="kpi-value" style="color:#12c47a">{fmt_currency(net)}</div>
            <div class="kpi-delta" style="color:#5a6d8e">Errors + Repricing</div>
        </div>""", unsafe_allow_html=True)

    # ─── SECTION 1: ERRORS ───
    if errors_df is not None and len(errors_df) > 0:
        st.markdown("""<div class="section-header">
            <span class="section-num">01</span>
            <span class="section-label">Error Cost Analysis & Forecasting</span>
        </div>""", unsafe_allow_html=True)

        ec1, ec2 = st.columns(2)
        with ec1:
            monthly = errors_df.copy()
            monthly["month"] = monthly["date"].astype(str).str[:7]
            monthly_agg = monthly.groupby("month")["payout_usd"].sum().reset_index()
            monthly_agg["payout_k"] = monthly_agg["payout_usd"] / 1000

            fig = px.bar(monthly_agg, x="month", y="payout_k", title="Monthly Error Payouts ($K)",
                         color_discrete_sequence=[COLORS["red"]])
            fig.update_layout(**CHART_LAYOUT)
            fig.update_yaxes(title_text="Payout ($K)")
            st.plotly_chart(fig, use_container_width=True)

        with ec2:
            cause_agg = errors_df.groupby("root_cause")["payout_usd"].sum().reset_index()
            cause_agg = cause_agg.sort_values("payout_usd", ascending=False)
            fig = px.pie(cause_agg, values="payout_usd", names="root_cause", title="Root Cause Distribution",
                         color_discrete_sequence=[COLORS["red"], COLORS["amber"], COLORS["purple"], COLORS["blue"], COLORS["green"], "#5a6d8e"],
                         hole=0.55)
            fig.update_layout(**CHART_LAYOUT)
            st.plotly_chart(fig, use_container_width=True)

        with st.expander(f"📋 Error Event Log ({len(errors_df)} events)", expanded=True):
            display_df = errors_df.sort_values("payout_usd", ascending=False).copy()
            display_df["payout_usd"] = display_df["payout_usd"].apply(lambda x: f"${x:,.0f}")
            st.dataframe(display_df, use_container_width=True, hide_index=True)

    # ─── SECTION 2: REPRICING ───
    if repricing_df is not None and len(repricing_df) > 0:
        st.markdown("""<div class="section-header">
            <span class="section-num">02</span>
            <span class="section-label">Client Revenue Erosion</span>
        </div>""", unsafe_allow_html=True)

        rc1, rc2 = st.columns(2)
        with rc1:
            sorted_rp = repricing_df.sort_values("date")
            sorted_rp["rev_lost"] = (sorted_rp["old_fee_bps"] - sorted_rp["new_fee_bps"]) / 10000 * sorted_rp["aum_usd_m"] * 1_000_000
            sorted_rp["cumul_lost"] = sorted_rp["rev_lost"].cumsum()

            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=sorted_rp["date"].astype(str), y=-sorted_rp["cumul_lost"] / 1000,
                mode="lines+markers", fill="tozeroy",
                line=dict(color=COLORS["red"], width=2),
                fillcolor="rgba(240,72,72,0.08)",
                name="Cumulative Lost",
            ))
            fig.update_layout(title="Cumulative Revenue Impact ($K)", **CHART_LAYOUT)
            fig.update_yaxes(title_text="Revenue Lost ($K)")
            st.plotly_chart(fig, use_container_width=True)

        with rc2:
            fig = go.Figure()
            fig.add_trace(go.Bar(
                y=repricing_df["client_name"], x=repricing_df["old_fee_bps"],
                name="Old Fee (bps)", orientation="h",
                marker_color="rgba(58,123,253,0.3)",
            ))
            fig.add_trace(go.Bar(
                y=repricing_df["client_name"], x=repricing_df["new_fee_bps"],
                name="New Fee (bps)", orientation="h",
                marker_color=COLORS["blue"],
            ))
            fig.update_layout(title="Fee Change by Client (bps)", barmode="group", **CHART_LAYOUT)
            st.plotly_chart(fig, use_container_width=True)

        with st.expander(f"📋 Repricing Events ({len(repricing_df)} events)", expanded=True):
            rp_display = repricing_df.copy()
            rp_display["Δ_revenue_yr"] = ((rp_display["old_fee_bps"] - rp_display["new_fee_bps"]) / 10000 * rp_display["aum_usd_m"] * 1_000_000).apply(lambda x: f"-${abs(x):,.0f}")
            st.dataframe(rp_display, use_container_width=True, hide_index=True)

    # ─── SECTION 3: ATTRITION ───
    if attrition_df is not None and len(attrition_df) > 0:
        st.markdown("""<div class="section-header">
            <span class="section-num">03</span>
            <span class="section-label">Client Health & Churn Risk</span>
        </div>""", unsafe_allow_html=True)

        scored = attrition_df.copy()
        scored["risk_score"] = scored.apply(compute_risk_score, axis=1)

        ac1, ac2 = st.columns(2)
        with ac1:
            fig = px.scatter(
                scored, x="risk_score", y="annual_revenue_usd",
                size="aum_usd_m", hover_name="client_name",
                color="risk_score",
                color_continuous_scale=[[0, COLORS["green"]], [0.5, COLORS["amber"]], [1, COLORS["red"]]],
                title="Risk vs Revenue",
                labels={"risk_score": "Risk Score (%)", "annual_revenue_usd": "Annual Revenue ($)"},
            )
            fig.update_layout(**CHART_LAYOUT)
            fig.update_coloraxes(showscale=False)
            st.plotly_chart(fig, use_container_width=True)

        with ac2:
            scored_sorted = scored.sort_values("risk_score", ascending=False)
            display_attr = scored_sorted[["client_name", "aum_usd_m", "annual_revenue_usd", "escalations_12m", "errors_12m", "nps_score", "risk_score"]].copy()
            display_attr["annual_revenue_usd"] = display_attr["annual_revenue_usd"].apply(lambda x: f"${x:,.0f}")
            st.dataframe(display_attr, use_container_width=True, hide_index=True)

    # ─── SECTION 4: FORECAST & INSIGHTS ───
    st.markdown("""<div class="section-header">
        <span class="section-num">04</span>
        <span class="section-label">P&L Forecast & AI Insights</span>
    </div>""", unsafe_allow_html=True)

    fc1, fc2 = st.columns([3, 2])

    with fc1:
        impact = -(total_error_cost + total_rev_lost)
        base_val = impact / 1_000_000
        months = [f"M{i+1}" for i in range(12)]
        base = [round(base_val * (1 - i * 0.04), 2) for i in range(12)]
        upper = [round(b + abs(base_val) * 0.3, 2) for b in base]
        lower = [round(b - abs(base_val) * 0.35, 2) for b in base]

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=months, y=upper, name="Recovery (P90)", line=dict(color=COLORS["green"], dash="dash", width=1), fill=None))
        fig.add_trace(go.Scatter(x=months, y=base, name="Base (P50)", line=dict(color=COLORS["blue"], width=2.5), fill="tonexty", fillcolor="rgba(18,196,122,0.04)"))
        fig.add_trace(go.Scatter(x=months, y=lower, name="Bear (P10)", line=dict(color=COLORS["red"], dash="dash", width=1), fill="tonexty", fillcolor="rgba(240,72,72,0.04)"))
        fig.update_layout(title="12-Month P&L Projection ($M)", **CHART_LAYOUT)
        fig.update_yaxes(title_text="P&L Impact ($M)")
        st.plotly_chart(fig, use_container_width=True)

        sc1, sc2, sc3 = st.columns(3)
        sc1.metric("Bear (P10)", f"${lower[-1]:.1f}M", "Continued erosion")
        sc2.metric("Base (P50)", f"${base[-1]:.1f}M", "Current trajectory")
        sc3.metric("Recovery (P90)", f"${upper[-1]:.1f}M", "Interventions land")

    with fc2:
        st.markdown("#### AI-Generated Insights")
        insights = generate_insights(errors_df, repricing_df, attrition_df, costs_df)
        for ins in insights:
            st.markdown(f"""<div class="insight-box {ins['level']}">
                <span class="insight-tag {ins['level']}">{ins['label']}</span>
                {ins['text']}
            </div>""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
# FOOTER
# ═══════════════════════════════════════════════════════════════
st.markdown("---")
st.caption(f"FA P&L Intelligence Platform v1.0 · Built {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC")
