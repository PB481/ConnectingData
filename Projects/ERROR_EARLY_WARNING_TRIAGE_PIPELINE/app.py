"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  GLOBAL ERROR EARLY WARNING & TRIAGE PIPELINE — PHASE 2                     ║
║  Operational Risk Intelligence Dashboard — 2024–2025                        ║
║                                                                              ║
║  REACTIVE: EWMA-SPC + Autoencoder + Isolation Forest + PELT Changepoint     ║
║  PREDICTIVE: Gradient-Boosted Classifier on Lagged Leading Indicators       ║
║  Graceful degradation: base 7 cols → reactive only; expanded → predictive   ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
from scipy.signal import find_peaks
from sklearn.ensemble import IsolationForest, HistGradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.decomposition import PCA
from sklearn.inspection import permutation_importance
from sklearn.model_selection import TimeSeriesSplit
from sklearn.metrics import roc_auc_score, precision_score, recall_score
import io, calendar, warnings
warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="OpRisk Predictive Pipeline", page_icon="🔺",
                   layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=JetBrains+Mono:wght@400;500;700&display=swap');
.stApp{font-family:'DM Sans',sans-serif}
div[data-testid="stMetric"]{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);border:1px solid rgba(0,212,170,.15);border-radius:12px;padding:16px 20px;box-shadow:0 4px 20px rgba(0,0,0,.3)}
div[data-testid="stMetric"] label{font-family:'DM Sans',sans-serif!important;font-weight:500!important;color:#8892b0!important;font-size:.8rem!important;text-transform:uppercase;letter-spacing:.08em}
div[data-testid="stMetric"] [data-testid="stMetricValue"]{font-family:'JetBrains Mono',monospace!important;font-weight:700!important;color:#e6f1ff!important}
div[data-testid="stMetric"] [data-testid="stMetricDelta"]{font-family:'JetBrains Mono',monospace!important}
section[data-testid="stSidebar"]{background:linear-gradient(180deg,#0a0a1a 0%,#101028 100%);border-right:1px solid rgba(0,212,170,.1)}
section[data-testid="stSidebar"] .stMarkdown h1,section[data-testid="stSidebar"] .stMarkdown h2,section[data-testid="stSidebar"] .stMarkdown h3{color:#00d4aa!important}
.streamlit-expanderHeader{font-family:'DM Sans',sans-serif!important;font-weight:600!important;color:#ccd6f6!important;background:rgba(0,212,170,.05);border-radius:8px}
.stTabs [data-baseweb="tab-list"]{gap:8px}.stTabs [data-baseweb="tab"]{font-family:'DM Sans',sans-serif;font-weight:500;border-radius:8px 8px 0 0}
.stDataFrame{border-radius:8px;overflow:hidden}
.alert-banner{background:linear-gradient(135deg,#ff006620,#ff004010);border:1px solid #ff0066;border-radius:10px;padding:16px 24px;margin:8px 0;font-family:'JetBrains Mono',monospace;color:#ff6b9d;font-size:.9rem}
.ok-banner{background:linear-gradient(135deg,#00d4aa10,#00d4aa20);border:1px solid #00d4aa;border-radius:10px;padding:16px 24px;margin:8px 0;font-family:'JetBrains Mono',monospace;color:#00d4aa;font-size:.9rem}
.header-title{font-family:'JetBrains Mono',monospace;font-size:2.2rem;font-weight:700;background:linear-gradient(135deg,#00d4aa,#00b4d8);-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:-.02em;margin-bottom:0}
.header-sub{font-family:'DM Sans',sans-serif;color:#8892b0;font-size:1rem;margin-top:0}
.section-header{font-family:'JetBrains Mono',monospace;font-size:1.1rem;color:#00d4aa;border-bottom:1px solid rgba(0,212,170,.2);padding-bottom:8px;margin-top:24px;letter-spacing:.04em}
.insight-card{background:linear-gradient(135deg,#1a1a2e,#16213e);border:1px solid rgba(0,212,170,.12);border-radius:12px;padding:20px;margin:10px 0}
.how-box{background:linear-gradient(135deg,#1a1a2e,#0f2030);border-left:3px solid #00d4aa;border-radius:0 10px 10px 0;padding:14px 18px;margin:8px 0;font-size:.92rem;color:#a8b2d1}
.forecast-card{background:linear-gradient(135deg,#1a1a2e,#16213e);border:2px solid rgba(0,212,170,.25);border-radius:16px;padding:24px;margin:12px 0;text-align:center}
.forecast-high{border-color:#ff0066!important;background:linear-gradient(135deg,#1a1a2e,#2e1020)!important}
.forecast-med{border-color:#ff9f1c!important;background:linear-gradient(135deg,#1a1a2e,#2e2010)!important}
.forecast-low{border-color:#00d4aa!important}
.forecast-pct{font-family:'JetBrains Mono',monospace;font-size:3rem;font-weight:700;margin:8px 0}
.forecast-label{font-family:'DM Sans',sans-serif;color:#8892b0;font-size:.85rem;text-transform:uppercase;letter-spacing:.1em}
.pred-badge{display:inline-block;padding:3px 10px;border-radius:6px;font-family:'JetBrains Mono',monospace;font-size:.8rem;font-weight:600}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
BASE_COLS = ["Occurred Date", "Reporting Region", "Reporting Department",
             "Event Severity", "Automated or Manual Process", "Control (Core)",
             "Actual Bps Impact"]
LEADING_COLS = ["STP Rate (%)", "Exception Queue Depth", "Recon Breaks Open",
                "NAV Cycle Time (mins)", "Deployment Flag", "Staff Utilisation (%)",
                "Manual Overrides Today", "VIX Close", "Corporate Actions Count",
                "Regulatory Deadline", "Period End Flag"]
ALL_COLS = BASE_COLS + LEADING_COLS
VALID_REGIONS = {"NA", "EMEA", "APAC", "LATAM"}
VALID_SEVS = {"Low", "Medium", "High", "Critical"}

# Business-friendly names for the leading indicator features
FEATURE_LABELS = {
    "STP Rate (%)": "Straight-Through Processing Rate",
    "Exception Queue Depth": "Open Exception Queue Size",
    "Recon Breaks Open": "Unresolved Recon Breaks",
    "NAV Cycle Time (mins)": "NAV Production Time",
    "Deployment Flag": "Recent Code/Config Deployment",
    "Staff Utilisation (%)": "Team Staffing Level",
    "Manual Overrides Today": "Manual Control Overrides",
    "VIX Close": "Market Volatility (VIX)",
    "Corporate Actions Count": "Corporate Actions Volume",
    "Regulatory Deadline": "Regulatory Deadline Approaching",
    "Period End Flag": "Month/Quarter-End Pressure",
    "total_bps_lag1": "Yesterday\u2019s Total Error Cost",
    "total_bps_lag2": "Error Cost 2 Days Ago",
    "count_lag1": "Yesterday\u2019s Error Count",
    "high_crit_lag1": "Yesterday\u2019s High/Critical Errors",
    "manual_pct_lag1": "Yesterday\u2019s Manual Processing Rate",
    "mean_bps_lag1": "Yesterday\u2019s Avg Error Severity",
    "day_of_week": "Day of Week",
    "month": "Month",
    "is_monday": "Monday (Post-Weekend Backlog)",
}


def has_leading_indicators(df):
    """Check if the dataframe contains the expanded predictive columns."""
    present = [c for c in LEADING_COLS if c in df.columns]
    return len(present) >= 6  # need at least 6 of 11 to unlock predictive mode


# ─────────────────────────────────────────────────────────────────────────────
# DATA VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
def validate_uploaded_data(df):
    errors = []
    missing = [c for c in BASE_COLS if c not in df.columns]
    if missing:
        errors.append(f"Missing required columns: {', '.join(missing)}")
        return None, errors
    try:
        df["Occurred Date"] = pd.to_datetime(df["Occurred Date"], dayfirst=False)
    except Exception:
        errors.append("Could not parse 'Occurred Date'. Use YYYY-MM-DD format.")
        return None, errors

    bad_r = set(df["Reporting Region"].dropna().unique()) - VALID_REGIONS
    if bad_r:
        errors.append(f"Invalid Reporting Region: {bad_r}")
    bad_s = set(df["Event Severity"].dropna().unique()) - VALID_SEVS
    if bad_s:
        errors.append(f"Invalid Event Severity: {bad_s}")

    df["Actual Bps Impact"] = pd.to_numeric(df["Actual Bps Impact"], errors="coerce")
    # Convert binary flag columns
    for col in ["Deployment Flag", "Regulatory Deadline", "Period End Flag"]:
        if col in df.columns:
            df[col] = df[col].map({"Y": 1, "N": 0, "y": 1, "n": 0, 1: 1, 0: 0, "1": 1, "0": 0}).fillna(0).astype(int)
    # Numeric leading indicators
    for col in LEADING_COLS:
        if col in df.columns and col not in ["Deployment Flag", "Regulatory Deadline", "Period End Flag"]:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    before = len(df)
    df = df.dropna(subset=BASE_COLS).reset_index(drop=True)
    dropped = before - len(df)
    if dropped > 0:
        errors.append(f"Note: {dropped} rows dropped due to missing base values (non-blocking)")
    if len(df) < 50:
        errors.append(f"Only {len(df)} valid rows. Need at least 50.")
        return None, errors
    blocking = [e for e in errors if not e.startswith("Note:")]
    if blocking:
        return None, errors
    return df.sort_values("Occurred Date").reset_index(drop=True), errors


# ─────────────────────────────────────────────────────────────────────────────
# SYNTHETIC DATA GENERATION — 2 YEARS WITH LEADING INDICATORS
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=3600, show_spinner=False)
def generate_full_synthetic(n_records=8000, seed=42):
    """Generate 2-year dataset (2024-2025) with base + leading indicators.
    Injects EMEA September 2025 structural outage + correlated leading indicator degradation."""
    rng = np.random.default_rng(seed)
    start, end = datetime(2024, 1, 1), datetime(2025, 12, 31)
    total_days = (end - start).days + 1

    regions = ["NA", "EMEA", "APAC", "LATAM"]
    rwt = [0.30, 0.30, 0.25, 0.15]
    depts = {
        "NA": ["Fund Accounting", "Transfer Agency", "Compliance", "Middle Office", "Client Reporting"],
        "EMEA": ["Fund Accounting", "Transfer Agency", "Regulatory Ops", "NAV Oversight", "Depositary Ops"],
        "APAC": ["Fund Accounting", "Transfer Agency", "Compliance", "Settlement Ops", "Client Reporting"],
        "LATAM": ["Fund Accounting", "Transfer Agency", "Compliance", "Back Office", "Client Reporting"],
    }
    sevs = ["Low", "Medium", "High", "Critical"]
    sw_norm = [0.45, 0.30, 0.18, 0.07]
    sw_out = [0.10, 0.20, 0.35, 0.35]
    ctrls = ["4-Eye Check", "Automated Recon", "Tolerance Breach Gate", "Pre-NAV Validation",
             "AML/KYC Screen", "Swing Price Check", "FX Rate Lock", "Cash Recon",
             "Position Matching", "Price Stale Check"]

    records = []
    for _ in range(n_records):
        day_off = rng.integers(0, total_days)
        occ = start + timedelta(days=int(day_off))
        region = rng.choice(regions, p=rwt)
        dept = rng.choice(depts[region])
        ctrl = rng.choice(ctrls)
        is_outage = (region == "EMEA" and occ.month == 9 and occ.year == 2025)

        if is_outage:
            proc = rng.choice(["Automated", "Manual"], p=[0.15, 0.85])
            sev = rng.choice(sevs, p=sw_out)
            bps = round(float(np.clip(rng.lognormal(3.8, 0.7), 25, 250)), 2)
            # Degraded leading indicators
            stp = round(float(np.clip(rng.normal(55, 15), 10, 85)), 1)
            eq_depth = int(np.clip(rng.poisson(45), 10, 120))
            recon = int(np.clip(rng.poisson(18), 3, 50))
            nav_time = round(float(np.clip(rng.normal(180, 40), 90, 320)), 0)
            deploy = int(rng.random() < 0.6)
            staff = round(float(np.clip(rng.normal(68, 12), 35, 90)), 1)
            overrides = int(np.clip(rng.poisson(12), 2, 35))
            vix = round(float(np.clip(rng.normal(28, 6), 14, 55)), 1)
            ca_count = int(np.clip(rng.poisson(8), 0, 25))
        else:
            proc = rng.choice(["Automated", "Manual"], p=[0.72, 0.28])
            sev = rng.choice(sevs, p=sw_norm)
            sm = {"Low": 1.0, "Medium": 2.2, "High": 4.5, "Critical": 9.0}[sev]
            rm = {"NA": 1.0, "EMEA": 1.1, "APAC": 0.9, "LATAM": 1.3}[region]
            bps = round(float(np.clip(rng.lognormal(1.2, 0.8) * sm * rm, 0.1, 80)), 2)
            # Normal leading indicators
            stp = round(float(np.clip(rng.normal(91, 5), 60, 99)), 1)
            eq_depth = int(np.clip(rng.poisson(8), 0, 40))
            recon = int(np.clip(rng.poisson(3), 0, 20))
            nav_time = round(float(np.clip(rng.normal(95, 20), 40, 200)), 0)
            deploy = int(rng.random() < 0.12)
            staff = round(float(np.clip(rng.normal(94, 6), 60, 110)), 1)
            overrides = int(np.clip(rng.poisson(2), 0, 12))
            vix = round(float(np.clip(rng.normal(18, 4), 9, 40)), 1)
            ca_count = int(np.clip(rng.poisson(3), 0, 15))

        # Calendar flags
        dom = occ.day
        is_period = 1 if (dom >= 28 or dom <= 2) else 0
        is_reg = 1 if (occ.day in [10, 14, 15, 20, 25] and occ.month in [1, 3, 4, 6, 7, 9, 10, 12]) else 0

        records.append({
            "Occurred Date": occ, "Reporting Region": region, "Reporting Department": dept,
            "Event Severity": sev, "Automated or Manual Process": proc,
            "Control (Core)": ctrl, "Actual Bps Impact": bps,
            "STP Rate (%)": stp, "Exception Queue Depth": eq_depth,
            "Recon Breaks Open": recon, "NAV Cycle Time (mins)": nav_time,
            "Deployment Flag": deploy, "Staff Utilisation (%)": staff,
            "Manual Overrides Today": overrides, "VIX Close": vix,
            "Corporate Actions Count": ca_count,
            "Regulatory Deadline": is_reg, "Period End Flag": is_period,
        })

    df = pd.DataFrame(records)
    df["Occurred Date"] = pd.to_datetime(df["Occurred Date"])
    return df.sort_values("Occurred Date").reset_index(drop=True)


def generate_template_csv():
    """Empty template with 5 example rows including all columns."""
    rows = [
        {"Occurred Date": "2025-01-15", "Reporting Region": "EMEA", "Reporting Department": "Fund Accounting",
         "Event Severity": "Low", "Automated or Manual Process": "Automated", "Control (Core)": "4-Eye Check",
         "Actual Bps Impact": 3.5, "STP Rate (%)": 93.2, "Exception Queue Depth": 5,
         "Recon Breaks Open": 2, "NAV Cycle Time (mins)": 88, "Deployment Flag": "N",
         "Staff Utilisation (%)": 96, "Manual Overrides Today": 1, "VIX Close": 16.3,
         "Corporate Actions Count": 2, "Regulatory Deadline": "N", "Period End Flag": "N"},
        {"Occurred Date": "2025-02-20", "Reporting Region": "NA", "Reporting Department": "Transfer Agency",
         "Event Severity": "Medium", "Automated or Manual Process": "Manual", "Control (Core)": "Cash Recon",
         "Actual Bps Impact": 12.8, "STP Rate (%)": 87.0, "Exception Queue Depth": 12,
         "Recon Breaks Open": 5, "NAV Cycle Time (mins)": 110, "Deployment Flag": "Y",
         "Staff Utilisation (%)": 88, "Manual Overrides Today": 4, "VIX Close": 22.1,
         "Corporate Actions Count": 5, "Regulatory Deadline": "N", "Period End Flag": "N"},
    ]
    return pd.DataFrame(rows).to_csv(index=False)


# ─────────────────────────────────────────────────────────────────────────────
# REACTIVE ML ENGINES (from Phase 1)
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def run_trend_monitor(df, span=14, sensitivity=2.5):
    daily = df.groupby(df["Occurred Date"].dt.date).agg(
        total_bps=("Actual Bps Impact", "sum"), mean_bps=("Actual Bps Impact", "mean"),
        count=("Actual Bps Impact", "count"), max_bps=("Actual Bps Impact", "max"),
        high_crit_count=("Event Severity", lambda x: ((x == "High") | (x == "Critical")).sum()),
        manual_pct=("Automated or Manual Process", lambda x: (x == "Manual").mean()),
    ).reset_index()
    daily.columns = ["date", "total_bps", "mean_bps", "count", "max_bps", "high_crit_count", "manual_pct"]
    daily["date"] = pd.to_datetime(daily["date"])
    daily = daily.sort_values("date").reset_index(drop=True)
    daily["trend"] = daily["total_bps"].ewm(span=span, adjust=False).mean()
    daily["trend_std"] = daily["total_bps"].ewm(span=span, adjust=False).std()
    daily["upper_limit"] = daily["trend"] + sensitivity * daily["trend_std"]
    daily["lower_limit"] = (daily["trend"] - sensitivity * daily["trend_std"]).clip(lower=0)
    daily["over_limit"] = (daily["total_bps"] > daily["upper_limit"]).astype(int)
    rm = daily["total_bps"].rolling(21, min_periods=5).mean()
    rs = daily["total_bps"].rolling(21, min_periods=5).std()
    daily["deviation"] = (daily["total_bps"] - rm) / rs.replace(0, np.nan)
    daily["extreme_day"] = (daily["deviation"].abs() > sensitivity).astype(int).fillna(0)
    daily["flagged_day"] = ((daily["over_limit"] == 1) | (daily["extreme_day"] == 1)).astype(int)
    return daily


@st.cache_data(show_spinner=False)
def run_event_screener(df, alert_rate=0.06):
    fdf = df.copy()
    cat_cols = ["Reporting Region", "Reporting Department", "Event Severity",
                "Automated or Manual Process", "Control (Core)"]
    for col in cat_cols:
        fdf[col + "_enc"] = LabelEncoder().fit_transform(fdf[col])
    fdf["day_of_year"] = fdf["Occurred Date"].dt.dayofyear
    fdf["month"] = fdf["Occurred Date"].dt.month
    fdf["day_of_week"] = fdf["Occurred Date"].dt.dayofweek
    nc = [c + "_enc" for c in cat_cols] + ["Actual Bps Impact", "day_of_year", "month", "day_of_week"]
    X = fdf[nc].values.astype(float)
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    # Autoencoder
    nf, nh = Xs.shape[1], max(3, Xs.shape[1] // 3)
    rng = np.random.default_rng(42)
    W1 = rng.standard_normal((nf, nh)) * np.sqrt(2.0 / nf); b1 = np.zeros(nh)
    W2 = rng.standard_normal((nh, nf)) * np.sqrt(2.0 / nh); b2 = np.zeros(nf)
    for _ in range(80):
        idx = rng.permutation(len(Xs))
        for s in range(0, len(Xs), 128):
            b = Xs[idx[s:s+128]]
            h = np.maximum(0, b @ W1 + b1); o = h @ W2 + b2; e = o - b
            W2 -= 0.005 * (h.T @ e / len(b)); b2 -= 0.005 * e.mean(0)
            dh = e @ W2.T; dh[h <= 0] = 0
            W1 -= 0.005 * (b.T @ dh / len(b)); b1 -= 0.005 * dh.mean(0)
    hf = np.maximum(0, Xs @ W1 + b1); rec = hf @ W2 + b2
    ps = np.mean((Xs - rec) ** 2, axis=1)
    ae_flag = (ps > np.percentile(ps, (1 - alert_rate) * 100)).astype(int)
    iso = IsolationForest(n_estimators=200, contamination=alert_rate, max_features=0.8, random_state=42, n_jobs=-1)
    iso_flag = (iso.fit_predict(Xs) == -1).astype(int)
    iscore = -iso.score_samples(Xs)
    unusual = ((ae_flag == 1) | (iso_flag == 1)).astype(int)
    return ps, iscore, unusual, Xs, scaler, nc


@st.cache_data(show_spinner=False)
def run_regime_detection(daily_df, sensitivity=15):
    sig = daily_df["total_bps"].values
    try:
        import ruptures as rpt
        cp = rpt.Pelt(model="rbf", min_size=7, jump=1).fit(sig).predict(pen=sensitivity)
        cp = [c for c in cp if c < len(sig)]
    except ImportError:
        cs = np.cumsum(sig - np.mean(sig))
        peaks, _ = find_peaks(np.abs(cs), height=np.std(cs) * 3, distance=20)
        cp = peaks.tolist()
    return cp, [daily_df["date"].iloc[min(c, len(daily_df)-1)] for c in cp]


def build_triage(df, daily_df, unusual):
    df = df.copy(); df["unusual_event"] = unusual; df["event_date"] = df["Occurred Date"].dt.date
    fd = set(daily_df[daily_df["flagged_day"] == 1]["date"].dt.date)
    df["bad_day"] = df["event_date"].isin(fd).astype(int)
    df["confirmed_alert"] = ((df["bad_day"] == 1) & (df["unusual_event"] == 1)).astype(int)
    def pri(r):
        if r["confirmed_alert"] == 1:
            return "🔴 CRITICAL" if r["Event Severity"] in ["Critical", "High"] else "🟠 HIGH"
        elif r["unusual_event"] == 1 or r["bad_day"] == 1: return "🟡 WATCH"
        return "🟢 NORMAL"
    df["Priority"] = df.apply(pri, axis=1)
    return df


def explain_root_cause(adf, fdf):
    if len(adf) == 0: return []
    bl = fdf[fdf["confirmed_alert"] == 0]; f = []
    rd = adf["Reporting Region"].value_counts(normalize=True)
    br = bl["Reporting Region"].value_counts(normalize=True)
    for r, p in rd.items():
        bp = br.get(r, 0)
        if p > bp * 1.8: f.append(f"**{r} disproportionately affected** — {p:.0%} of alerts vs {bp:.0%} baseline")
    am = (adf["Automated or Manual Process"] == "Manual").mean()
    bm = (bl["Automated or Manual Process"] == "Manual").mean()
    if am > bm * 1.5: f.append(f"**Manual processing surged** to {am:.0%} (vs {bm:.0%} normally)")
    ac = adf["Event Severity"].isin(["High", "Critical"]).mean()
    bc = bl["Event Severity"].isin(["High", "Critical"]).mean()
    if ac > bc * 1.5: f.append(f"**Severity escalation** — {ac:.0%} High/Critical vs {bc:.0%} baseline")
    ab = adf["Actual Bps Impact"].mean(); bb = bl["Actual Bps Impact"].mean()
    if ab > bb * 2: f.append(f"**Impact {ab/bb:.1f}× normal** — avg {ab:.1f} bps vs {bb:.1f} bps baseline")
    dd = adf["Reporting Department"].value_counts(normalize=True)
    if len(dd) > 0:
        td, tp = dd.index[0], dd.iloc[0]
        if tp > (bl["Reporting Department"] == td).mean() * 1.5: f.append(f"**{td}** hardest-hit ({tp:.0%} of alerts)")
    cd = adf["Control (Core)"].value_counts(normalize=True)
    if len(cd) > 0: f.append(f"**Failing control:** {cd.index[0]}")
    ad = pd.to_datetime(adf["Occurred Date"])
    pm = ad.dt.month.mode()
    if len(pm) > 0: f.append(f"**Concentrated in {calendar.month_name[pm.iloc[0]]}**")
    return f


# ─────────────────────────────────────────────────────────────────────────────
# PREDICTIVE ENGINE: GRADIENT-BOOSTED CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def build_predictive_model(df, daily_df, threshold_pctile=85):
    """
    Train a Gradient-Boosted Classifier to predict whether tomorrow will have
    elevated error activity, using time-lagged leading indicators as features.
    Returns: model, feature_names, daily_features_df, model_metrics, forecasts
    """
    # 1. Build daily feature table by merging event-level leading indicators
    lead_agg = {}
    for col in LEADING_COLS:
        if col in df.columns:
            lead_agg[col] = (col, "mean")  # daily average of the leading indicator

    daily_lead = df.groupby(df["Occurred Date"].dt.date).agg(**lead_agg).reset_index()
    daily_lead.columns = ["date"] + [c for c in lead_agg.keys()]
    daily_lead["date"] = pd.to_datetime(daily_lead["date"])

    # Merge with daily reactive metrics
    feat = daily_df[["date", "total_bps", "mean_bps", "count", "max_bps",
                      "high_crit_count", "manual_pct"]].merge(daily_lead, on="date", how="left")
    feat = feat.sort_values("date").reset_index(drop=True)

    # 2. Create target: is tomorrow's total BPS above the Nth percentile?
    threshold = np.percentile(feat["total_bps"].dropna(), threshold_pctile)
    feat["target"] = (feat["total_bps"].shift(-1) > threshold).astype(int)

    # 3. Create lagged features (T-1, T-2 of reactive metrics)
    for lag in [1, 2]:
        feat[f"total_bps_lag{lag}"] = feat["total_bps"].shift(lag)
        if lag == 1:
            feat["count_lag1"] = feat["count"].shift(1)
            feat["high_crit_lag1"] = feat["high_crit_count"].shift(1)
            feat["manual_pct_lag1"] = feat["manual_pct"].shift(1)
            feat["mean_bps_lag1"] = feat["mean_bps"].shift(1)

    # Calendar features
    feat["day_of_week"] = feat["date"].dt.dayofweek
    feat["month"] = feat["date"].dt.month
    feat["is_monday"] = (feat["day_of_week"] == 0).astype(int)

    # 4. Define feature columns (exclude target and raw same-day metrics the model shouldn't peek at)
    feature_cols = []
    # Lagged reactive
    for c in ["total_bps_lag1", "total_bps_lag2", "count_lag1", "high_crit_lag1",
              "manual_pct_lag1", "mean_bps_lag1"]:
        if c in feat.columns:
            feature_cols.append(c)
    # Leading indicators (same-day is fair — these are available BEFORE errors occur)
    for c in LEADING_COLS:
        if c in feat.columns:
            feature_cols.append(c)
    # Calendar
    feature_cols += ["day_of_week", "month", "is_monday"]

    # Drop rows with NaN target or insufficient features
    model_df = feat.dropna(subset=["target"] + feature_cols[:3]).copy()
    if len(model_df) < 60:
        return None, None, feat, {}, None

    X = model_df[feature_cols].values.astype(float)
    y = model_df["target"].values.astype(int)

    # 5. Time-series aware split (last 20% for validation)
    split_idx = int(len(X) * 0.8)
    X_train, X_val = X[:split_idx], X[split_idx:]
    y_train, y_val = y[:split_idx], y[split_idx:]

    # 6. Train HistGradientBoosting (sklearn's XGBoost-equivalent)
    model = HistGradientBoostingClassifier(
        max_iter=300, max_depth=5, learning_rate=0.05,
        min_samples_leaf=10, l2_regularization=1.0,
        early_stopping=True, validation_fraction=0.15,
        n_iter_no_change=20, random_state=42,
    )
    model.fit(X_train, y_train)

    # 7. Metrics
    metrics = {}
    if len(X_val) > 10 and y_val.sum() > 0:
        y_prob = model.predict_proba(X_val)[:, 1]
        y_pred = model.predict(X_val)
        try: metrics["AUC"] = round(roc_auc_score(y_val, y_prob), 3)
        except: metrics["AUC"] = None
        metrics["Precision"] = round(precision_score(y_val, y_pred, zero_division=0), 3)
        metrics["Recall"] = round(recall_score(y_val, y_pred, zero_division=0), 3)
        metrics["Val Size"] = len(y_val)
        metrics["Positive Rate"] = round(y_val.mean(), 3)

    # 8. Permutation importance (model-agnostic, like SHAP but more robust for small data)
    if len(X_val) > 10:
        pi = permutation_importance(model, X_val, y_val, n_repeats=15, random_state=42, n_jobs=-1)
        importance = pd.DataFrame({
            "feature": feature_cols,
            "importance": pi.importances_mean,
            "std": pi.importances_std,
        }).sort_values("importance", ascending=False)
    else:
        importance = pd.DataFrame({"feature": feature_cols, "importance": 0, "std": 0})

    # 9. Generate forecasts for all days (including the last day = "tomorrow")
    feat_full = feat.copy()
    feat_full["forecast_prob"] = np.nan
    valid_mask = feat_full[feature_cols].notna().all(axis=1)
    if valid_mask.sum() > 0:
        X_all = feat_full.loc[valid_mask, feature_cols].values.astype(float)
        probs = model.predict_proba(X_all)[:, 1]
        feat_full.loc[valid_mask, "forecast_prob"] = probs

    return model, feature_cols, feat_full, metrics, importance


# ─────────────────────────────────────────────────────────────────────────────
# CHART CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
C = {"bg": "#0a0a1a", "paper": "#0f0f23", "grid": "rgba(0,212,170,0.06)",
     "text": "#8892b0", "title": "#ccd6f6", "accent": "#00d4aa",
     "accent2": "#00b4d8", "danger": "#ff0066", "warning": "#ff9f1c", "signal": "#e6f1ff"}
LY = dict(plot_bgcolor=C["bg"], paper_bgcolor=C["paper"],
          font=dict(family="DM Sans, sans-serif", color=C["text"], size=12),
          title_font=dict(family="JetBrains Mono, monospace", color=C["title"], size=15),
          margin=dict(l=50, r=30, t=60, b=40),
          legend=dict(bgcolor="rgba(0,0,0,0)", bordercolor="rgba(0,212,170,0.15)", borderwidth=1, font=dict(size=11)))
AX = dict(gridcolor=C["grid"], zerolinecolor=C["grid"])

def styled(fig):
    fig.update_xaxes(**AX); fig.update_yaxes(**AX); return fig


# ── Reactive charts ──
def chart_daily_trend(daily_df, change_dates):
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=daily_df["date"], y=daily_df["total_bps"], mode="lines", name="Actual Daily Impact",
        line=dict(color=C["signal"], width=1.2), opacity=0.5))
    fig.add_trace(go.Scatter(x=daily_df["date"], y=daily_df["trend"], mode="lines", name="Smoothed Trend",
        line=dict(color=C["accent"], width=2.5)))
    fig.add_trace(go.Scatter(x=daily_df["date"], y=daily_df["upper_limit"], mode="lines", name="Upper Warning",
        line=dict(color=C["danger"], width=1, dash="dash")))
    fig.add_trace(go.Scatter(x=daily_df["date"], y=daily_df["lower_limit"], mode="lines", name="Lower Warning",
        line=dict(color=C["accent2"], width=1, dash="dash"), fill="tonexty", fillcolor="rgba(0,212,170,0.03)"))
    br = daily_df[daily_df["flagged_day"] == 1]
    fig.add_trace(go.Scatter(x=br["date"], y=br["total_bps"], mode="markers", name="Abnormal Day",
        marker=dict(color=C["danger"], size=9, symbol="diamond", line=dict(width=1.5, color="#fff"))))
    for cpd in change_dates:
        fig.add_vline(x=cpd, line_dash="dot", line_color=C["warning"], line_width=2, opacity=0.8,
            annotation_text="REGIME SHIFT", annotation_position="top",
            annotation=dict(font=dict(color=C["warning"], size=10, family="JetBrains Mono")))
    fig.update_layout(**LY, title="Daily Impact Trend — Are error costs creeping up or spiking?",
        xaxis_title="Date", yaxis_title="Total Daily BPS Impact", height=440, hovermode="x unified")
    return styled(fig)

def chart_heatmap(df):
    df2 = df.copy(); df2["month"] = df2["Occurred Date"].dt.month
    pv = df2.groupby(["Reporting Region", "month"]).agg(m=("Actual Bps Impact", "mean")).reset_index()
    pw = pv.pivot(index="Reporting Region", columns="month", values="m")
    for m in range(1, 13):
        if m not in pw.columns: pw[m] = 0
    pw = pw[sorted(pw.columns)]
    mos = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    fig = go.Figure(data=go.Heatmap(z=pw.values, x=mos, y=pw.index.tolist(),
        colorscale=[[0,"#0a0a1a"],[.3,"#0f4c5c"],[.6,"#00b4d8"],[.8,"#ff9f1c"],[1,"#ff0066"]],
        colorbar=dict(title="Avg BPS", tickfont=dict(color=C["text"])),
        hovertemplate="Region: %{y}<br>Month: %{x}<br>Avg Impact: %{z:.1f} bps<extra></extra>"))
    fig.update_layout(**LY, title="Where & When Are Errors Most Costly?", xaxis_title="Month", yaxis_title="Region", height=300)
    return styled(fig)

def chart_manual_trend(df):
    df2 = df.copy(); df2["month"] = df2["Occurred Date"].dt.month
    mo = df2.groupby(["Reporting Region", "month"]).apply(
        lambda x: (x["Automated or Manual Process"] == "Manual").mean() * 100, include_groups=False
    ).reset_index(name="manual_pct")
    fig = px.line(mo, x="month", y="manual_pct", color="Reporting Region", markers=True,
        color_discrete_map={"NA": C["accent2"], "EMEA": C["danger"], "APAC": C["accent"], "LATAM": C["warning"]})
    fig.update_layout(**LY, title="Manual Workaround Rate by Region", xaxis_title="Month", yaxis_title="% Manual", height=350)
    fig.update_xaxes(tickmode="array", tickvals=list(range(1,13)),
        ticktext=["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], **AX)
    fig.update_yaxes(**AX)
    return fig


# ── Predictive charts ──
def chart_forecast_timeline(feat_df):
    """Probability of elevated errors over time."""
    fdf = feat_df.dropna(subset=["forecast_prob"]).copy()
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=fdf["date"], y=fdf["forecast_prob"] * 100,
        mode="lines", name="Risk Probability",
        line=dict(color=C["accent"], width=2), fill="tozeroy", fillcolor="rgba(0,212,170,0.08)"))
    fig.add_hline(y=60, line_dash="dash", line_color=C["warning"], line_width=1,
        annotation_text="Elevated Risk (60%)", annotation_position="right",
        annotation=dict(font=dict(color=C["warning"], size=10)))
    fig.add_hline(y=80, line_dash="dash", line_color=C["danger"], line_width=1,
        annotation_text="High Risk (80%)", annotation_position="right",
        annotation=dict(font=dict(color=C["danger"], size=10)))
    fig.update_layout(**LY, title="Predicted Risk of Elevated Errors — Forward-Looking Probability",
        xaxis_title="Date", yaxis_title="Probability of Elevated Errors Tomorrow (%)", height=400, hovermode="x unified")
    fig.update_yaxes(range=[0, 100], **AX)
    fig.update_xaxes(**AX)
    return fig

def chart_feature_importance(importance_df, top_n=12):
    """Horizontal bar chart of feature importance with business-friendly labels."""
    top = importance_df.head(top_n).copy()
    top["label"] = top["feature"].map(lambda f: FEATURE_LABELS.get(f, f))
    top = top.sort_values("importance", ascending=True)

    fig = go.Figure()
    colors = [C["danger"] if v > 0.03 else C["warning"] if v > 0.01 else C["accent"] for v in top["importance"]]
    fig.add_trace(go.Bar(y=top["label"], x=top["importance"], orientation="h",
        marker=dict(color=colors, line=dict(width=0)),
        error_x=dict(type="data", array=top["std"].values, color=C["text"], thickness=1),
        hovertemplate="%{y}: %{x:.4f}<extra></extra>"))
    fig.update_layout(**LY,
        title="What\u2019s Driving the Prediction? — Feature Importance Ranking",
        xaxis_title="Importance (higher = more influence on prediction)",
        yaxis_title="", height=max(300, top_n * 32 + 80))
    fig.update_layout(margin=dict(l=250, r=30, t=60, b=40))
    return styled(fig)

def chart_leading_indicators(feat_df):
    """Small multiples of key leading indicators over time."""
    indicators = [c for c in ["STP Rate (%)", "Exception Queue Depth", "Recon Breaks Open",
                               "NAV Cycle Time (mins)", "Staff Utilisation (%)", "VIX Close"]
                  if c in feat_df.columns and feat_df[c].notna().sum() > 10]
    if not indicators:
        return None
    from plotly.subplots import make_subplots
    fig = make_subplots(rows=len(indicators), cols=1, shared_xaxes=True,
                        subplot_titles=[FEATURE_LABELS.get(i, i) for i in indicators],
                        vertical_spacing=0.04)
    for idx, col in enumerate(indicators, 1):
        series = feat_df.dropna(subset=[col])
        fig.add_trace(go.Scatter(x=series["date"], y=series[col], mode="lines",
            line=dict(color=C["accent"], width=1.5), name=FEATURE_LABELS.get(col, col), showlegend=False), row=idx, col=1)
    fig.update_layout(plot_bgcolor=C["bg"], paper_bgcolor=C["paper"], height=180 * len(indicators),
        font=dict(family="DM Sans, sans-serif", color=C["text"], size=11),
        margin=dict(l=60, r=30, t=40, b=30))
    for i in range(1, len(indicators) + 1):
        fig.update_xaxes(gridcolor=C["grid"], row=i, col=1)
        fig.update_yaxes(gridcolor=C["grid"], row=i, col=1)
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APPLICATION
# ─────────────────────────────────────────────────────────────────────────────
def main():
    st.markdown('<p class="header-title">🔺 OPERATIONAL RISK EARLY WARNING SYSTEM</p>', unsafe_allow_html=True)
    st.markdown('<p class="header-sub">Phase 2 — Reactive Detection + Predictive Forecasting Engine</p>', unsafe_allow_html=True)

    # ── SIDEBAR ──
    with st.sidebar:
        st.markdown("### 📁 Data Source")
        data_mode = st.radio("Choose data source",
            ["Use sample data (demo)", "Upload my own data"],
            help="Sample data includes 2 years of events with leading indicators. Upload your own CSV to run on real data.")

        st.download_button("📥 Download CSV template (with all columns)",
            data=generate_template_csv(), file_name="oprisk_predictive_template.csv", mime="text/csv",
            help="Template includes base event columns + all 11 leading indicator columns.")

        uploaded_file = None
        if data_mode == "Upload my own data":
            uploaded_file = st.file_uploader("Upload event data (CSV)", type=["csv"])
            if uploaded_file is None:
                st.info("Upload a CSV to begin, or switch to sample data.")

        st.markdown("---")
        st.markdown("### 🎛 Sensitivity Controls")
        trend_window = st.slider("Trend smoothing (days)", 5, 30, 14,
            help="Shorter = faster reaction, more noise. Longer = smoother, slower.")
        alert_sensitivity = st.slider("Alert sensitivity", 1.5, 4.0, 2.5, 0.1,
            help="Lower = more alerts. Higher = only extremes.")
        anomaly_rate = st.slider("Unusual event rate", 0.02, 0.15, 0.06, 0.01)
        regime_sens = st.slider("Regime shift sensitivity", 5, 50, 15)

        st.markdown("---")
        st.markdown("### 🔎 Filters")
        region_filter = st.multiselect("Regions", ["NA", "EMEA", "APAC", "LATAM"],
                                       default=["NA", "EMEA", "APAC", "LATAM"])
        severity_filter = st.multiselect("Severities", ["Low", "Medium", "High", "Critical"],
                                         default=["Low", "Medium", "High", "Critical"])

        if data_mode == "Use sample data (demo)":
            st.markdown("---")
            st.markdown("### 🧪 Sample Data")
            n_records = st.number_input("Records", 4000, 15000, 8000, 1000)
            seed = st.number_input("Seed", 1, 999, 42, 1)
        else:
            n_records, seed = 8000, 42

        st.markdown("---")
        st.caption("v4.0 — Phase 2: Predictive Engine")

    # ── LOAD DATA ──
    if data_mode == "Upload my own data":
        if uploaded_file is None:
            st.markdown('<div class="how-box"><b>Getting started:</b><br>'
                '1. Download the CSV template from the sidebar<br>'
                '2. Fill it with your data (leading indicator columns are optional)<br>'
                '3. Upload and the dashboard will auto-detect which mode to run</div>', unsafe_allow_html=True)
            st.stop()
        try: raw_df = pd.read_csv(uploaded_file)
        except Exception as e: st.error(f"Could not read CSV: {e}"); st.stop()
        clean_df, errors = validate_uploaded_data(raw_df)
        for e in errors:
            (st.warning if e.startswith("Note:") else st.error)(e)
        if clean_df is None: st.stop()
        raw_df = clean_df
        st.success(f"Loaded {len(raw_df):,} events ({raw_df['Occurred Date'].min().strftime('%b %Y')} – {raw_df['Occurred Date'].max().strftime('%b %Y')})")
    else:
        with st.spinner("Generating 2-year synthetic dataset with leading indicators..."):
            raw_df = generate_full_synthetic(n_records=n_records, seed=seed)

    # ── DETECT MODE ──
    predictive_mode = has_leading_indicators(raw_df)

    # ── FILTER ──
    df = raw_df[(raw_df["Reporting Region"].isin(region_filter)) &
                (raw_df["Event Severity"].isin(severity_filter))].copy().reset_index(drop=True)
    if len(df) < 50:
        st.error("Not enough data with current filters."); return

    # ── MODE INDICATOR ──
    if predictive_mode:
        present = [c for c in LEADING_COLS if c in df.columns]
        st.markdown(
            f'<div class="ok-banner">🧠 <b>PREDICTIVE MODE ACTIVE</b> — {len(present)} leading indicator columns detected. '
            f'Tomorrow\u2019s Forecast panel is enabled.</div>', unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="how-box">📊 <b>REACTIVE MODE</b> — Only base event columns detected. '
            'Add leading indicator columns (STP Rate, Exception Queue Depth, etc.) to unlock predictive forecasting.</div>',
            unsafe_allow_html=True)

    # ── RUN REACTIVE MODELS ──
    with st.spinner("Analysing daily trends..."): daily_df = run_trend_monitor(df, span=trend_window, sensitivity=alert_sensitivity)
    with st.spinner("Screening events..."): ps, iscore, unusual, Xs, scaler, nc = run_event_screener(df, alert_rate=anomaly_rate)
    with st.spinner("Detecting regime shifts..."): cps, cpdates = run_regime_detection(daily_df, sensitivity=regime_sens)
    df = build_triage(df, daily_df, unusual)
    confirmed = df[df["confirmed_alert"] == 1]
    n_alerts = len(confirmed)

    # ── RUN PREDICTIVE MODEL (if available) ──
    model, feat_cols, feat_df, model_metrics, importance = None, None, None, {}, None
    if predictive_mode:
        with st.spinner("Training predictive model on leading indicators..."):
            model, feat_cols, feat_df, model_metrics, importance = build_predictive_model(df, daily_df)

    # ── KPI STRIP ──
    st.markdown('<p class="section-header">DASHBOARD OVERVIEW</p>', unsafe_allow_html=True)
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Events", f"{len(df):,}")
    c2.metric("Abnormal Days", int(daily_df["flagged_day"].sum()),
        delta=f"{daily_df['flagged_day'].sum()/max(len(daily_df),1)*100:.0f}% of days")
    c3.metric("Unusual Events", int(unusual.sum()), delta=f"{unusual.sum()/max(len(df),1)*100:.1f}%")
    c4.metric("Confirmed Alerts", n_alerts,
        delta="ACTION REQUIRED" if n_alerts > 0 else "ALL CLEAR",
        delta_color="inverse" if n_alerts > 0 else "normal")
    c5.metric("Regime Shifts", len(cpdates))
    if predictive_mode and feat_df is not None and "forecast_prob" in feat_df.columns:
        last_prob = feat_df.dropna(subset=["forecast_prob"])
        if len(last_prob) > 0:
            tp = last_prob.iloc[-1]["forecast_prob"]
            c6.metric("Tomorrow\u2019s Risk", f"{tp:.0%}",
                delta="HIGH" if tp > 0.6 else "MODERATE" if tp > 0.35 else "LOW",
                delta_color="inverse" if tp > 0.6 else "normal" if tp < 0.35 else "off")
        else:
            c6.metric("Tomorrow\u2019s Risk", "N/A")
    else:
        c6.metric("Avg Impact", f"{df['Actual Bps Impact'].mean():.1f} bps")

    # Alert banner
    if n_alerts > 0:
        tr = confirmed["Reporting Region"].value_counts()
        st.markdown(
            f'<div class="alert-banner">⚠ ACTION REQUIRED — {n_alerts} confirmed alerts | '
            f'Worst region: {tr.index[0]} ({tr.iloc[0]} events) | {len(cpdates)} structural shift(s)</div>',
            unsafe_allow_html=True)
    elif predictive_mode and feat_df is not None:
        lp = feat_df.dropna(subset=["forecast_prob"])
        if len(lp) > 0 and lp.iloc[-1]["forecast_prob"] > 0.6:
            st.markdown(
                f'<div class="alert-banner">⚠ PREDICTIVE WARNING — Tomorrow\u2019s risk probability is '
                f'{lp.iloc[-1]["forecast_prob"]:.0%}. Leading indicators suggest elevated errors ahead.</div>',
                unsafe_allow_html=True)
        else:
            st.markdown('<div class="ok-banner">✓ ALL CLEAR — No confirmed alerts and predictive risk is low.</div>',
                unsafe_allow_html=True)
    else:
        st.markdown('<div class="ok-banner">✓ ALL CLEAR — No confirmed alerts.</div>', unsafe_allow_html=True)

    # ── HOW IT WORKS ──
    with st.expander("ℹ️  How does this dashboard work?", expanded=False):
        st.markdown("""
**REACTIVE ENGINE** (always active — needs only the base 7 columns):
- **Daily Trend Monitor:** Tracks total BPS each day against smoothed thresholds. Flags abnormal days.
- **Event Screener:** Two independent methods score each event for unusualness.
- **Triage Rule:** Only "Confirmed" when both the daily trend AND event screening agree.
- **Regime Shift Detector:** Finds the exact dates where the error pattern fundamentally changed.

**PREDICTIVE ENGINE** (unlocked when leading indicator columns are present):
- **Gradient-Boosted Classifier:** Trained on time-lagged leading indicators to predict whether tomorrow's error level will be elevated.
- **Features used:** Yesterday's STP rate, exception queue depth, recon breaks, staffing, deployment history, market volatility, and more.
- **Feature Importance:** Shows exactly which factors are driving the prediction — actionable for ops managers.
""")

    # ── TABS ──
    if predictive_mode and model is not None:
        tab_f, tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "🔮 Tomorrow\u2019s Forecast", "📈 Daily Trends", "🔬 Event Screening",
            "🗺 Regional View", "🔍 Root Cause", "📊 Data & Export"])
    else:
        tab_f = None
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📈 Daily Trends", "🔬 Event Screening",
            "🗺 Regional View", "🔍 Root Cause", "📊 Data & Export"])

    # ── FORECAST TAB ──
    if tab_f is not None:
        with tab_f:
            st.markdown('<p class="section-header">TOMORROW\u2019S FORECAST — PREDICTIVE RISK ENGINE</p>', unsafe_allow_html=True)
            st.markdown(
                '<div class="how-box"><b>What this shows:</b> The predictive model analyses today\u2019s '
                'leading indicators — STP rates, exception queues, staffing levels, recent deployments, '
                'market volatility — and estimates the probability that tomorrow will see elevated error activity. '
                'The feature importance chart shows exactly which factors are driving the risk.</div>',
                unsafe_allow_html=True)

            # ── Forecast cards per region ──
            st.markdown("#### Regional Risk Forecast")
            # Build per-region last-day forecasts
            region_forecasts = {}
            for region in region_filter:
                rdf = raw_df[raw_df["Reporting Region"] == region].copy()
                if len(rdf) < 50: continue
                r_daily = run_trend_monitor(rdf, span=trend_window, sensitivity=alert_sensitivity)
                _, _, r_feat, _, _ = build_predictive_model(rdf, r_daily)
                if r_feat is not None and "forecast_prob" in r_feat.columns:
                    lp = r_feat.dropna(subset=["forecast_prob"])
                    if len(lp) > 0:
                        region_forecasts[region] = lp.iloc[-1]["forecast_prob"]

            if region_forecasts:
                rcols = st.columns(len(region_forecasts))
                for i, (region, prob) in enumerate(region_forecasts.items()):
                    css_class = "forecast-high" if prob > 0.7 else "forecast-med" if prob > 0.4 else "forecast-low"
                    color = "#ff0066" if prob > 0.7 else "#ff9f1c" if prob > 0.4 else "#00d4aa"
                    label = "HIGH RISK" if prob > 0.7 else "ELEVATED" if prob > 0.4 else "LOW RISK"
                    with rcols[i]:
                        st.markdown(
                            f'<div class="forecast-card {css_class}">'
                            f'<div class="forecast-label">{region}</div>'
                            f'<div class="forecast-pct" style="color:{color}">{prob:.0%}</div>'
                            f'<div class="forecast-label">{label}</div></div>', unsafe_allow_html=True)
            else:
                # Fallback: global forecast
                lp = feat_df.dropna(subset=["forecast_prob"])
                if len(lp) > 0:
                    prob = lp.iloc[-1]["forecast_prob"]
                    css = "forecast-high" if prob > 0.7 else "forecast-med" if prob > 0.4 else "forecast-low"
                    clr = "#ff0066" if prob > 0.7 else "#ff9f1c" if prob > 0.4 else "#00d4aa"
                    lbl = "HIGH RISK" if prob > 0.7 else "ELEVATED" if prob > 0.4 else "LOW RISK"
                    st.markdown(
                        f'<div class="forecast-card {css}" style="max-width:400px;margin:0 auto">'
                        f'<div class="forecast-label">GLOBAL FORECAST</div>'
                        f'<div class="forecast-pct" style="color:{clr}">{prob:.0%}</div>'
                        f'<div class="forecast-label">{lbl}</div></div>', unsafe_allow_html=True)

            st.markdown("---")

            # ── Forecast probability timeline ──
            if feat_df is not None:
                st.plotly_chart(chart_forecast_timeline(feat_df), use_container_width=True, key="fcast_tl")

            # ── Feature importance ──
            col_imp, col_met = st.columns([2, 1])
            with col_imp:
                if importance is not None and len(importance) > 0:
                    st.plotly_chart(chart_feature_importance(importance), use_container_width=True, key="fimp")
            with col_met:
                st.markdown("#### Model Performance")
                if model_metrics:
                    for k, v in model_metrics.items():
                        if v is not None:
                            nice = {"AUC": "Prediction Accuracy (AUC)", "Precision": "Alert Precision",
                                    "Recall": "Alert Recall (Coverage)", "Val Size": "Validation Days",
                                    "Positive Rate": "Elevated-Day Frequency"}.get(k, k)
                            st.metric(nice, f"{v:.1%}" if isinstance(v, float) and v <= 1 else str(v))
                else:
                    st.info("Insufficient data for model validation metrics.")

                st.markdown("#### How to read this")
                st.markdown(
                    "**Feature importance** shows which indicators have the most influence on tomorrow\u2019s "
                    "risk prediction. Red bars = strongest drivers. If \u201COpen Exception Queue Size\u201D "
                    "is top, that\u2019s the lever to pull today to prevent tomorrow\u2019s errors.")

            # ── Leading indicator trends ──
            if feat_df is not None:
                with st.expander("📊 Leading indicator trends over time", expanded=False):
                    li_fig = chart_leading_indicators(feat_df)
                    if li_fig:
                        st.plotly_chart(li_fig, use_container_width=True, key="li_trends")
                    else:
                        st.info("No leading indicator time series available.")

    # ── TAB 1: DAILY TRENDS ──
    with tab1:
        st.markdown('<div class="how-box"><b>Reading this chart:</b> White = actual daily cost. Green = smoothed trend. '
            'Red dashed = warning threshold. Red diamonds = abnormal days. Orange lines = regime shifts.</div>',
            unsafe_allow_html=True)
        st.plotly_chart(chart_daily_trend(daily_df, cpdates), use_container_width=True, key="trend")
        col_a, col_b = st.columns(2)
        with col_a:
            with st.expander("📊 Daily breakdown", expanded=False):
                d = daily_df[["date","total_bps","trend","upper_limit","flagged_day"]].copy()
                d.columns = ["Date","Total BPS","Trend","Threshold","Flagged?"]
                d["Flagged?"] = d["Flagged?"].map({1:"⚠ Yes",0:"No"})
                for c in ["Total BPS","Trend","Threshold"]: d[c] = d[c].round(1)
                st.dataframe(d.sort_values("Date", ascending=False).head(60), use_container_width=True, height=350)
        with col_b:
            with st.expander("📅 Regime shifts", expanded=True):
                if cpdates:
                    for i, cpd in enumerate(cpdates):
                        nr = daily_df.iloc[(daily_df["date"]-cpd).abs().argsort()[:1]]
                        st.markdown(f"**Shift #{i+1}:** `{cpd.strftime('%Y-%m-%d')}` — {nr['total_bps'].values[0]:.0f} bps")
                else: st.info("No structural shifts detected.")

    # ── TAB 2: EVENT SCREENING ──
    with tab2:
        st.markdown('<div class="how-box"><b>Each dot = one event.</b> Top-right = most unusual. '
            'Red = confirmed alerts. Right chart shows clustering.</div>', unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        with c1:
            fig_s = go.Figure()
            nm = df["confirmed_alert"] == 0
            fig_s.add_trace(go.Scattergl(x=ps[nm], y=iscore[nm], mode="markers", name="Normal",
                marker=dict(color=C["accent"], size=3, opacity=0.2)))
            am = df["confirmed_alert"] == 1
            fig_s.add_trace(go.Scattergl(x=ps[am], y=iscore[am], mode="markers", name="Confirmed Alert",
                marker=dict(color=C["danger"], size=7, opacity=0.9, line=dict(width=1, color="#fff"))))
            fig_s.update_layout(**LY, title="Event Unusualness Map", height=420,
                xaxis_title="Pattern Deviation", yaxis_title="Isolation Score")
            st.plotly_chart(styled(fig_s), use_container_width=True, key="esc")
        with c2:
            pca = PCA(n_components=2).fit_transform(Xs)
            labels = np.where(df["confirmed_alert"]==1, "Alert", np.where(unusual==1, "Unusual", "Normal"))
            fig_p = go.Figure()
            for lb, cl, sz, op in [("Normal",C["accent"],3,.15),("Unusual",C["warning"],5,.5),("Alert",C["danger"],8,.9)]:
                m = labels == lb
                fig_p.add_trace(go.Scattergl(x=pca[m,0], y=pca[m,1], mode="markers", name=lb,
                    marker=dict(color=cl, size=sz, opacity=op)))
            fig_p.update_layout(**LY, title="Event Clustering", height=420, xaxis_title="Dim 1", yaxis_title="Dim 2")
            st.plotly_chart(styled(fig_p), use_container_width=True, key="pca")

    # ── TAB 3: REGIONAL ──
    with tab3:
        st.plotly_chart(chart_heatmap(df), use_container_width=True, key="hm")
        st.plotly_chart(chart_manual_trend(df), use_container_width=True, key="mt")
        st.markdown('<p class="section-header">REGIONAL SUMMARY</p>', unsafe_allow_html=True)
        ar = [r for r in region_filter if r in df["Reporting Region"].unique()]
        if ar:
            rc = st.columns(len(ar))
            for i, r in enumerate(ar):
                rd = df[df["Reporting Region"]==r]; ra = rd["confirmed_alert"].sum()
                with rc[i]:
                    st.markdown(f"**{r}**"); st.metric("Events", len(rd))
                    st.metric("Alerts", int(ra), delta="⚠" if ra > 0 else "✓", delta_color="inverse" if ra > 0 else "normal")
                    st.metric("Avg BPS", f"{rd['Actual Bps Impact'].mean():.1f}")
                    st.metric("Manual%", f"{(rd['Automated or Manual Process']=='Manual').mean():.0%}")

    # ── TAB 4: ROOT CAUSE ──
    with tab4:
        st.markdown('<p class="section-header">WHY WERE THESE FLAGGED?</p>', unsafe_allow_html=True)
        if n_alerts > 0:
            findings = explain_root_cause(confirmed, df)
            st.markdown('<div class="insight-card">', unsafe_allow_html=True)
            st.markdown("#### 🔍 Key Findings")
            for f in findings: st.markdown(f"- {f}")
            st.markdown('</div>', unsafe_allow_html=True)

            st.markdown("#### Impact Comparison")
            a_s = df[df["confirmed_alert"]==1]["Actual Bps Impact"].describe()
            n_s = df[df["confirmed_alert"]==0]["Actual Bps Impact"].describe()
            comp = pd.DataFrame({
                "Metric": ["Average (bps)", "Std Dev", "Worst Event (bps)", "Median (bps)"],
                "Flagged": [a_s["mean"], a_s["std"], a_s["max"], a_s["50%"]],
                "Normal": [n_s["mean"], n_s["std"], n_s["max"], n_s["50%"]],
            })
            comp["Ratio"] = (comp["Flagged"] / comp["Normal"].replace(0,1)).round(2)
            st.dataframe(comp.style.format({"Flagged":"{:.1f}","Normal":"{:.1f}","Ratio":"{:.1f}×"}), use_container_width=True)
        else:
            st.markdown('<div class="ok-banner">No confirmed alerts to investigate.</div>', unsafe_allow_html=True)

    # ── TAB 5: DATA & EXPORT ──
    with tab5:
        st.markdown('<p class="section-header">EVENT LOG & EXPORT</p>', unsafe_allow_html=True)
        st.markdown('<div class="how-box"><b>Templates:</b> Download either the blank template or the full sample dataset. '
            'The base 7 columns run the reactive engine. Add the 11 leading indicator columns to unlock predictive mode.</div>',
            unsafe_allow_html=True)

        d1, d2, d3 = st.columns(3)
        with d1:
            st.download_button("📥 Blank template", data=generate_template_csv(),
                file_name="oprisk_template.csv", mime="text/csv")
        with d2:
            st.download_button("📥 Sample data (all columns)",
                data=raw_df.to_csv(index=False), file_name="oprisk_sample_full.csv", mime="text/csv")
        with d3:
            st.download_button("📥 Sample data (base only)",
                data=raw_df[BASE_COLS].to_csv(index=False), file_name="oprisk_sample_base.csv", mime="text/csv",
                help="Download with only the 7 base columns — will run in reactive mode.")

        st.markdown("---")
        show_only = st.toggle("Show only confirmed alerts", value=False)
        disp = confirmed if show_only else df
        dcols = BASE_COLS + ["Priority"]
        st.dataframe(disp[dcols].sort_values("Occurred Date", ascending=False),
            use_container_width=True, height=500,
            column_config={
                "Occurred Date": st.column_config.DateColumn("Date", format="YYYY-MM-DD"),
                "Actual Bps Impact": st.column_config.NumberColumn("BPS Impact", format="%.2f")})
        st.download_button("📥 Analysed dataset", data=df[dcols].to_csv(index=False),
            file_name="oprisk_analysed.csv", mime="text/csv")

    st.markdown("---")
    mode_label = "Reactive + Predictive" if predictive_mode else "Reactive Only"
    st.caption(f"Pipeline v4.0 — {mode_label} | Trend Monitor → Event Screening → Triage → "
        f"Regime Detection → {'XGBoost Forecast → Feature Importance → ' if predictive_mode else ''}Root Cause")


if __name__ == "__main__":
    main()
