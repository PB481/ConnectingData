"""
FA Deal Pricing Engine — Streamlit Application
===============================================
Automated fund administration deal pricing with scenario testing,
cost-to-serve modelling, lifecycle schematics, and deal summaries.

Run: streamlit run deal_pricing_app.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
import warnings
warnings.filterwarnings("ignore")

st.set_page_config(page_title="FA Deal Pricing Engine", page_icon="⚡", layout="wide", initial_sidebar_state="expanded")

# ═══════════════════════════════════════════════════════════════
# STYLING
# ═══════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;500;600;700&family=Fira+Code:wght@300;400;500&display=swap');
.stApp { background-color: #04080d; }
section[data-testid="stSidebar"] { background-color: #0b1018; border-right:1px solid #1e3048; }
h1,h2,h3 { font-family:'Instrument Sans',sans-serif !important; }

.hero { background:linear-gradient(135deg,#0b1018,#111a28); border:1px solid #1e3048;
  border-radius:12px; padding:28px 32px; margin-bottom:24px; }
.hero h1 { font-size:26px; font-weight:700; margin:0;
  background:linear-gradient(135deg,#eef2f9,#1ac7c7); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }
.hero p { color:#7a8faa; font-size:13px; margin:6px 0 0; }

.kpi-card { background:#111a28; border:1px solid #1e3048; border-radius:9px; padding:16px 18px;
  position:relative; overflow:hidden; }
.kpi-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; }
.kpi-card.blue::before { background:#2d8cf0; }
.kpi-card.green::before { background:#0fc882; }
.kpi-card.amber::before { background:#e8a317; }
.kpi-card.teal::before { background:#1ac7c7; }
.kpi-label { font-size:10px; color:#4e6380; text-transform:uppercase; letter-spacing:.7px; font-weight:500; }
.kpi-value { font-family:'Fira Code',monospace; font-size:22px; font-weight:500; margin:6px 0 2px; }
.kpi-sub { font-size:10px; color:#4e6380; font-family:'Fira Code',monospace; }

.scenario-box { background:#0b1018; border:1px solid #1e3048; border-radius:10px;
  padding:22px; text-align:center; }
.scenario-box.rec { border-color:#0fc882; }
.sc-name { font-size:10px; text-transform:uppercase; letter-spacing:.8px; color:#4e6380; margin-bottom:6px; }
.sc-fee { font-family:'Fira Code',monospace; font-size:28px; font-weight:600; }
.sc-unit { font-size:11px; color:#7a8faa; }
.sc-metric { font-size:11px; color:#7a8faa; margin-top:4px; }
.good { color:#0fc882; } .ok { color:#e8a317; } .bad { color:#f0463c; }

.lc-container { display:flex; gap:0; overflow-x:auto; padding:12px 0; }
.lc-step { flex:1; min-width:100px; text-align:center; position:relative; }
.lc-icon { font-size:24px; margin-bottom:6px; }
.lc-name { font-size:10px; font-weight:600; color:#b8c6dc; }
.lc-tz { font-size:9px; color:#4e6380; font-family:'Fira Code',monospace; }
.lc-step:not(:last-child)::after { content:'→'; position:absolute; right:-8px; top:8px; color:#1e3048; font-size:16px; }

.summary-row { display:flex; justify-content:space-between; padding:10px 14px; background:#0b1018;
  border-radius:7px; margin-bottom:6px; }
.summary-label { font-size:11px; color:#7a8faa; }
.summary-val { font-family:'Fira Code',monospace; font-size:12px; font-weight:500; }

.section-hdr { display:flex; align-items:center; gap:10px; margin:24px 0 14px; padding-bottom:8px;
  border-bottom:1px solid #1e3048; }
.sec-num { font-family:'Fira Code',monospace; font-size:10px; padding:3px 8px; border-radius:4px; }
.num-b { background:rgba(45,140,240,.1); color:#2d8cf0; }
.num-g { background:rgba(15,200,130,.08); color:#0fc882; }
.num-a { background:rgba(232,163,23,.08); color:#e8a317; }
.num-t { background:rgba(26,199,199,.08); color:#1ac7c7; }
.sec-title { font-size:15px; font-weight:600; color:#eef2f9; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════
# COST MODEL
# ═══════════════════════════════════════════════════════════════
COST_MODEL = {
    "base_cost": {"ucits": 85000, "aif": 110000, "etf": 95000},
    "complexity_mult": {"Standard": 1.0, "Moderate": 1.35, "Complex": 1.8, "Highly Complex": 2.5},
    "domicile_mult": {"Ireland": 1.0, "Luxembourg": 1.12, "Cayman": 0.9},
    "nav_freq_mult": {"Daily": 1.0, "Weekly": 0.55, "Monthly": 0.35},
    "strategy_mult": {"Equity": 1.0, "Fixed Income": 1.15, "Multi-Asset": 1.25, "Alternatives / Credit": 1.6, "Real Assets": 1.8, "Money Market": 0.75},
    "share_class_cost": 4500,
    "sub_fund_cost": 40000,
    "txn_cost_per": 1.2,
    "comp_adj": {"Sole Bid": 1.15, "Competitive (2-3 bidders)": 1.0, "Highly Competitive (4+)": 0.88, "Incumbent Defense": 0.92},
}

SERVICES = {
    "Transfer Agency": {"cost": 35000, "lc_step": "Investor Servicing", "lc_icon": "👥", "lc_tz": "GMT/EST"},
    "Custody (Internal)": {"cost": 25000, "lc_step": "Custody & Settlement", "lc_icon": "🔒", "lc_tz": "GMT"},
    "FX Execution": {"cost": 12000, "lc_step": "FX Management", "lc_icon": "💱", "lc_tz": "GMT/EST/APAC"},
    "CBI Regulatory Reporting": {"cost": 28000, "lc_step": "Regulatory Filing", "lc_icon": "📋", "lc_tz": "GMT"},
    "Performance & Attribution": {"cost": 22000, "lc_step": "Performance Calc", "lc_icon": "📊", "lc_tz": "GMT"},
    "Investor Reporting": {"cost": 18000, "lc_step": "Client Reports", "lc_icon": "📄", "lc_tz": "GMT"},
    "Tax Services": {"cost": 32000, "lc_step": "Tax Processing", "lc_icon": "🏛", "lc_tz": "GMT"},
}


def fmt_k(val):
    if abs(val) >= 1_000_000: return f"${val/1_000_000:.1f}M"
    if abs(val) >= 1_000: return f"${val/1_000:.0f}K"
    return f"${val:.0f}"


def compute_costs(fund_type, complexity, domicile, nav_freq, strategy, share_classes, sub_funds, txn_volume, selected_services):
    base = COST_MODEL["base_cost"].get(fund_type, 85000)
    c_mult = COST_MODEL["complexity_mult"].get(complexity, 1.0)
    d_mult = COST_MODEL["domicile_mult"].get(domicile, 1.0)
    n_mult = COST_MODEL["nav_freq_mult"].get(nav_freq, 1.0)
    s_mult = COST_MODEL["strategy_mult"].get(strategy, 1.0)

    core = base * c_mult * d_mult * n_mult * s_mult
    core += (share_classes - 1) * COST_MODEL["share_class_cost"]
    core += (sub_funds - 1) * COST_MODEL["sub_fund_cost"]
    core += txn_volume * 12 * COST_MODEL["txn_cost_per"]

    svc_cost = 0
    svc_breakdown = []
    for svc_name in selected_services:
        svc = SERVICES[svc_name]
        adj = svc["cost"] * c_mult
        svc_cost += adj
        svc_breakdown.append({"name": svc_name, "cost": adj})

    return core, svc_cost, core + svc_cost, svc_breakdown


def generate_scenarios(total_cost, aum_m, target_margin_pct, competitive):
    aum_usd = aum_m * 1_000_000
    margin = target_margin_pct / 100
    target_rev = total_cost / (1 - margin) if margin < 1 else total_cost * 2
    target_fee = target_rev / aum_usd * 10000
    adj = COST_MODEL["comp_adj"].get(competitive, 1.0)

    scenarios = {}
    for name, mult in [("Aggressive", 0.82), ("Recommended", 1.0), ("Premium", 1.18)]:
        fee = round(target_fee * mult * adj, 1)
        rev = fee / 10000 * aum_usd
        mg = (rev - total_cost) / rev * 100 if rev > 0 else 0
        be = total_cost / (fee / 10000) / 1_000_000 if fee > 0 else 0
        scenarios[name] = {"fee": fee, "revenue": rev, "margin": mg, "breakeven": be}

    return scenarios


# ═══════════════════════════════════════════════════════════════
# SIDEBAR — DEAL INPUTS
# ═══════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("### ⚡ Deal Parameters")
    st.markdown("---")

    deal_name = st.text_input("Client / Deal Name", "Prospective Fund Co.")

    st.markdown("##### Fund Details")
    c1, c2 = st.columns(2)
    fund_type = c1.selectbox("Fund Type", ["ucits", "aif", "etf"], format_func=lambda x: x.upper())
    domicile = c2.selectbox("Domicile", ["Ireland", "Luxembourg", "Cayman"])
    c3, c4 = st.columns(2)
    strategy = c3.selectbox("Strategy", ["Equity", "Fixed Income", "Multi-Asset", "Alternatives / Credit", "Real Assets", "Money Market"])
    complexity = c4.selectbox("Complexity", ["Standard", "Moderate", "Complex", "Highly Complex"])

    st.markdown("##### Scale")
    aum = st.slider("Expected AUM ($M)", 100, 20000, 2000, 100)
    c5, c6 = st.columns(2)
    share_classes = c5.number_input("Share Classes", 1, 50, 5)
    sub_funds = c6.number_input("Sub-Funds", 1, 20, 1)
    c7, c8 = st.columns(2)
    nav_freq = c7.selectbox("NAV Frequency", ["Daily", "Weekly", "Monthly"])
    txn_volume = c8.number_input("Txns / Month", 0, 50000, 500)

    st.markdown("##### Services")
    default_services = ["Transfer Agency", "FX Execution", "CBI Regulatory Reporting", "Investor Reporting"]
    selected_services = st.multiselect("Included Services", list(SERVICES.keys()), default=default_services)

    st.markdown("##### Pricing")
    target_margin = st.slider("Target Margin (%)", 5, 50, 25)
    competitive = st.selectbox("Competitive Context", ["Sole Bid", "Competitive (2-3 bidders)", "Highly Competitive (4+)", "Incumbent Defense"], index=1)
    win_prob = st.number_input("Win Probability (%)", 1, 100, 40)

    calculate = st.button("⚡ Calculate Pricing", type="primary", use_container_width=True)


# ═══════════════════════════════════════════════════════════════
# MAIN — RESULTS
# ═══════════════════════════════════════════════════════════════
st.markdown(f"""
<div class="hero">
    <h1>Deal Pricing Engine</h1>
    <p>Automated cost-to-serve modelling, scenario testing, and deal structuring for Fund Administration</p>
</div>
""", unsafe_allow_html=True)

if calculate or st.session_state.get("calculated"):
    st.session_state.calculated = True

    core_cost, svc_cost, total_cost, svc_breakdown = compute_costs(
        fund_type, complexity, domicile, nav_freq, strategy, share_classes, sub_funds, txn_volume, selected_services
    )
    scenarios = generate_scenarios(total_cost, aum, target_margin, competitive)
    rec = scenarios["Recommended"]
    prob_weighted = rec["revenue"] * (win_prob / 100)

    # ─── KPIs ───
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f'<div class="kpi-card blue"><div class="kpi-label">Recommended Fee</div><div class="kpi-value" style="color:#2d8cf0">{rec["fee"]} bps</div><div class="kpi-sub">{competitive}</div></div>', unsafe_allow_html=True)
    with k2:
        st.markdown(f'<div class="kpi-card green"><div class="kpi-label">Annual Revenue</div><div class="kpi-value" style="color:#0fc882">{fmt_k(rec["revenue"])}</div><div class="kpi-sub">at ${aum:,}M AUM</div></div>', unsafe_allow_html=True)
    with k3:
        mc = "#0fc882" if rec["margin"] >= 20 else "#e8a317" if rec["margin"] >= 10 else "#f0463c"
        st.markdown(f'<div class="kpi-card amber"><div class="kpi-label">Margin</div><div class="kpi-value" style="color:{mc}">{rec["margin"]:.1f}%</div><div class="kpi-sub">target: {target_margin}%</div></div>', unsafe_allow_html=True)
    with k4:
        st.markdown(f'<div class="kpi-card teal"><div class="kpi-label">Prob-Weighted Rev</div><div class="kpi-value" style="color:#1ac7c7">{fmt_k(prob_weighted)}</div><div class="kpi-sub">{win_prob}% win probability</div></div>', unsafe_allow_html=True)

    # ─── Section 1: Scenarios ───
    st.markdown('<div class="section-hdr"><span class="sec-num num-b">01</span><span class="sec-title">Pricing Scenarios</span></div>', unsafe_allow_html=True)

    sc1, sc2, sc3 = st.columns(3)
    for col, (name, data) in zip([sc1, sc2, sc3], scenarios.items()):
        is_rec = name == "Recommended"
        mc = "good" if data["margin"] >= 20 else "ok" if data["margin"] >= 10 else "bad"
        with col:
            st.markdown(f"""
            <div class="scenario-box {'rec' if is_rec else ''}">
                <div class="sc-name">{'★ ' if is_rec else ''}{name}</div>
                <div class="sc-fee">{data['fee']}</div>
                <div class="sc-unit">basis points</div>
                <div class="sc-metric">Revenue: <strong>{fmt_k(data['revenue'])}/yr</strong></div>
                <div class="sc-metric">Margin: <span class="{mc}">{data['margin']:.1f}%</span></div>
                <div class="sc-metric">Break-even: ${data['breakeven']:,.0f}M</div>
            </div>""", unsafe_allow_html=True)

    # ─── Section 2: Cost Breakdown ───
    st.markdown('<div class="section-hdr"><span class="sec-num num-g">02</span><span class="sec-title">Cost-to-Serve Breakdown</span></div>', unsafe_allow_html=True)

    cc1, cc2 = st.columns(2)
    with cc1:
        labels = ["Core FA"] + [s["name"] for s in svc_breakdown]
        values = [core_cost] + [s["cost"] for s in svc_breakdown]
        colors = ["#2d8cf0", "#1ac7c7", "#0fc882", "#e8a317", "#8a63f2", "#f0463c", "#2d8cf080", "#7a8faa"]
        fig = px.pie(names=labels, values=values, hole=0.55, color_discrete_sequence=colors[:len(labels)])
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          font=dict(family="Instrument Sans", size=11, color="#7a8faa"),
                          legend=dict(font=dict(size=10)), margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig, use_container_width=True)

    with cc2:
        fig = go.Figure(go.Bar(y=labels, x=values, orientation="h",
                               marker_color=colors[:len(labels)],
                               text=[fmt_k(v) for v in values], textposition="auto"))
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          font=dict(family="Instrument Sans", size=11, color="#7a8faa"),
                          xaxis=dict(gridcolor="rgba(30,48,72,0.3)"), yaxis=dict(gridcolor="rgba(30,48,72,0.3)"),
                          showlegend=False, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig, use_container_width=True)

    # ─── Section 3: Sensitivity Matrix ───
    st.markdown('<div class="section-hdr"><span class="sec-num num-a">03</span><span class="sec-title">Margin Sensitivity (Fee × AUM)</span></div>', unsafe_allow_html=True)

    fee_levels = [1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0]
    aum_levels = [int(aum * m) for m in [0.5, 0.75, 1.0, 1.5, 2.0]]

    sens_data = []
    for a in aum_levels:
        row = {"AUM ($M)": f"${a:,}"}
        for f in fee_levels:
            rev = f / 10000 * a * 1_000_000
            margin = (rev - total_cost) / rev * 100 if rev > 0 else -100
            row[f"{f} bps"] = f"{margin:.0f}%"
        sens_data.append(row)

    sens_df = pd.DataFrame(sens_data)
    st.dataframe(sens_df, use_container_width=True, hide_index=True)

    st.caption("Green ≥20% | Amber 10-20% | Red <10% — ★ marks recommended fee column")

    # ─── Section 4: Lifecycle ───
    st.markdown('<div class="section-hdr"><span class="sec-num num-t">04</span><span class="sec-title">Operational Lifecycle Schematic</span></div>', unsafe_allow_html=True)

    lc_steps = [
        {"name": "Trade Capture", "icon": "📥", "tz": "GMT/EST", "detail": "T+0 matching"},
        {"name": "Pricing & Valuation", "icon": "💰", "tz": "GMT 16:00", "detail": f"{nav_freq} NAV"},
        {"name": "NAV Calculation", "icon": "🧮", "tz": "GMT 18:00", "detail": f"{share_classes} classes"},
    ]
    for svc_name in selected_services:
        svc = SERVICES[svc_name]
        lc_steps.append({"name": svc["lc_step"], "icon": svc["lc_icon"], "tz": svc["lc_tz"], "detail": ""})
    lc_steps.append({"name": "Sign-Off & Release", "icon": "✅", "tz": "GMT 20:00", "detail": "Senior review"})

    lc_html = '<div class="lc-container">'
    for step in lc_steps:
        lc_html += f"""<div class="lc-step">
            <div class="lc-icon">{step['icon']}</div>
            <div class="lc-name">{step['name']}</div>
            <div class="lc-tz">{step['tz']}</div>
        </div>"""
    lc_html += '</div>'
    st.markdown(lc_html, unsafe_allow_html=True)

    # ─── Section 5: Deal Summary ───
    st.markdown('<div class="section-hdr"><span class="sec-num num-b">05</span><span class="sec-title">Deal Summary</span></div>', unsafe_allow_html=True)

    summary_items = [
        ("Client", deal_name), ("Fund Type", fund_type.upper()), ("Domicile", domicile),
        ("Strategy", strategy), ("AUM", f"${aum:,}M"), ("Share Classes", str(share_classes)),
        ("Sub-Funds", str(sub_funds)), ("NAV Frequency", nav_freq),
        ("Monthly Txns", f"{txn_volume:,}"), ("Complexity", complexity),
        ("Cost-to-Serve", f"{fmt_k(total_cost)}/yr"), ("Recommended Fee", f"{rec['fee']} bps"),
        ("Projected Revenue", f"{fmt_k(rec['revenue'])}/yr"), ("Margin", f"{rec['margin']:.1f}%"),
        ("Break-Even AUM", f"${rec['breakeven']:,.0f}M"), ("Win Probability", f"{win_prob}%"),
        ("Prob-Weighted Rev", f"{fmt_k(prob_weighted)}/yr"),
        ("Services", f"{len(selected_services)} of {len(SERVICES)}"),
    ]

    s_html = ""
    for label, val in summary_items:
        s_html += f'<div class="summary-row"><span class="summary-label">{label}</span><span class="summary-val">{val}</span></div>'
    st.markdown(s_html, unsafe_allow_html=True)

    # ─── Export ───
    st.markdown("---")
    summary_df = pd.DataFrame(summary_items, columns=["Parameter", "Value"])
    csv_data = summary_df.to_csv(index=False).encode("utf-8")
    st.download_button("⬇ Export Deal Summary (CSV)", csv_data, f"deal_summary_{deal_name.replace(' ','_')}.csv", "text/csv", use_container_width=True)

else:
    st.info("👈 Configure deal parameters in the sidebar, then click **⚡ Calculate Pricing** to generate scenarios.")
    st.markdown("""
    ### How It Works
    
    This tool replaces manual pricing spreadsheets with an automated engine that:
    
    1. **Calculates cost-to-serve** from fund parameters (type, complexity, AUM, services)
    2. **Generates 3 pricing scenarios** adjusted for competitive context
    3. **Shows a margin sensitivity matrix** so reviewers can instantly see the impact of changing fee or AUM assumptions
    4. **Maps the operational lifecycle** showing how the fund will run day-to-day
    5. **Produces a deal summary** ready for senior review — no rework needed
    
    Every parameter is adjustable. Change anything, results update instantly. No ping-pong.
    """)

st.markdown("---")
st.caption(f"FA Deal Pricing Engine v1.0 · {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC")
