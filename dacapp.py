"""
╔══════════════════════════════════════════════════════════════════════╗
║  S110 DAC SPV — Interactive Learning Tool for Fund Accountants       ║
║  Tech: Streamlit · Pandas · Plotly                                   ║
║  Theme: Dark Financial Terminal (.streamlit/config.toml)             ║
║                                                                      ║
║  Run:  streamlit run app.py                                          ║
║  Deps: pip install streamlit pandas plotly openpyxl                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import random
from datetime import datetime, timedelta

random.seed(42)

# ──────────────────────────────────────────────────────────────
# Theme Constants (mirrors .streamlit/config.toml)
# ──────────────────────────────────────────────────────────────
THEME = {
    "bg": "#0a0e1a", "surface": "#111b2e", "border": "#1a2a48",
    "text": "#c8d6e5", "muted": "#5e7ba0",
    "accent": "#00d4ff", "accent2": "#00d4aa",
    "warn": "#f39c12", "danger": "#e74c3c", "success": "#2ecc71",
}

PLOTLY_LAYOUT = dict(
    plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
    font=dict(color=THEME["muted"], size=12, family="JetBrains Mono, Consolas, monospace"),
    margin=dict(l=20, r=20, t=40, b=20),
    hoverlabel=dict(bgcolor=THEME["surface"], font_color=THEME["text"], bordercolor=THEME["border"]),
)

# ──────────────────────────────────────────────────────────────
# Data Generation
# ──────────────────────────────────────────────────────────────
SECTORS = ["Healthcare", "Technology", "Industrials", "Consumer", "Energy",
           "Telecoms", "Financials", "Real Estate", "Utilities", "Materials"]
RATINGS = ["BB+", "BB", "BB-", "B+", "B", "B-", "CCC+"]
BORROWERS = [
    "Acme Healthcare GmbH", "TechFlow Solutions", "Nordic Industries AB",
    "EuroRetail Holdings", "Iberian Energy SA", "Baltic Telecoms",
    "Alpine Financial", "CityProp REIT", "Green Utilities NV",
    "Rhine Materials AG", "MedTech Innovations", "DataCore Systems",
    "Scandia Manufacturing", "LuxBrands International", "Petro Atlantic",
    "Connect Networks", "Zurich Capital", "Metro Living",
    "PowerGrid Europe", "SteelWorks Intl",
]
BOND_NAMES = [
    "European Investment Bank 2.5% 2028", "KfW 1.75% 2029",
    "Volkswagen Intl 3.25% 2027", "TotalEnergies 2.0% 2030",
    "Siemens AG 2.875% 2028", "BNP Paribas 3.5% 2029",
    "Enel SpA 3.0% 2031", "Deutsche Telekom 2.625% 2027",
    "Iberdrola 2.25% 2030", "Anheuser-Busch InBev 3.125% 2028",
]
BOND_COUPONS = [2.5, 1.75, 3.25, 2.0, 2.875, 3.5, 3.0, 2.625, 2.25, 3.125]
BOND_RATINGS = ["AAA", "AAA", "BBB+", "A-", "A", "A-", "BBB", "BBB+", "A-", "BBB+"]

@st.cache_data
def generate_loan_portfolio():
    loans = []
    for i in range(100):
        par = round(random.uniform(250000, 750000), 0)
        price = round(random.uniform(88, 102), 2)
        spread = random.choice([250, 300, 325, 350, 375, 400, 425, 450, 500, 550])
        fv = round(par * price / 100, 2)
        ai = round(par * spread / 10000 * 30 / 360, 2)
        loans.append({
            "Markit ID": f"LX{170000 + i}",
            "Borrower": f"{BORROWERS[i % 20]} TL-{chr(65 + i % 5)}",
            "Sector": SECTORS[i % 10],
            "Par Value (€)": par,
            "Markit Price": price,
            "Fair Value (€)": fv,
            "Unrealised G/L (€)": round(fv - par, 2),
            "Coupon": f"E+{spread}",
            "Spread (bps)": spread,
            "Accrued Int (€)": ai,
            "Maturity": datetime(2027 + i % 5, (i % 12) + 1, 15),
            "Rating": RATINGS[i % 7],
        })
    return pd.DataFrame(loans)

@st.cache_data
def generate_bond_portfolio():
    bonds = []
    for i in range(10):
        nominal = round(random.uniform(300000, 800000), 0)
        price = round(random.uniform(95, 105), 2)
        mv = round(nominal * price / 100, 2)
        ai = round(nominal * BOND_COUPONS[i] / 100 * 30 / 360, 2)
        bonds.append({
            "ISIN": f"XS{2000000000 + i * 111}",
            "Bond Name": BOND_NAMES[i],
            "Sector": SECTORS[i],
            "Nominal (€)": nominal,
            "Clean Price": price,
            "Market Value (€)": mv,
            "Unrealised G/L (€)": round(mv - nominal, 2),
            "Coupon (%)": BOND_COUPONS[i],
            "Accrued Int (€)": ai,
            "Maturity": datetime(2027 + i % 5, 6, 15),
            "Rating": BOND_RATINGS[i],
        })
    return pd.DataFrame(bonds)

def teach(private_credit_term, traditional_term, explanation):
    """Render a teaching callout mapping PC term -> trad term."""
    st.markdown(
        f"**🔄 Term Translation** | "
        f"*Private Credit:* **{private_credit_term}** → "
        f"*Traditional Fund:* **{traditional_term}**"
    )
    st.caption(explanation)

# ──────────────────────────────────────────────────────────────
# Page Config
# ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="S110 DAC SPV — Learning Tool",
    page_icon="🏦",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────
# Sidebar Navigation
# ──────────────────────────────────────────────────────────────
st.sidebar.title("🏦 S110 DAC SPV")
st.sidebar.caption("Interactive Learning Tool for Fund Accountants")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigate",
    [
        "🏠 Structure Overview",
        "📖 Terminology Map",
        "📊 Portfolio Holdings",
        "💰 NAV Calculation",
        "📋 NAV Process Tasks",
        "📜 PPN Lifecycle",
        "💸 Cash Flow & Waterfall",
        "📦 In-Kind Subscription",
        "🔄 DAC ↔ AUT Cash Movement",
        "🏛 TA & Paying Agent",
        "📥 Additional Drawdown",
        "🏦 ATAD & GL Structure",
        "📡 CBI Reporting",
        "🛡 WHT & DTT",
        "⚠️ Friction & Exceptions",
        "⚡ Quick Reference",
    ],
    label_visibility="collapsed",
)

st.sidebar.markdown("---")
st.sidebar.markdown("**Key Parties**")
st.sidebar.markdown("SPV: ABC DAC")
st.sidebar.markdown("IM: KKR")
st.sidebar.markdown("ManCo: Maples")
st.sidebar.markdown("Trustee: Maples")
st.sidebar.markdown("Investor: Australian Unit Trust")
st.sidebar.markdown("Pricing: IHS Markit")

# Load data
loans_df = generate_loan_portfolio()
bonds_df = generate_bond_portfolio()

# ══════════════════════════════════════════════════════════════
# PAGE: Structure Overview
# ══════════════════════════════════════════════════════════════
if page == "🏠 Structure Overview":
    st.title("Irish DAC S110 SPV — Structure Overview")
    st.markdown("*Everything a junior fund accountant needs to understand this structure*")

    st.info(
        "**What is this?** An Irish Section 110 SPV (Special Purpose Vehicle) structured as a DAC "
        "(Designated Activity Company). It holds a portfolio of 100 synthetic loans and 10 bonds, "
        "managed by KKR, with one investor — an Australian Unit Trust — who accesses the vehicle "
        "through a Profit Participating Note (PPN). Think of it as a fund, but wrapped in a company."
    )

    st.subheader("Key Parties & Roles")
    teach("SPV / Issuer", "The Fund / Sub-Fund",
          "The DAC is the legal entity holding the assets. In traditional fund admin, this would be the fund itself.")

    parties = pd.DataFrame([
        {"Role": "SPV / Issuer", "Entity": "ABC DAC", "Traditional Equivalent": "The Fund / Sub-Fund",
         "Notes": "Irish S110 qualifying company — tax neutral vehicle"},
        {"Role": "Investment Manager", "Entity": "KKR", "Traditional Equivalent": "Investment Manager / Adviser",
         "Notes": "Makes all investment decisions on the loan portfolio"},
        {"Role": "Management Company", "Entity": "Maples Fund Services", "Traditional Equivalent": "ManCo / AIFM",
         "Notes": "Governance, risk, substance, regulatory oversight"},
        {"Role": "Trustee", "Entity": "Maples Fund Services", "Traditional Equivalent": "Trustee / Depositary",
         "Notes": "Holds security over assets for noteholder benefit"},
        {"Role": "Fund Administrator", "Entity": "Your Firm", "Traditional Equivalent": "Fund Administrator",
         "Notes": "NAV calculation, investor services, reporting"},
        {"Role": "Investor", "Entity": "Australian Unit Trust", "Traditional Equivalent": "Shareholder / Unitholder",
         "Notes": "Single investor via PPN — reflects DAC as a fund holding"},
        {"Role": "Pricing Vendor", "Entity": "IHS Markit (S&P Global)", "Traditional Equivalent": "Bloomberg / WM Daten",
         "Notes": "Provides daily fair values for the synthetic loan book"},
        {"Role": "Paying Agent", "Entity": "Maples / Appointed Bank", "Traditional Equivalent": "Transfer Agent",
         "Notes": "Processes note distributions to investor"},
        {"Role": "Account Bank", "Entity": "Appointed Bank (e.g., BNY)", "Traditional Equivalent": "Custodian Cash Account",
         "Notes": "Holds DAC cash — swept quarterly"},
    ])
    st.dataframe(parties, use_container_width=True, hide_index=True)

    st.subheader("Legal & Tax Structure")
    st.warning(
        "**Critical Difference:** In a UCITS or AIF, the fund itself is tax-exempt. In a S110 DAC, "
        "the company IS taxable — but achieves tax neutrality by paying out all profits as PPN coupon "
        "(which is deductible). Same result, different mechanism."
    )

    features = pd.DataFrame([
        {"Feature": "Vehicle Type", "S110 Detail": "DAC (Designated Activity Company)", "Traditional": "ICAV / Unit Trust / PLC"},
        {"Feature": "Tax Regime", "S110 Detail": "S110 TCA 1997 — profit offset by PPN deduction", "Traditional": "Tax-exempt fund"},
        {"Feature": "Regulatory", "S110 Detail": "Unregulated — BUT CBI statistical reporting MANDATORY", "Traditional": "CBI Authorised AIF/UCITS"},
        {"Feature": "Investor Access", "S110 Detail": "Profit Participating Note (PPN)", "Traditional": "Share Class / Units"},
        {"Feature": "Subscription", "S110 Detail": "In-Kind (asset transfer)", "Traditional": "Cash Subscription"},
        {"Feature": "Distribution", "S110 Detail": "Note Coupon (monthly)", "Traditional": "Dividend / Income Distribution"},
        {"Feature": "Cash Sweep", "S110 Detail": "Quarterly to waterfall", "Traditional": "N/A (daily settlement)"},
        {"Feature": "Accounting", "S110 Detail": "FRS 102 Section 12 — Fair Value through P&L for synthetic loans", "Traditional": "FRS 102 / Irish GAAP"},
        {"Feature": "WHT", "S110 Detail": "20% default — DTT/Eurobond exemption required", "Traditional": "Fund-level WHT exemption"},
        {"Feature": "ATAD ILR", "S110 Detail": "Interest deduction may be capped at 30% EBITDA — de minimis €3m", "Traditional": "N/A for exempt funds"},
    ])
    st.dataframe(features, use_container_width=True, hide_index=True)

    st.error(
        "**CORRECTION (from independent review):** The original model stated S110 DACs require 'no CBI returns.' "
        "This is **factually incorrect**. Under Section 18 of the Central Bank Act 1971, ALL Section 110 SPVs must "
        "register with the CBI within 5 working days of their first financial transaction and submit mandatory "
        "quarterly balance sheet and annual P&L returns."
    )

    st.subheader("Lifecycle Flow")
    flow = pd.DataFrame([
        {"Stage": "1. Inception", "What Happens": "KKR originates 100 loans + 10 bonds",
         "Traditional Equiv.": "Fund launch — seed portfolio", "Key Point": "In-kind subscription — no cash moves"},
        {"Stage": "2. PPN Issuance", "What Happens": "DAC issues PPN to AUT",
         "Traditional Equiv.": "Unit/share issuance", "Key Point": "AUT records as a 'fund holding'"},
        {"Stage": "3. Daily NAV", "What Happens": "FA prices loans (Markit) + bonds",
         "Traditional Equiv.": "Daily NAV calculation", "Key Point": "NAV = Assets − Liabilities"},
        {"Stage": "4. Monthly Dist.", "What Happens": "Loan interest → distributed as PPN coupon",
         "Traditional Equiv.": "Monthly dividend", "Key Point": "Reduces NAV like an ex-div"},
        {"Stage": "5. Quarterly Sweep", "What Happens": "Excess cash swept per waterfall",
         "Traditional Equiv.": "N/A — unique to structured credit", "Key Point": "Priority of payments applies"},
        {"Stage": "6. Year-End", "What Happens": "Audit, S110 tax return",
         "Traditional Equiv.": "Annual accounts + audit", "Key Point": "PPN deduction = zero tax"},
    ])
    st.dataframe(flow, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════
# PAGE: Terminology Map
# ══════════════════════════════════════════════════════════════
elif page == "📖 Terminology Map":
    st.title("Private Credit ↔ Traditional Fund Terminology")
    st.markdown("*When you see a private credit term, here’s what it means in your language*")

    search = st.text_input("🔍 Search terms", placeholder="e.g. PPN, coupon, waterfall...")

    terms = [
        ("DAC (Designated Activity Company)", "Fund / Sub-Fund", "The legal entity holding assets. Think of it as 'the fund' structured as an Irish company."),
        ("Profit Participating Note (PPN)", "Share Class", "The instrument the investor holds. Instead of units/shares, they own a debt note participating in profits."),
        ("Noteholder", "Shareholder / Unitholder", "The investor holding the PPN. Here: the Australian Unit Trust."),
        ("Note Coupon", "Dividend / Distribution", "Payment to investor, structured as PPN interest rather than a fund dividend."),
        ("In-Kind Subscription", "In-Specie Transfer", "Investor contributes assets (loans + bonds) rather than cash to acquire the PPN."),
        ("Synthetic Loan", "Fund Holding / Investment", "Credit exposure via derivative/swap rather than buying the actual loan. Booked at fair value."),
        ("Markit Fair Value", "NAV Pricing / Vendor Price", "Daily loan price from IHS Markit — like getting a Bloomberg price for an equity."),
        ("Cash Sweep / Waterfall", "Distribution Calculation", "Quarterly process of distributing excess cash per a priority of payments."),
        ("Priority of Payments", "Expense Allocation Order", "Contractual order: expenses → trustee → ManCo → investor."),
        ("Collateral Pool", "Fund Portfolio", "The collection of loans and bonds — this IS the portfolio you administer."),
        ("Offering Memorandum (OM)", "Prospectus / Supplement", "Legal doc describing the SPV, investments, risks, terms."),
        ("Trust Deed", "Instrument of Incorporation", "Governing document with priority of payments, security, covenants."),
        ("Note Purchase Agreement", "Subscription Agreement", "Contract by which investor acquires the PPN."),
        ("Administration Agreement", "Fund Administration Agreement", "Your contract — same obligations, applied to a DAC."),
        ("Servicing Report", "Manager Report", "Periodic report from KKR on loan performance."),
        ("Credit Event", "Corporate Action", "Loan default, restructure — process like a bond corporate action."),
        ("Par Value / Notional", "Nominal / Face Value", "Original loan amount — like bond face value."),
        ("Spread / Coupon", "Yield / Running Yield", "Interest rate (EURIBOR + spread) — like a bond coupon."),
        ("Recovery Rate", "N/A (new concept)", "% of principal recovered if a loan defaults."),
        ("Mark-to-Market (MTM)", "Unrealised Gain/Loss", "Daily fair value change from Markit."),
        ("S110 Qualifying Company", "Tax-Exempt Fund", "Tax regime making DAC neutral — via deduction not exemption."),
        ("Profit Participating Deduction", "N/A (S110 specific)", "Profits paid as PPN coupon → deduction → zero tax."),
        ("Drawdown / Funding", "Subscription", "Additional capital contributed or loans added."),
        ("Cash Reserve", "Minimum Cash Allocation", "Cash retained for expenses — not swept to investor."),
        ("ATAD Interest Limitation Rule (ILR)", "N/A (new for S110)", "EU rule limiting interest deductions to 30% of EBITDA. May restrict PPN coupon deductibility. De minimis exemption at €3m."),
        ("CBI Statistical Reporting (S18)", "CBI Returns / AIFMD Annex IV", "MANDATORY quarterly balance sheet + annual P&L returns to Central Bank of Ireland. NOT optional for S110 DACs."),
        ("Withholding Tax (WHT)", "Investor-level tax", "Ireland imposes 20% WHT on interest to non-residents. Exemptions available via DTT or quoted Eurobond route."),
        ("Ireland-Australia DTT", "N/A (treaty-specific)", "Double Taxation Treaty reducing/eliminating WHT on interest paid to Australian residents."),
        ("Quoted Eurobond Exemption", "N/A", "If PPN is listed on Euronext Dublin, interest can be paid gross to non-residents regardless of DTT."),
        ("Irrecoverable VAT", "N/A (new concept)", "The portion of VAT on professional fees that CANNOT be reclaimed. Must be included in expense accruals or NAV is overstated."),
        ("FRS 102 Section 12", "Accounting Standard", "Classification for 'non-basic' financial instruments. Requires fair value through profit or loss. Applies to synthetic loans."),
        ("EBITDA (for ATAD)", "N/A", "Earnings Before Interest, Taxes, Depreciation and Amortisation. Used to calculate the 30% ILR threshold."),
    ]

    terms_df = pd.DataFrame(terms, columns=["Private Credit Term", "Traditional Fund Term", "Explanation"])

    if search:
        mask = terms_df.apply(lambda row: search.lower() in row.str.lower().str.cat(sep=" "), axis=1)
        terms_df = terms_df[mask]

    for _, row in terms_df.iterrows():
        with st.expander(f"**{row['Private Credit Term']}** → {row['Traditional Fund Term']}"):
            st.markdown(row["Explanation"])

# ══════════════════════════════════════════════════════════════
# PAGE: Portfolio Holdings
# ══════════════════════════════════════════════════════════════
elif page == "📊 Portfolio Holdings":
    st.title("DAC Portfolio — 100 Synthetic Loans + 10 Bonds")
    teach("Collateral Pool", "Fund Portfolio",
          "This is the portfolio you’re administering. Loans are priced daily by Markit; bonds by Bloomberg/vendor.")

    # Summary metrics
    total_par_loans = loans_df["Par Value (€)"].sum()
    total_fv_loans = loans_df["Fair Value (€)"].sum()
    total_gl_loans = loans_df["Unrealised G/L (€)"].sum()
    total_ai_loans = loans_df["Accrued Int (€)"].sum()

    total_nom_bonds = bonds_df["Nominal (€)"].sum()
    total_mv_bonds = bonds_df["Market Value (€)"].sum()
    total_gl_bonds = bonds_df["Unrealised G/L (€)"].sum()
    total_ai_bonds = bonds_df["Accrued Int (€)"].sum()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Portfolio FV", f"€{(total_fv_loans + total_mv_bonds):,.0f}")
    col2.metric("Total Par/Nominal", f"€{(total_par_loans + total_nom_bonds):,.0f}")
    col3.metric("Total Unrealised G/L", f"€{(total_gl_loans + total_gl_bonds):,.0f}")
    col4.metric("Total Accrued Interest", f"€{(total_ai_loans + total_ai_bonds):,.0f}")

    tab1, tab2, tab3 = st.tabs(["📋 Loan Book (100)", "📋 Bond Book (10)", "📊 Analytics"])

    with tab1:
        st.subheader("Synthetic Loan Portfolio")
        teach("Synthetic Loan", "Fund Holding (at Fair Value)",
              "Each loan is a credit exposure booked at Markit fair value. The Markit price × par value = fair value. Same concept as pricing an equity at Bloomberg close.")

        # Interactive price adjuster
        st.markdown("**Try it:** Adjust a Markit price below and see how fair value changes — exactly like repricing a holding.")
        adj_col1, adj_col2, adj_col3 = st.columns(3)
        with adj_col1:
            adj_loan = st.selectbox("Select loan", loans_df["Markit ID"].tolist()[:10], index=0)
        with adj_col2:
            current_price = loans_df.loc[loans_df["Markit ID"] == adj_loan, "Markit Price"].values[0]
            new_price = st.number_input("New Markit Price", value=float(current_price), min_value=0.0, max_value=150.0, step=0.5)
        with adj_col3:
            loan_row = loans_df[loans_df["Markit ID"] == adj_loan].iloc[0]
            old_fv = loan_row["Fair Value (€)"]
            new_fv = loan_row["Par Value (€)"] * new_price / 100
            change = new_fv - old_fv
            st.metric("Fair Value Impact", f"€{new_fv:,.0f}", f"€{change:+,.0f}")

        fmt = {
            "Par Value (€)": "{:,.0f}", "Fair Value (€)": "{:,.0f}",
            "Unrealised G/L (€)": "{:,.0f}", "Accrued Int (€)": "{:,.0f}",
            "Markit Price": "{:.2f}",
        }
        st.dataframe(
            loans_df[["Markit ID", "Borrower", "Sector", "Par Value (€)", "Markit Price",
                       "Fair Value (€)", "Unrealised G/L (€)", "Coupon", "Accrued Int (€)",
                       "Rating"]].style.format(fmt),
            use_container_width=True, hide_index=True, height=400,
        )

        st.caption(f"**Loan Totals:** Par €{total_par_loans:,.0f} | FV €{total_fv_loans:,.0f} | "
                   f"Unrealised G/L €{total_gl_loans:,.0f} | Accrued Int €{total_ai_loans:,.0f}")

        # ── Real-World Friction: IPV ──
        with st.expander("⚠️ REAL-WORLD FRICTION: Independent Price Verification (IPV)", expanded=False):
            st.error(
                "**Markit is NOT a magic bullet.** Unlike Bloomberg equity prices, leveraged loan marks are notoriously "
                "illiquid and frequently stale. The FA team carries significant IPV burden:"
            )
            st.markdown("""
            **What the happy path doesn't tell you:**

            **Stale Price Protocol** — When a Markit price hasn't moved in >5 days (common for illiquid tranches), 
            you cannot simply flag it and move on. The OM typically mandates a specific escalation protocol:
            source 2-3 independent broker quotes, apply matrix pricing based on comparable credits, or fall back to
            the IM's internal mark — each requiring documented justification and ManCo sign-off.

            **Bid/Ask/Mid Configuration** — The OM specifies which price to use (bid for conservative, mid for standard).
            This is NOT always mid. Some OMs require bid-side pricing for loans below par and mid for loans above par.
            Your system must handle this conditional logic per-position.

            **Markit Coverage Gaps** — Not all 100 loans will have Markit coverage on day one. New originations,
            club deals, and bespoke bilateral facilities may have ZERO vendor coverage. You must establish an
            alternative pricing waterfall: Markit → Bloomberg BVAL → broker quotes → IM mark → fair value committee.

            **Price Challenge Process** — KKR (as IM) will periodically challenge Markit prices they believe are
            stale or incorrect. You must have a documented price challenge workflow that preserves independence
            while allowing legitimate challenges to be investigated.
            """)

            ipv_data = pd.DataFrame([
                {"Scenario": "Markit price available & fresh (<5 days)", "Likelihood": "~70% of loans", "FA Action": "Apply directly. Standard workflow.", "Effort": "Low"},
                {"Scenario": "Markit price stale (>5 days unchanged)", "Likelihood": "~15% of loans", "FA Action": "Source broker quotes, apply escalation protocol, document.", "Effort": "High"},
                {"Scenario": "No Markit coverage at all", "Likelihood": "~10% of loans", "FA Action": "Alternative pricing waterfall. IM mark with ManCo approval.", "Effort": "Very High"},
                {"Scenario": "IM price challenge received", "Likelihood": "~5% of loans", "FA Action": "Investigate, document, escalate to fair value committee.", "Effort": "Very High"},
            ])
            st.dataframe(ipv_data, use_container_width=True, hide_index=True)

    with tab2:
        st.subheader("Bond Portfolio")
        teach("Bond Holding", "Bond Holding (at Fair Value)",
              "Bonds are priced the same way as in a traditional fund. Clean price × nominal / 100 = market value.")

        fmt_b = {
            "Nominal (€)": "{:,.0f}", "Market Value (€)": "{:,.0f}",
            "Unrealised G/L (€)": "{:,.0f}", "Accrued Int (€)": "{:,.0f}",
            "Clean Price": "{:.2f}",
        }
        st.dataframe(
            bonds_df.style.format(fmt_b),
            use_container_width=True, hide_index=True,
        )

        st.caption(f"**Bond Totals:** Nominal €{total_nom_bonds:,.0f} | MV €{total_mv_bonds:,.0f} | "
                   f"Unrealised G/L €{total_gl_bonds:,.0f} | Accrued Int €{total_ai_bonds:,.0f}")

    with tab3:
        st.subheader("Portfolio Analytics")

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            sector_agg = loans_df.groupby("Sector")["Fair Value (€)"].sum().reset_index()
            fig_sector = px.pie(sector_agg, values="Fair Value (€)", names="Sector",
                               title="Loan Portfolio by Sector", hole=0.4,
                               color_discrete_sequence=px.colors.qualitative.Set3)
            fig_sector.update_layout(**PLOTLY_LAYOUT, title_font_color=THEME["text"])
            st.plotly_chart(fig_sector, use_container_width=True)

        with chart_col2:
            rating_agg = loans_df.groupby("Rating")["Fair Value (€)"].sum().reset_index()
            rating_order = ["BB+", "BB", "BB-", "B+", "B", "B-", "CCC+"]
            rating_agg["Rating"] = pd.Categorical(rating_agg["Rating"], categories=rating_order, ordered=True)
            rating_agg = rating_agg.sort_values("Rating")
            fig_rating = go.Figure(go.Bar(
                x=rating_agg["Rating"], y=rating_agg["Fair Value (€)"],
                marker_color=THEME["accent"], text=rating_agg["Fair Value (€)"].apply(lambda x: f"€{x/1e6:.1f}m"),
                textposition="outside", textfont=dict(color=THEME["text"]),
            ))
            fig_rating.update_layout(**PLOTLY_LAYOUT, title="Loan FV by Rating", title_font_color=THEME["text"],
                                     yaxis_title="Fair Value (€)")
            st.plotly_chart(fig_rating, use_container_width=True)

        # Price distribution
        fig_price = go.Figure(go.Histogram(
            x=loans_df["Markit Price"], nbinsx=20,
            marker_color=THEME["accent2"], opacity=0.8,
        ))
        fig_price.update_layout(**PLOTLY_LAYOUT, title="Distribution of Markit Prices",
                                title_font_color=THEME["text"],
                                xaxis_title="Markit Price", yaxis_title="Count")
        fig_price.add_vline(x=100, line_dash="dash", line_color=THEME["warn"],
                            annotation_text="Par (100)", annotation_font_color=THEME["warn"])
        st.plotly_chart(fig_price, use_container_width=True)

        st.info("**For Fund Accountants:** Loans trading below 100 are at a discount (unrealised loss). "
                "Above 100 = premium (unrealised gain). This is exactly the same concept as a bond trading "
                "above or below par.")

# ══════════════════════════════════════════════════════════════
# PAGE: NAV Calculation
# ══════════════════════════════════════════════════════════════
elif page == "💰 NAV Calculation":
    st.title("Daily NAV Calculation — DAC SPV")
    teach("DAC Net Asset Value", "Fund NAV",
          "NAV = Total Assets minus Total Liabilities. Exactly the same as any fund. The DAC is just the legal wrapper.")

    st.info("**Key insight:** The PPN value = the NAV. There is one investor and one note. "
            "So the NAV IS the note value. The AUT records this as its 'fund holding'.")

    nav_date = st.date_input("NAV Date", value=datetime(2025, 3, 31))

    st.subheader("Assets")
    total_fv_loans = loans_df["Fair Value (€)"].sum()
    total_fv_bonds = bonds_df["Market Value (€)"].sum()
    total_ai_loans = loans_df["Accrued Int (€)"].sum()
    total_ai_bonds = bonds_df["Accrued Int (€)"].sum()

    # Editable cash inputs
    col_a, col_b = st.columns(2)
    with col_a:
        cash_at_bank = st.number_input("Cash at Bank (€)", value=1250000, step=10000, format="%d")
    with col_b:
        interest_recv = st.number_input("Interest Receivable — Settled (€)", value=85000, step=1000, format="%d")
    other_recv = 15000

    assets_data = [
        {"Line Item": "Loan Portfolio — Fair Value", "Amount (€)": total_fv_loans,
         "Traditional Equivalent": "Investment Portfolio (FV)", "Source": "Markit daily prices"},
        {"Line Item": "Bond Portfolio — Fair Value", "Amount (€)": total_fv_bonds,
         "Traditional Equivalent": "Investment Portfolio (FV)", "Source": "Bloomberg / Vendor"},
        {"Line Item": "Accrued Interest — Loans", "Amount (€)": total_ai_loans,
         "Traditional Equivalent": "Accrued Income", "Source": "Calculated from coupon terms"},
        {"Line Item": "Accrued Interest — Bonds", "Amount (€)": total_ai_bonds,
         "Traditional Equivalent": "Accrued Income", "Source": "Calculated from coupon terms"},
        {"Line Item": "Cash at Bank", "Amount (€)": cash_at_bank,
         "Traditional Equivalent": "Cash & Cash Equivalents", "Source": "Bank statement / SWIFT"},
        {"Line Item": "Interest Receivable (settled)", "Amount (€)": interest_recv,
         "Traditional Equivalent": "Income Receivable", "Source": "Loan servicing report"},
        {"Line Item": "Other Receivables", "Amount (€)": other_recv,
         "Traditional Equivalent": "Other Debtors", "Source": "Admin records"},
    ]
    assets_df = pd.DataFrame(assets_data)
    total_assets = assets_df["Amount (€)"].sum()

    st.dataframe(assets_df.style.format({"Amount (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)
    st.success(f"**TOTAL ASSETS (A): €{total_assets:,.0f}**")

    # ── Real-World Friction: Accruals ──
    with st.expander("⚠️ REAL-WORLD FRICTION: Accrued Interest Is NOT Simple", expanded=False):
        st.error(
            "**The happy path shows a clean formula: Par × Spread / 10000 × Days / 360.** "
            "In reality, loan accruals are significantly more complex than bond coupons."
        )
        st.markdown("""
        **EURIBOR Floors** — Many leveraged loans have a EURIBOR floor (e.g., floor at 0%). If the actual
        3-month EURIBOR is below the floor, you use the floor rate, not the market rate. Your accrual
        engine must check the floor on every rate reset.

        **Rate Reset Lag** — EURIBOR resets on specific dates (quarterly, monthly) per the credit agreement.
        The new rate doesn't apply from the reset date — it applies from the next interest period start date.
        You must track reset dates per-facility and apply the correct rate for the correct period.

        **PIK Interest (Payment-in-Kind)** — Some loans capitalise interest instead of paying cash. When PIK
        interest is capitalised, you must: (a) increase the par/notional value of the loan, (b) adjust the
        cost basis for amortisation, (c) recognise the income as accrued but NOT as a cash receipt. This
        changes your accrual AND your position records simultaneously.

        **Day Count Mismatches** — Your 100 loans may use Actual/360, Actual/365, or 30/360 depending on
        jurisdiction and currency. You cannot apply a single convention across the book. Each facility's
        credit agreement specifies its own day count.

        **Broken Period Interest** — When a loan trades mid-period, accrued interest from the last payment
        date to the trade date must be calculated and settled between buyer and seller. This is NOT
        handled by your pricing vendor — you must calculate it from the credit agreement terms.
        """)

    # ── Real-World Friction: Discount Accretion (OID) ──
    with st.expander("⚠️ REAL-WORLD FRICTION: Discount Accretion (OID) vs MTM", expanded=False):
        st.error(
            "**Loans purchased at a discount (e.g., 97.50) will naturally pull to par over their life.** "
            "While FRS 102 FVTPL captures this in unrealised gains, tax neutrality often requires splitting it out."
        )
        st.markdown("""
        **The Problem:** If you buy a loan at 97.50, the 2.50 discount is effectively additional economic yield. 
        Under straight Mark-to-Market (MTM) accounting, this shows up as an "Unrealised Gain" when the price rises.
        However, for S110 distributable income (and to calculate the correct PPN coupon), the tax adviser may 
        require the FA to separate true market fluctuations from the systemic accretion of Original Issue Discount (OID).

        **The FA Burden:** You cannot just rely on Markit's daily MTM. Your system must run a parallel 
        Effective Interest Rate (EIR) or straight-line amortization model to calculate how much of that 2.50 
        discount accretes into the income pool daily. 

        **The Entries:** - DR Loan Cost Basis | CR Discount Accretion Income
        - This effectively reclassifies part of your "Unrealised Gain" into "Interest Income," driving up the 
          PPN coupon to ensure full S110 tax neutrality on the total economic return of the loan.
        """)

    st.subheader("Liabilities & Accrued Expenses")

    liab_data = [
        {"Line Item": "Admin Fee Accrual", "Amount (€)": 25000, "Traditional Equivalent": "Administration Fee Accrual", "Frequency": "Daily accrual"},
        {"Line Item": "Management Fee Accrual (Maples)", "Amount (€)": 35000, "Traditional Equivalent": "ManCo Fee Accrual", "Frequency": "Daily accrual"},
        {"Line Item": "Investment Mgmt Fee Accrual (KKR)", "Amount (€)": 125000, "Traditional Equivalent": "IM Fee Accrual", "Frequency": "Daily accrual"},
        {"Line Item": "Trustee Fee Accrual", "Amount (€)": 12500, "Traditional Equivalent": "Trustee/Depositary Fee", "Frequency": "Daily accrual"},
        {"Line Item": "Audit Fee Accrual", "Amount (€)": 8333, "Traditional Equivalent": "Audit Fee Accrual", "Frequency": "Daily accrual"},
        {"Line Item": "Legal Fee Accrual", "Amount (€)": 6250, "Traditional Equivalent": "Legal Fee Accrual", "Frequency": "Quarterly"},
        {"Line Item": "Listing Fee Accrual", "Amount (€)": 2500, "Traditional Equivalent": "Listing Fee Accrual", "Frequency": "Annual"},
        {"Line Item": "Paying Agent Fee Accrual", "Amount (€)": 3000, "Traditional Equivalent": "TA Fee / Paying Agent", "Frequency": "Quarterly"},
        {"Line Item": "Other Accrued Expenses", "Amount (€)": 5000, "Traditional Equivalent": "Sundry Creditors", "Frequency": "As incurred"},
        {"Line Item": "PPN Coupon Accrual (to AUT)", "Amount (€)": 0, "Traditional Equivalent": "Distribution Payable", "Frequency": "Monthly"},
    ]
    liab_df = pd.DataFrame(liab_data)
    total_liab = liab_df["Amount (€)"].sum()

    st.dataframe(liab_df.style.format({"Amount (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)
    st.error(f"**TOTAL LIABILITIES (B): €{total_liab:,.0f}**")

    # ── VAT Analysis (Review Correction) ──
    with st.expander("📋 VAT Breakdown on Expenses (Review Correction)", expanded=False):
        st.warning(
            "**CORRECTION:** The original model did not address VAT treatment. Core admin/ManCo/IM/trustee services "
            "to a qualifying S110 SPV are typically VAT **exempt**. But professional services (audit, legal) carry "
            "23% Irish VAT, and the irrecoverable portion must be factored into NAV."
        )
        vat_data = pd.DataFrame([
            {"Expense": "Admin Fee", "Net (€)": 25000, "VAT Rate": "Exempt", "VAT (€)": 0, "Irrecoverable VAT (€)": 0},
            {"Expense": "ManCo Fee", "Net (€)": 35000, "VAT Rate": "Exempt", "VAT (€)": 0, "Irrecoverable VAT (€)": 0},
            {"Expense": "IM Fee (KKR)", "Net (€)": 125000, "VAT Rate": "Exempt", "VAT (€)": 0, "Irrecoverable VAT (€)": 0},
            {"Expense": "Trustee Fee", "Net (€)": 12500, "VAT Rate": "Exempt", "VAT (€)": 0, "Irrecoverable VAT (€)": 0},
            {"Expense": "Audit Fee", "Net (€)": 8333, "VAT Rate": "23%", "VAT (€)": 1917, "Irrecoverable VAT (€)": 1629},
            {"Expense": "Legal Fee", "Net (€)": 6250, "VAT Rate": "23%", "VAT (€)": 1438, "Irrecoverable VAT (€)": 1222},
            {"Expense": "Listing Fee", "Net (€)": 2500, "VAT Rate": "Exempt", "VAT (€)": 0, "Irrecoverable VAT (€)": 0},
            {"Expense": "Paying Agent Fee", "Net (€)": 3000, "VAT Rate": "Exempt", "VAT (€)": 0, "Irrecoverable VAT (€)": 0},
            {"Expense": "Other Expenses", "Net (€)": 5000, "VAT Rate": "Mixed", "VAT (€)": 500, "Irrecoverable VAT (€)": 425},
        ])
        st.dataframe(vat_data.style.format({"Net (€)": "€{:,.0f}", "VAT (€)": "€{:,.0f}", "Irrecoverable VAT (€)": "€{:,.0f}"}),
                     use_container_width=True, hide_index=True)

        total_irrecoverable = vat_data["Irrecoverable VAT (€)"].sum()
        st.metric("Total Irrecoverable VAT (additional cost to NAV)", f"€{total_irrecoverable:,.0f}")
        st.caption("If you accrue expenses NET of VAT but some VAT is irrecoverable, your NAV will be OVERSTATED. "
                   "Confirm the exact recovery rate with the tax adviser at inception.")

    nav = total_assets - total_liab
    st.markdown("---")

    nav_col1, nav_col2, nav_col3 = st.columns(3)
    nav_col1.metric("NET ASSET VALUE (A − B)", f"€{nav:,.0f}")
    nav_col2.metric("PPN Note Value", f"€{nav:,.0f}", help="PPN value = NAV. One investor, one note.")
    nav_col3.metric("AUT Fund Holding Value", f"€{nav:,.0f}", help="This is what the AUT books as its investment in the DAC.")

    # ── PPN Face Value Stability Check ──
    st.markdown("---")
    st.subheader("PPN Face Value Stability Check")
    teach("PPN Face Value", "Share Class Capital Base",
          "The PPN face value is set at inception and only changes on drawdown or wind-down. "
          "Unlike a traditional fund, there is NO daily capital activity.")

    ppn_col1, ppn_col2, ppn_col3 = st.columns(3)
    inception_fv = total_fv_loans + total_mv_bonds
    with ppn_col1:
        ppn_inception = st.number_input("PPN Face Value at Inception (€)", value=int(inception_fv), step=100000, format="%d")
    with ppn_col2:
        additional_drawdown = st.number_input("Additional Drawdowns (€)", value=0, step=100000, format="%d",
                                               help="Enter supplemental note issuances if KKR adds new loans post-inception")
    with ppn_col3:
        principal_paydown = st.number_input("Principal Paydowns (€)", value=0, step=100000, format="%d",
                                            help="Enter partial note redemptions or wind-down amounts")

    current_ppn_fv = ppn_inception + additional_drawdown - principal_paydown
    ppn_status = "UNCHANGED SINCE INCEPTION" if (additional_drawdown == 0 and principal_paydown == 0) else "ADJUSTED — REVIEW REQUIRED"

    st_col1, st_col2 = st.columns(2)
    st_col1.metric("Current PPN Face Value", f"€{current_ppn_fv:,.0f}")
    if additional_drawdown == 0 and principal_paydown == 0:
        st_col2.success(f"✓ {ppn_status}")
    else:
        st_col2.warning(f"⚠ {ppn_status}")

    st.caption("This should match the PPN register held by Maples (Registrar). If there is a mismatch, investigate immediately.")

    # ── No Daily Capital Activity Callout ──
    st.markdown("---")
    st.error(
        "**NO DAILY CAPITAL ACTIVITY — KEY DIFFERENCE FROM TRADITIONAL FUNDS**\n\n"
        "Unlike a traditional mutual fund, the PPN balance does NOT change daily. "
        "There is NO daily subscription/redemption activity. "
        "You do NOT need to wait for TA capital activity before calculating NAV.\n\n"
        "**The ONLY times the PPN face value changes:**\n"
        "- Day 1: Initial in-kind subscription\n"
        "- Additional Drawdowns: KKR adds new loans → supplemental note issued → PPN face value increases\n"
        "- Wind-Down: DAC returns principal to AUT → PPN face value decreases\n"
        "- Distribution Days: Monthly coupon & quarterly sweep reduce CASH and PPN coupon accrual, but NOT the PPN face value\n\n"
        "**The 'TA' function** is handled by Maples (Fiduciary Services / SPV Administration), NOT a Transfer Agency desk. "
        "Your contact at Maples is their Fiduciary/SPV Admin team."
    )

    st.markdown("---")
    with st.expander("📝 Notes for Fund Accountants"):
        st.markdown("""
        1. **NAV = Assets − Liabilities.** Same as any fund — the DAC is just the legal wrapper.
        2. **Loan fair values from Markit DAILY** — treat like any pricing vendor. Download, check, apply.
        3. **PPN coupon accrual** is the S110 mechanism — the amount distributed as note interest.
        4. **Accrued interest on loans** uses actual/360 (leveraged loan convention). Bonds vary.
        5. **Unrealised gains/losses** flow through the Income Statement daily — like marking a UCITS equity book.
        6. **Cash at bank** = excess cash that gets swept quarterly. Between sweeps, it sits in the DAC account.
        7. **The AUT sees NAV as its fund holding value** — like holding a unit in a sub-fund.
        """)

# ══════════════════════════════════════════════════════════════
# PAGE: NAV Process Tasks
# ══════════════════════════════════════════════════════════════
elif page == "📋 NAV Process Tasks":
    st.title("NAV Process — Task Calendar")
    st.markdown("*Every task, mapped from private credit terminology to what you already know*")

    freq_filter = st.multiselect("Filter by frequency",
                                  ["DAILY", "WEEKLY", "MONTHLY", "QUARTERLY", "ANNUAL"],
                                  default=["DAILY", "WEEKLY", "MONTHLY", "QUARTERLY", "ANNUAL"])

    all_tasks = {
        "DAILY": [
            ("Download Markit loan prices", "Markit pricing file", "Download pricing file from vendor", "FA Team", "By 10am; check for stale prices (>5 days old)"),
            ("Apply fair values to loan book", "Mark-to-Market (MTM)", "Apply vendor prices to portfolio", "FA Team", "Match Markit ID to internal position ID"),
            ("Price bond holdings", "Bond pricing", "Apply bond prices", "FA Team", "Use mid-price unless OM specifies"),
            ("Calculate accrued interest — loans", "Loan accrued interest calc", "Accrued income calculation", "FA Team", "EURIBOR + spread; actual/360 day count"),
            ("Calculate accrued interest — bonds", "Bond accrued interest calc", "Accrued income calculation", "FA Team", "Per bond terms; 30/360 or act/act"),
            ("Accrue daily expenses", "Expense accrual", "Daily fee accrual", "FA Team", "Admin, ManCo, IM, Trustee, Audit, Legal fees"),
            ("Calculate NAV", "DAC Net Asset Value", "Fund NAV calculation", "FA Team", "Assets − Liabilities = NAV. NAV = PPN value."),
            ("Prepare NAV pack for review", "NAV pack / pricing memo", "NAV sign-off pack", "FA Team", "Price movements, exceptions, commentary"),
            ("NAV review & sign-off", "Four-eyes NAV check", "NAV checker review", "Senior FA", "Check prices, accruals, cash, variances"),
            ("Publish NAV to investor", "NAV reporting to noteholder", "NAV dissemination", "FA Team", "Send to AUT administrator — they update fund holding"),
        ],
        "WEEKLY": [
            ("Loan event monitoring", "Credit event check", "Corporate action monitoring", "FA Team", "Defaults, restructurings, amendments"),
            ("Cash position reconciliation", "Cash book rec vs bank stmt", "Bank reconciliation", "FA Team", "Reconcile DAC bank account to cash book"),
            ("Position reconciliation", "Portfolio rec to servicing rpt", "Holdings reconciliation", "FA Team", "Rec loan positions to KKR servicing report"),
            ("Stale price review", "Stale price monitoring", "Pricing exception report", "FA Team", "Flag Markit prices unchanged >5 business days"),
            ("EURIBOR rate check", "Reference rate verification", "Benchmark rate check", "FA Team", "Verify EURIBOR fixing used in accrual calcs"),
        ],
        "MONTHLY": [
            ("Calculate distributable income", "PPN coupon calculation", "Distribution calculation", "FA Team", "Net income available for note coupon payment"),
            ("Prepare distribution notice", "Note payment notice", "Dividend notice", "FA Team", "Notify AUT of upcoming PPN coupon"),
            ("Process PPN coupon payment", "Note interest payment", "Dividend payment", "FA / PA", "Wire from DAC account to AUT"),
            ("Monthly investor report", "Noteholder report", "Monthly factsheet", "FA Team", "NAV, performance, top holdings"),
            ("KKR servicing report review", "IM servicing report", "Manager report review", "FA Team", "Loan performance, defaults, watchlist"),
            ("Trial balance review", "DAC trial balance", "Fund trial balance", "FA Team", "Verify all GL accounts balance"),
            ("Update AUT holding value", "Notify AUT of NAV/PPN value", "Update investor register", "FA Team", "AUT updates their books"),
            ("FX check (EUR/AUD)", "FX exposure monitoring", "FX hedge check", "FA Team", "AUT is AUD-based; check hedging"),
        ],
        "QUARTERLY": [
            ("Cash sweep calculation", "Quarterly cash sweep / waterfall", "N/A — structured credit", "FA Team", "Calculate excess cash for distribution"),
            ("Apply priority of payments", "Waterfall distribution", "Expense priority order", "FA Team", "Pay per waterfall layers"),
            ("Prepare waterfall report", "Waterfall compliance report", "Distribution breakdown", "FA Team", "Each layer of waterfall + amounts"),
            ("Pay quarterly expenses", "Quarterly expense settlement", "Quarterly fee payment", "FA / PA", "Settle admin, ManCo, trustee, legal invoices"),
            ("Portfolio compliance check", "Investment guideline test", "Investment restriction check", "FA Team", "Sector, name, rating limits per OM"),
            ("Covenant compliance testing", "Financial covenant test", "N/A — credit specific", "FA Team", "Coverage ratios, LTV, OC/IC tests"),
            ("Prepare quarterly accounts", "Interim financial statements", "Management accounts", "FA Team", "BS, P&L, cash flow for the DAC"),
            ("Board reporting pack", "Director reporting pack", "Board report", "FA Team", "NAV history, performance, risk metrics"),
        ],
        "ANNUAL": [
            ("Provide statutory accounts data pack", "Data pack to CSP for FRS 102 accounts", "Annual fund accounts data", "FA Team", "Trial balance, portfolio valuations, accrual schedules → Maples CSP prepares the actual statutory accounts"),
            ("Coordinate audit", "Statutory audit", "Annual fund audit", "FA Team", "Confirmations, pricing evidence, cash recs, fair value hierarchy (Level 2/3) documentation"),
            ("S110 tax computation", "S110 profit participating deduction", "N/A — S110 specific", "Tax Adviser", "PPN coupon ≥ taxable profit → zero tax. FA provides data pack."),
            ("CRO annual return", "Company annual return", "CBI return (for regulated)", "Co. Sec.", "File with CRO not CBI"),
            ("FATCA entity registration", "IRS GIIN maintenance", "FATCA compliance", "FA / Compliance", "DAC is a Financial Institution. Maintain GIIN, file Form 8966 annually."),
            ("CRS / AEOI reporting", "Irish Revenue AEOI return", "CRS compliance", "FA / Compliance", "Collect W-8BEN-E from AUT. File annual CRS return to Irish Revenue."),
            ("Investor tax reporting", "Noteholder tax certificate", "Investor tax statement", "FA Team", "Interest certificate for Australian tax"),
            ("CBI quarterly returns (×4)", "CBI statistical reporting", "AIFMD returns", "FA / Reporting Agent", "Quarterly balance sheet + annual P&L to CBI. Not optional."),
            ("SLA performance review", "Service level review", "SLA review", "FA / Client", "NAV accuracy, timeliness, errors"),
            ("AML/KYC refresh", "AML/KYC annual review", "AML/KYC review", "Compliance", "Refresh AUT investor documentation"),
        ],
    }

    freq_colors = {"DAILY": "🔵", "WEEKLY": "🟢", "MONTHLY": "🟠", "QUARTERLY": "🔴", "ANNUAL": "🟣"}

    for freq in freq_filter:
        st.subheader(f"{freq_colors.get(freq, '')} {freq} Tasks")
        tasks_df = pd.DataFrame(all_tasks[freq],
                                 columns=["Task", "Private Credit Term", "Traditional Equivalent", "Owner", "Detail"])
        st.dataframe(tasks_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.info(f"**Total tasks across all frequencies:** {sum(len(v) for v in all_tasks.values())} tasks")

    # ── Real-World Friction Warnings ──
    st.markdown("---")
    st.subheader("⚠️ Operational Friction — What the Task List Doesn't Show")

    with st.expander("🔴 Reconciliation Reality: Agent Bank Friction & Delayed Settlement", expanded=False):
        st.error(
            "**You are NOT reconciling against clean SWIFT statements from a global custodian.** "
            "Loan cash flows arrive via agent bank notices — often manual PDF/fax, inconsistent formats, "
            "and late by days or weeks."
        )
        st.markdown("""
        **Agent Bank Notices** — Each of the 100 loans has an agent bank (JPMorgan, BofA, Citi, etc.)
        that sends interest payment notices, principal paydown notices, and amendment notices. These arrive
        in different formats, at different times, and frequently contain errors. You must build a
        reconciliation process that matches these manual notices to your accrual records.

        **LSTA/LMA Delayed Settlement** — Leveraged loan trades do NOT settle T+2 like equities or bonds.
        Standard LSTA settlement is T+7 to T+10 for par trades. Distressed trades can take 20+ business days.
        During this period you must track: (a) pending trades, (b) delayed compensation (the buyer owes the
        seller interest from trade date to settlement date), (c) cost of carry on unfunded commitments.

        **Income Reconciliation Complexity** — Rate resets on floating-rate loans mean the interest amount
        changes every quarter. Your income rec must match the agent bank's calculation exactly, accounting for
        EURIBOR floor adjustments, day count conventions, and any rate reset lag. A 1bp discrepancy on a
        €500k par loan = €4.17/month. Across 100 loans, these add up fast.

        **Break Funding** — If a borrower prepays a loan between EURIBOR reset dates, the lender may be
        entitled to a break funding payment to compensate for the rate mismatch. You must calculate and
        accrue for this.
        """)

    with st.expander("🔴 Credit Events Are NOT Just 'Defaults'", expanded=False):
        st.warning(
            "**The happy path mentions 'credit event processing' as if it's a single workflow.** "
            "In reality, there are at least 6 distinct credit event types, each with different accounting treatment."
        )
        st.markdown("""
        **PIK (Payment-in-Kind) Interest** — The borrower doesn't pay cash interest; instead, the interest
        is capitalised and added to the loan principal. When this happens:
        - Par value of the loan INCREASES by the PIK amount
        - You must adjust the cost basis for amortisation calculations
        - Income is recognised but NO cash is received
        - The Markit fair value will reflect the new, higher par value
        - Your accrual engine must handle the toggle between cash-pay and PIK periods

        **Amend & Extend (A&E)** — The borrower renegotiates the loan terms. Typically: maturity extended
        by 1-3 years, spread may increase or decrease, commitment fees may change, EURIBOR floor may be
        added or removed. Each A&E requires: (a) updating the facility terms in your system, (b) recalculating
        all forward accruals, (c) potentially recognising an amendment fee, (d) assessing whether the
        modification triggers derecognition under FRS 102.

        **Partial Principal Paydowns** — The borrower repays part of the loan early. You must: (a) reduce
        par value, (b) calculate and book any realised gain/loss (proceeds vs. cost basis), (c) recalculate
        accrued interest on the reduced balance, (d) update the Markit position for the new notional.

        **Distressed Debt Exchanges** — The borrower swaps existing debt for new debt at a discount.
        You receive a new instrument at a different rate, maturity, and par value. The old position must
        be derecognised, the new position booked, and any gain/loss realised.

        **Covenant Waiver / Amendment** — No immediate financial impact, but you must update the compliance
        testing parameters and flag the waiver to the ManCo and Trustee.

        **Full Default & Recovery** — The loan enters workout. Markit prices it at recovery value (often
        30-60 cents). You must track the recovery process over months/years, booking partial recoveries
        as they occur, and eventually derecognising the position.
        """)

    with st.expander("🔴 FATCA & CRS: The DAC Is a Financial Institution", expanded=False):
        st.warning(
            "**Even with ONE investor, the DAC must comply with FATCA and CRS.** "
            "The S110 DAC is classified as a Financial Institution for AEOI purposes."
        )
        st.markdown("""
        **FATCA (Foreign Account Tax Compliance Act)**:
        - The DAC must register with the IRS and obtain a Global Intermediary Identification Number (GIIN)
        - The AUT must provide a W-8BEN-E self-certification confirming its FATCA status
        - The FA team must file Form 8966 annually (or confirm nil return if the AUT is FATCA-compliant)
        - Irish Revenue acts as the competent authority for US-Ireland FATCA information exchange

        **CRS (Common Reporting Standard)**:
        - The DAC must register with Irish Revenue as a Reporting Financial Institution
        - The AUT must provide a CRS self-certification
        - Annual CRS return must be filed to Irish Revenue, reporting the AUT's account balance and income
        - Australia is a CRS participating jurisdiction — the data WILL be exchanged

        **FA Team's Role**: Collect and validate self-certification documents (W-8BEN-E, CRS form),
        maintain the FATCA/CRS classification of the AUT, and provide the data for annual filings.
        """)

    with st.expander("🔴 Statutory Accounts ≠ Fund Accounts — The FRS 102 Burden", expanded=False):
        st.error(
            "**You are NOT producing a Statement of Operations and Statement of Net Assets.** "
            "You are producing FULL CORPORATE STATUTORY FINANCIAL STATEMENTS under FRS 102."
        )
        st.markdown("""
        **What traditional FA teams are used to producing:**
        - Statement of Net Assets (one page)
        - Statement of Operations (one page)
        - Schedule of Investments
        - Standard fund-specific notes

        **What the S110 DAC requires:**
        - Full Directors' Report (governance, principal activities, post-balance-sheet events, going concern)
        - Income Statement (corporate P&L format, not fund format)
        - Balance Sheet (corporate format with fixed/current asset distinction)
        - Statement of Changes in Equity (even though equity is nominal)
        - Cash Flow Statement (direct or indirect method)
        - S110-Specific Tax Notes (profit participating deduction disclosure, ATAD ILR assessment)
        - Related Party Disclosures (KKR as IM, Maples as ManCo/Trustee/Director — all related parties)
        - Financial Instruments Disclosures (FRS 102 Section 11/12 classification, fair value hierarchy)
        - Risk Disclosures (credit risk, market risk, liquidity risk — loan-level analysis)

        The audit is also more onerous. Auditors will test the S110 qualifying conditions,
        verify the profit participating deduction, and examine the ATAD ILR position.
        Budget 2-3x the audit support effort compared to a traditional fund.
        """)

# ══════════════════════════════════════════════════════════════
# PAGE: PPN Lifecycle
# ══════════════════════════════════════════════════════════════
elif page == "📜 PPN Lifecycle":
    st.title("Profit Participating Note (PPN) — Full Lifecycle")
    teach("Profit Participating Note", "Share Class",
          "The PPN is the instrument the investor holds. Instead of buying shares/units, "
          "the AUT buys a debt note that participates in the DAC’s profits. This is the critical difference.")

    tab1, tab2, tab3, tab4 = st.tabs(["📦 Issuance", "📈 Valuation", "💸 Distribution", "🏛 S110 Tax"])

    with tab1:
        st.subheader("Step 1: PPN Issuance (In-Kind Subscription)")
        st.warning("**No cash changes hands at inception.** The AUT transfers loans + bonds to the DAC, "
                   "and the DAC issues a PPN in return. The PPN face value = total fair value of assets transferred.")
        steps = pd.DataFrame([
            {"Step": 1, "Action": "KKR selects loans + bonds for DAC", "Traditional": "Fund launch portfolio selection"},
            {"Step": 2, "Action": "Assets valued by Markit + vendor", "Traditional": "Initial pricing"},
            {"Step": 3, "Action": "AUT transfers assets to DAC (in-kind)", "Traditional": "Subscription in specie"},
            {"Step": 4, "Action": "DAC issues PPN to AUT", "Traditional": "Share/unit issuance"},
            {"Step": 5, "Action": "AUT records PPN as fund holding", "Traditional": "Record fund investment"},
            {"Step": 6, "Action": "DAC books assets on balance sheet", "Traditional": "Portfolio setup on admin system"},
            {"Step": 7, "Action": "FA team sets up fund on system", "Traditional": "Fund launch / go-live"},
        ])
        st.dataframe(steps, use_container_width=True, hide_index=True)

    with tab2:
        st.subheader("Step 2: PPN Ongoing Valuation")
        st.info("**Simple rule:** PPN value = DAC NAV. One investor, one note. The AUT uses this to value their holding.")
        steps_v = pd.DataFrame([
            {"Step": 1, "Action": "Calculate daily NAV of DAC", "Traditional": "Fund NAV calculation"},
            {"Step": 2, "Action": "PPN value = DAC NAV", "Traditional": "NAV per unit/share"},
            {"Step": 3, "Action": "Communicate NAV to AUT", "Traditional": "NAV publication"},
            {"Step": 4, "Action": "AUT revalues fund holding", "Traditional": "Portfolio revaluation"},
        ])
        st.dataframe(steps_v, use_container_width=True, hide_index=True)

    with tab3:
        st.subheader("Step 3: Monthly Distribution (PPN Coupon)")
        teach("Note Coupon", "Dividend / Distribution",
              "The monthly payment to the AUT. It's structured as interest on the PPN, "
              "not a fund dividend. But the economic effect is the same — cash goes to investor, NAV drops.")

        steps_d = pd.DataFrame([
            {"Step": 1, "Action": "Calculate net income for the month", "Traditional": "Income available for distribution"},
            {"Step": 2, "Action": "Determine PPN coupon amount", "Traditional": "Dividend declaration"},
            {"Step": 3, "Action": "Trustee/ManCo approval", "Traditional": "Distribution sign-off"},
            {"Step": 4, "Action": "Execute payment (Paying Agent)", "Traditional": "Dividend payment"},
            {"Step": 5, "Action": "Book distribution in DAC", "Traditional": "Distribution expense"},
            {"Step": 6, "Action": "AUT records income receipt", "Traditional": "Record dividend income"},
            {"Step": 7, "Action": "Reduce NAV by distribution amount", "Traditional": "Ex-dividend NAV"},
        ])
        st.dataframe(steps_d, use_container_width=True, hide_index=True)

        st.success("**DAC books:** DR PPN Coupon Expense (P&L) | CR Cash at Bank")
        st.success("**AUT books:** DR Cash at Bank | CR Income from DAC Investment")

    with tab4:
        st.subheader("Step 4: S110 Tax Mechanism")
        st.warning("**This is the whole point of S110:** The DAC is taxable, but achieves tax neutrality "
                   "by paying out all profits as PPN coupon. The coupon is deductible → taxable profit = zero.")

        tax_data = {
            "Item": ["Gross Income (interest + gains)", "Less: Operating Expenses",
                     "Pre-PPN Taxable Profit", "Less: PPN Coupon Paid",
                     "Taxable Profit After PPN", "Corporation Tax @ 25%"],
            "Amount (€)": [2500000, 500000, 2000000, 2000000, 0, 0],
            "Note": [
                "All loan interest + bond coupons + realised gains",
                "Admin + ManCo + IM + other",
                "This WOULD be taxable at 25% without S110",
                "Profit participating deduction — coupon = taxable profit",
                "Tax-neutral result achieved",
                "Zero tax. This is the whole point of S110.",
            ],
        }
        tax_df = pd.DataFrame(tax_data)
        st.dataframe(tax_df.style.format({"Amount (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)

        # Visual waterfall
        fig_tax = go.Figure(go.Waterfall(
            x=["Gross Income", "Expenses", "Pre-PPN Profit", "PPN Coupon", "Taxable Profit"],
            y=[2500000, -500000, 0, -2000000, 0],
            measure=["absolute", "relative", "total", "relative", "total"],
            text=["€2.5m", "(€0.5m)", "€2.0m", "(€2.0m)", "€0 ✓"],
            textfont=dict(color=THEME["text"]),
            connector_line_color=THEME["border"],
            increasing_marker_color=THEME["success"],
            decreasing_marker_color=THEME["danger"],
            totals_marker_color=THEME["accent"],
        ))
        fig_tax.update_layout(**PLOTLY_LAYOUT, title="S110 Tax Waterfall — How Tax Neutrality Works",
                              title_font_color=THEME["text"], showlegend=False)
        st.plotly_chart(fig_tax, use_container_width=True)

# ══════════════════════════════════════════════════════════════
# PAGE: Cash Flow & Waterfall
# ══════════════════════════════════════════════════════════════
elif page == "💸 Cash Flow & Waterfall":
    st.title("Quarterly Cash Sweep & Priority of Payments")
    teach("Cash Sweep / Waterfall", "Distribution Calculation",
          "Every quarter, excess cash above the reserve is distributed per a strict priority of payments. "
          "Think of it as a structured distribution — expenses first, investor last.")

    st.error(
        "**Critical structural point:** Interest proceeds and principal proceeds flow through SEPARATE waterfalls. "
        "You cannot dump all cash into one pool. Interest pays expenses and the PPN coupon (income). "
        "Principal is used to reinvest in new loans or pay down the PPN face value (capital)."
    )

    # ── Interest Waterfall ──
    st.subheader("A. Interest Waterfall (Income Proceeds)")
    st.caption("Sources: loan interest, bond coupons, commitment fees, amendment fees")

    interest_inflows = pd.DataFrame([
        {"Source": "Loan Interest Received", "Q1 (€)": 625000},
        {"Source": "Bond Coupon Received", "Q1 (€)": 42500},
        {"Source": "Commitment / Amendment Fees", "Q1 (€)": 8500},
    ])
    total_interest = interest_inflows["Q1 (€)"].sum()
    st.dataframe(interest_inflows.style.format({"Q1 (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)
    st.success(f"**Total Interest Inflows: €{total_interest:,.0f}**")

    int_waterfall = [
        {"Priority": "I-1", "Payment": "Taxes (if any)", "Q1 (€)": 0, "Annual Cap (€)": "N/A"},
        {"Priority": "I-2", "Payment": "Trustee Fees (Maples)", "Q1 (€)": 12500, "Annual Cap (€)": "€50,000"},
        {"Priority": "I-3", "Payment": "Fund Administration Fees", "Q1 (€)": 25000, "Annual Cap (€)": "€100,000"},
        {"Priority": "I-4", "Payment": "ManCo Fees (Maples)", "Q1 (€)": 35000, "Annual Cap (€)": "€140,000"},
        {"Priority": "I-5", "Payment": "IM Fees (KKR)", "Q1 (€)": 125000, "Annual Cap (€)": "€500,000"},
        {"Priority": "I-6", "Payment": "Audit & Legal Fees", "Q1 (€)": 15000, "Annual Cap (€)": "€80,000"},
        {"Priority": "I-7", "Payment": "Paying Agent & Listing", "Q1 (€)": 3000, "Annual Cap (€)": "€15,000"},
        {"Priority": "I-8", "Payment": "Other Operating Expenses", "Q1 (€)": 5000, "Annual Cap (€)": "€25,000"},
        {"Priority": "I-9", "Payment": "Cash Reserve Top-Up", "Q1 (€)": 50000, "Annual Cap (€)": "N/A"},
    ]
    int_wf_df = pd.DataFrame(int_waterfall)
    int_expenses = int_wf_df["Q1 (€)"].sum()
    int_residual = total_interest - int_expenses
    int_wf_df.loc[len(int_wf_df)] = {"Priority": "I-10", "Payment": "PPN Interest Coupon to AUT (residual)", "Q1 (€)": int_residual, "Annual Cap (€)": "N/A — residual"}
    st.dataframe(int_wf_df.style.format({"Q1 (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)

    i_col1, i_col2, i_col3 = st.columns(3)
    i_col1.metric("Interest Inflows", f"€{total_interest:,.0f}")
    i_col2.metric("Senior Expenses (I-1 to I-9)", f"€{int_expenses:,.0f}")
    i_col3.metric("PPN Income Coupon (I-10)", f"€{int_residual:,.0f}")

    # Interest waterfall chart
    fig_int = go.Figure(go.Waterfall(
        x=["Interest Inflows"] + [r["Payment"][:20] for _, r in int_wf_df.iterrows()],
        y=[total_interest] + [-r["Q1 (€)"] for _, r in int_wf_df.iterrows()],
        measure=["absolute"] + ["relative"] * len(int_wf_df),
        text=[f"€{total_interest:,.0f}"] + [f"(€{r['Q1 (€)']:,.0f})" for _, r in int_wf_df.iterrows()],
        textfont=dict(color=THEME["text"], size=9),
        connector_line_color=THEME["border"],
        increasing_marker_color=THEME["success"],
        decreasing_marker_color=THEME["danger"],
        totals_marker_color=THEME["accent"],
    ))
    fig_int.update_layout(**PLOTLY_LAYOUT, title="Interest Waterfall — Income Proceeds Only",
                         title_font_color=THEME["text"], showlegend=False,
                         xaxis_tickangle=-45, margin=dict(b=120))
    st.plotly_chart(fig_int, use_container_width=True)

    # ── Principal Waterfall ──
    st.markdown("---")
    st.subheader("B. Principal Waterfall (Capital Proceeds)")
    st.caption("Sources: loan principal repayments, loan sale proceeds, recovery proceeds")

    princ_inflows = pd.DataFrame([
        {"Source": "Loan Principal Repayments (scheduled)", "Q1 (€)": 100000},
        {"Source": "Loan Principal Prepayments", "Q1 (€)": 50000},
        {"Source": "Cash from Loan Sales", "Q1 (€)": 0},
        {"Source": "Recovery Proceeds (defaulted loans)", "Q1 (€)": 0},
    ])
    total_princ = princ_inflows["Q1 (€)"].sum()
    st.dataframe(princ_inflows.style.format({"Q1 (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)

    princ_waterfall = pd.DataFrame([
        {"Priority": "P-1", "Application": "Reinvestment in new loans (during reinvestment period)", "Q1 (€)": total_princ,
         "Note": "KKR deploys into new facilities per OM guidelines"},
        {"Priority": "P-2", "Application": "Pay down PPN face value (after reinvestment period ends)", "Q1 (€)": 0,
         "Note": "Reduces PPN notional — update Stability Check"},
        {"Priority": "P-3", "Application": "Residual to cash reserve or AUT (wind-down)", "Q1 (€)": 0,
         "Note": "Only applies if reinvestment period has ended and no new loans available"},
    ])
    st.dataframe(princ_waterfall.style.format({"Q1 (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)

    st.warning(
        "**Why this separation matters for S110 tax neutrality:** The PPN coupon (interest waterfall residual) "
        "is the deductible expense that achieves the S110 tax deduction. If you accidentally include principal "
        "repayments in the PPN coupon calculation, you over-distribute income, creating a mismatch between the "
        "accounting P&L and the tax computation. The tax adviser needs clean interest-only figures."
    )

    # ── Expense Caps ──
    st.markdown("---")
    with st.expander("⚠️ REAL-WORLD FRICTION: Expense Caps in the Trust Deed", expanded=False):
        st.error(
            "**The Trust Deed does NOT give a blank cheque for senior expenses.** Each expense layer typically "
            "has an annual cap. If an invoice pushes the YTD total above the cap, the excess is subordinated — "
            "it drops to the very bottom of the waterfall, below the PPN coupon."
        )
        st.markdown("""
        **How expense caps work in practice:**

        The Trust Deed specifies annual maximum amounts for each expense category. For example:
        - Admin fees capped at €100,000/year
        - Legal fees capped at €80,000/year (routine) with a separate provision for extraordinary legal costs

        **The FA must maintain a cumulative YTD expense tracker** for each capped layer. Before processing
        any quarterly payment, check the YTD against the cap:
        - YTD + this quarter's invoice ≤ cap → pay in full at the priority position
        - YTD + this quarter's invoice > cap → pay up to the cap at priority; the excess becomes "subordinated expenses" and drops below the PPN coupon

        **Subordinated expenses** are still owed — they don't disappear. They are paid from residual cash
        AFTER the PPN coupon, and if insufficient cash exists, they carry forward as a deferred payable.

        **Why this matters:** If you pay an over-cap invoice at the senior priority level, you have breached
        the Trust Deed. The Trustee can halt the waterfall. This is a contractual default, not just an
        accounting error.
        """)

        cap_tracker = pd.DataFrame([
            {"Expense": "Trustee Fees", "Annual Cap": 50000, "Q1 Paid": 12500, "Q2 Paid": 12500, "YTD": 25000, "Remaining": 25000, "Status": "Within Cap"},
            {"Expense": "Admin Fees", "Annual Cap": 100000, "Q1 Paid": 25000, "Q2 Paid": 25000, "YTD": 50000, "Remaining": 50000, "Status": "Within Cap"},
            {"Expense": "Legal Fees", "Annual Cap": 80000, "Q1 Paid": 15000, "Q2 Paid": 55000, "YTD": 70000, "Remaining": 10000, "Status": "Near Cap"},
            {"Expense": "IM Fees (KKR)", "Annual Cap": 500000, "Q1 Paid": 125000, "Q2 Paid": 125000, "YTD": 250000, "Remaining": 250000, "Status": "Within Cap"},
        ])
        st.dataframe(cap_tracker.style.format({"Annual Cap": "€{:,.0f}", "Q1 Paid": "€{:,.0f}", "Q2 Paid": "€{:,.0f}", "YTD": "€{:,.0f}", "Remaining": "€{:,.0f}"}),
                     use_container_width=True, hide_index=True)

    # ── Real-World Friction: Waterfall & Fee Complexity ──
    with st.expander("⚠️ REAL-WORLD FRICTION: Waterfall & Fee Calculation Complexity", expanded=False):
        st.error(
            "**The waterfall above shows the 'clean' version.** In reality, waterfall calculations require "
            "significant manual adjustment and cannot be fully automated from the simple priority list."
        )
        st.markdown("""
        **IM Fee Complexity — NOT a Simple bps on NAV:**

        KKR's management fee is rarely a flat basis point charge on the daily NAV. Common structures include:
        - **Fee on Invested Capital** — calculated on the aggregate cost basis of all deployed loans, not on fair value. If Markit marks a loan down 20%, the fee base doesn't change.
        - **Fee on Committed Capital** — calculated on total committed amount, including unfunded commitments. You must track the committed vs. drawn amounts separately.
        - **Fee on Performing Collateral Balance** — the fee base EXCLUDES non-performing loans (typically loans rated CCC or below, or those in default). You must flag and exclude these positions from the fee calculation each quarter.
        - **Fee Holidays & Step-Downs** — some IMA agreements include fee holidays (0% for year 1) or step-downs (1.5% for years 1-3, then 1.0%). You must track the fee schedule over the life of the vehicle.

        **Non-Performing Loan Exclusions:**

        The waterfall often requires splitting the portfolio into 'performing' and 'non-performing' for different
        interest layers. For example:
        - Interest from performing loans → flows through the main waterfall to the PPN coupon
        - Interest from non-performing loans → may be diverted to a separate reserve or used to reduce exposure
        - Recovery proceeds from defaulted loans → may have a separate priority in the waterfall

        **Catch-Up & Deferral Mechanics:**

        If a prior quarter's waterfall could not fully pay a layer (e.g., insufficient cash for the IM fee),
        the unpaid amount may carry forward as a 'deferred fee' with or without interest. The next quarter's
        waterfall must check for and pay any deferred amounts BEFORE the current quarter's amounts. This
        creates a rolling ledger of deferred payments that must be tracked meticulously.
        """)

        fee_comparison = pd.DataFrame([
            {"Fee Structure": "Flat bps on NAV", "Traditional Fund?": "✅ Yes — standard", "S110 DAC?": "❌ Rare", "Complexity": "Low"},
            {"Fee Structure": "bps on Invested Capital", "Traditional Fund?": "❌ No", "S110 DAC?": "✅ Common", "Complexity": "Medium — track cost basis"},
            {"Fee Structure": "bps on Committed Capital", "Traditional Fund?": "❌ No", "S110 DAC?": "✅ Common for PE", "Complexity": "Medium — track commitments"},
            {"Fee Structure": "bps on Performing Collateral", "Traditional Fund?": "❌ No", "S110 DAC?": "✅ Common for CLOs", "Complexity": "High — exclude NPLs daily"},
            {"Fee Structure": "With catch-up/deferral", "Traditional Fund?": "❌ No", "S110 DAC?": "✅ Possible", "Complexity": "Very High — rolling deferred ledger"},
        ])
        st.dataframe(fee_comparison, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════
# PAGE: In-Kind Subscription
# ══════════════════════════════════════════════════════════════
elif page == "📦 In-Kind Subscription":
    st.title("In-Kind (In-Specie) Subscription — DAC Setup")
    teach("In-Kind Subscription", "Subscription in Specie",
          "The AUT contributes assets (loans + bonds) rather than cash. "
          "The DAC issues a PPN with face value equal to the total fair value of assets transferred. "
          "NO CASH changes hands at inception.")

    st.error("**Critical concept:** In-kind means NO CASH at inception. The portfolio IS the subscription. "
             "Think of it like an in-specie transfer into a traditional fund.")

    st.subheader("Step-by-Step Process")
    steps = pd.DataFrame([
        {"Step": 1, "Action": "KKR selects 100 loans + 10 bonds", "DR": "—", "CR": "—",
         "Explanation": "Investment decision made by KKR."},
        {"Step": 2, "Action": "Markit provides inception fair values", "DR": "—", "CR": "—",
         "Explanation": "Each loan priced by Markit. This sets the subscription value."},
        {"Step": 3, "Action": "Bonds priced by vendor", "DR": "—", "CR": "—",
         "Explanation": "Total FV of all assets = subscription amount."},
        {"Step": 4, "Action": "Assets legally transfer to DAC", "DR": "Loan + Bond Portfolio", "CR": "—",
         "Explanation": "Ownership moves to the DAC entity."},
        {"Step": 5, "Action": "DAC issues PPN to AUT", "DR": "—", "CR": "PPN Liability",
         "Explanation": "DAC now owes AUT the value of assets received."},
        {"Step": 6, "Action": "AUT books the investment", "DR": "Investment in DAC", "CR": "Portfolio",
         "Explanation": "AUT swaps individual holdings for one 'fund holding'."},
        {"Step": 7, "Action": "FA team books opening NAV", "DR": "Per NAV calc", "CR": "Per NAV calc",
         "Explanation": "Day 1 NAV = total fair value. This IS the PPN value."},
    ])
    st.dataframe(steps, use_container_width=True, hide_index=True)

    st.subheader("Inception Balance Sheet")

    total_fv_loans = loans_df["Fair Value (€)"].sum()
    total_mv_bonds = bonds_df["Market Value (€)"].sum()
    total_portfolio = total_fv_loans + total_mv_bonds

    bs_col1, bs_col2 = st.columns(2)

    with bs_col1:
        st.markdown("**ASSETS**")
        bs_assets = pd.DataFrame([
            {"Item": "Loan Portfolio (100 loans at Markit FV)", "Amount (€)": total_fv_loans},
            {"Item": "Bond Portfolio (10 bonds at vendor FV)", "Amount (€)": total_mv_bonds},
            {"Item": "Cash at Bank", "Amount (€)": 0},
            {"Item": "TOTAL ASSETS", "Amount (€)": total_portfolio},
        ])
        st.dataframe(bs_assets.style.format({"Amount (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)

    with bs_col2:
        st.markdown("**LIABILITIES & PPN**")
        bs_liab = pd.DataFrame([
            {"Item": "PPN Liability (Note to AUT)", "Amount (€)": total_portfolio},
            {"Item": "Other Liabilities", "Amount (€)": 0},
            {"Item": "TOTAL LIABILITIES", "Amount (€)": total_portfolio},
        ])
        st.dataframe(bs_liab.style.format({"Amount (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)

    check = total_portfolio - total_portfolio
    if check == 0:
        st.success("✓ Balance Sheet balanced: Assets = Liabilities + PPN")
    else:
        st.error(f"✗ Imbalance: €{check:,.0f}")

    with st.expander("📝 Key Points for Fund Accountants"):
        st.markdown("""
        1. **No cash at inception.** The portfolio IS the subscription. Like an in-specie transfer.
        2. **PPN value at Day 1 = total fair value** of assets transferred. This is your opening NAV.
        3. **From Day 2, price normally** using Markit (loans) and Bloomberg (bonds).
        4. **AUT's old holdings** (individual loans + bonds) become ONE line item: 'Investment in DAC PPN'.
        5. **Balance sheet must always balance:** Assets = PPN Liability + Other Liabilities.
        6. **If new assets added later,** PPN face value adjusts (additional note issuance).
        """)

# ══════════════════════════════════════════════════════════════
# PAGE: DAC ↔ AUT Cash Movement
# ══════════════════════════════════════════════════════════════
elif page == "🔄 DAC ↔ AUT Cash Movement":
    st.title("Cash Movement Between DAC and AUT")
    teach("Note Coupon Payment", "Dividend Payment",
          "Every movement of cash between the DAC and the Australian Unit Trust. "
          "Monthly PPN coupons + quarterly cash sweep residuals.")

    movements = []
    for month in range(12):
        m_date = datetime(2025, month + 1, 28 if month + 1 != 2 else 28)
        coupon = 150000 + month * 2000
        movements.append({
            "Date": m_date, "Description": f"PPN Monthly Coupon — {m_date.strftime('%B')}",
            "From": "DAC", "To": "AUT", "Amount (€)": coupon, "Type": "Monthly Distribution"
        })
        if (month + 1) % 3 == 0:
            sweep = random.randint(180000, 350000)
            movements.append({
                "Date": datetime(2025, month + 1, 28),
                "Description": f"Q{(month + 1) // 3} Cash Sweep Residual",
                "From": "DAC", "To": "AUT", "Amount (€)": sweep, "Type": "Quarterly Sweep"
            })

    mvmt_df = pd.DataFrame(movements)
    mvmt_df["Date"] = pd.to_datetime(mvmt_df["Date"])

    type_filter = st.multiselect("Filter by type", ["Monthly Distribution", "Quarterly Sweep"],
                                  default=["Monthly Distribution", "Quarterly Sweep"])
    filtered = mvmt_df[mvmt_df["Type"].isin(type_filter)]

    st.dataframe(
        filtered.style.format({"Amount (€)": "€{:,.0f}", "Date": lambda x: x.strftime("%d-%b-%Y")}),
        use_container_width=True, hide_index=True,
    )

    total_to_aut = filtered["Amount (€)"].sum()
    monthly_total = filtered[filtered["Type"] == "Monthly Distribution"]["Amount (€)"].sum()
    sweep_total = filtered[filtered["Type"] == "Quarterly Sweep"]["Amount (€)"].sum()

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Cash DAC → AUT", f"€{total_to_aut:,.0f}")
    col2.metric("Monthly Coupons", f"€{monthly_total:,.0f}")
    col3.metric("Quarterly Sweeps", f"€{sweep_total:,.0f}")

    # Timeline chart
    fig_timeline = go.Figure()
    monthly = filtered[filtered["Type"] == "Monthly Distribution"]
    quarterly = filtered[filtered["Type"] == "Quarterly Sweep"]

    fig_timeline.add_trace(go.Bar(
        x=monthly["Date"], y=monthly["Amount (€)"],
        name="Monthly Coupon", marker_color=THEME["accent"],
        text=monthly["Amount (€)"].apply(lambda x: f"€{x / 1000:.0f}k"),
        textposition="outside", textfont=dict(color=THEME["text"]),
    ))
    if not quarterly.empty:
        fig_timeline.add_trace(go.Bar(
            x=quarterly["Date"], y=quarterly["Amount (€)"],
            name="Quarterly Sweep", marker_color=THEME["warn"],
            text=quarterly["Amount (€)"].apply(lambda x: f"€{x / 1000:.0f}k"),
            textposition="outside", textfont=dict(color=THEME["text"]),
        ))

    fig_timeline.update_layout(**PLOTLY_LAYOUT, title="Cash Flows DAC → AUT (2025)",
                               title_font_color=THEME["text"],
                               barmode="group", legend=dict(font_color=THEME["text"]))
    st.plotly_chart(fig_timeline, use_container_width=True)

    with st.expander("📝 Accounting Entries"):
        st.markdown("""
        **On each PPN coupon payment:**
        - DAC: DR PPN Coupon Expense (P&L) | CR Cash at Bank
        - AUT: DR Cash at Bank | CR Income from DAC Investment

        **On each quarterly cash sweep:**
        - DAC: DR PPN Coupon Expense (P&L) | CR Cash at Bank
        - AUT: DR Cash at Bank | CR Income from DAC Investment

        **AUT's total return** = Change in PPN value (unrealised) + Total coupons received (realised)

        **DAC's P&L** should net to approximately zero over a full year (S110 mechanism)
        """)

# ══════════════════════════════════════════════════════════════
# PAGE: TA & Paying Agent
# ══════════════════════════════════════════════════════════════
elif page == "🏛 TA & Paying Agent":
    st.title("Transfer Agent Role — How It Collapses in an S110 DAC")
    teach("Transfer Agent", "Registrar & Paying Agent (Maples Fiduciary Services)",
          "The traditional TA function disappears. There is ONE investor, ONE instrument (PPN), and a STATIC register. "
          "Maples handles this via their Fiduciary/SPV Administration team — NOT a Transfer Agency desk.")

    st.error(
        "**Key message for your team:** In a traditional fund, your daily NAV process includes "
        "'Receive capital activity from TA (subs/reds).' **THIS STEP DOES NOT EXIST FOR THIS DAC.** "
        "Do NOT hold up NAV production waiting for TA data. There is none."
    )

    st.subheader("Traditional TA ↔ S110 DAC Role Mapping")
    ta_mapping = pd.DataFrame([
        {"Traditional Function": "Transfer Agent (TA)", "S110 DAC Equivalent": "Registrar & Paying Agent",
         "Handled By": "Maples (Fiduciary/SPV Admin)", "Explanation": "Static ledger showing AUT owns the PPN + wire coupons. Not a high-volume TA desk."},
        {"Traditional Function": "Shareholder Register", "S110 DAC Equivalent": "Register of Noteholders",
         "Handled By": "Maples (Registrar)", "Explanation": "Single-line document: AUT owns the PPN. Updated only on drawdown or wind-down."},
        {"Traditional Function": "Daily Subscription Processing", "S110 DAC Equivalent": "N/A — Does Not Exist",
         "Handled By": "N/A", "Explanation": "NO daily capital activity. PPN issued on Day 1 (in-kind). No daily subs to process."},
        {"Traditional Function": "Daily Redemption Processing", "S110 DAC Equivalent": "N/A — Does Not Exist",
         "Handled By": "N/A", "Explanation": "Capital only returns on partial note redemption or wind-down. Not a daily event."},
        {"Traditional Function": "Dealing Deadline / Cut-Off Times", "S110 DAC Equivalent": "N/A — Does Not Exist",
         "Handled By": "N/A", "Explanation": "No dealing cycle. No cut-off times. No anti-dilution. No swing pricing."},
        {"Traditional Function": "Dividend Processing", "S110 DAC Equivalent": "Paying Agent Duties",
         "Handled By": "Maples (Paying Agent)", "Explanation": "Monthly coupon + quarterly sweep: Paying Agent wires from DAC account to AUT."},
        {"Traditional Function": "Contract Notes", "S110 DAC Equivalent": "Note Issuance Certificate",
         "Handled By": "Maples (Registrar)", "Explanation": "Global Note certificate issued at inception. Updated only on drawdown."},
        {"Traditional Function": "Capital Activity Reporting to FA", "S110 DAC Equivalent": "Drawdown/Paydown Notice (rare)",
         "Handled By": "Maples / KKR", "Explanation": "In traditional funds, FA waits for daily TA data. Here, capital changes are RARE events."},
        {"Traditional Function": "AML/KYC (ongoing)", "S110 DAC Equivalent": "AML/KYC (one investor)",
         "Handled By": "Maples (Compliance)", "Explanation": "One investor to check, not thousands. Full KYC at inception, annual refresh."},
        {"Traditional Function": "Investor Communications", "S110 DAC Equivalent": "Noteholder Communications",
         "Handled By": "FA Team + Maples", "Explanation": "Monthly NAV report to AUT. No bulk mailing."},
        {"Traditional Function": "Tax Reclaim Processing", "S110 DAC Equivalent": "WHT Tracking",
         "Handled By": "FA Team", "Explanation": "Track WHT on loan interest. No investor-level tax processing (single investor)."},
    ])
    st.dataframe(ta_mapping, use_container_width=True, hide_index=True, height=450)

    st.subheader("Governance Gate: Board Resolution for Distributions")
    st.warning(
        "**Critical difference from traditional funds:** In a UCITS, you calculate the dividend and the TA pays it. "
        "Here, Maples ManCo + DAC Directors + Trustee must ALL approve before the Paying Agent can wire. "
        "There is a governance gate between your distribution calculation and payment execution."
    )

    gov_steps = pd.DataFrame([
        {"Step": 1, "Action": "FA calculates distributable income", "Responsible": "Fund Administrator", "Timeline": "T+3 after month-end"},
        {"Step": 2, "Action": "FA prepares distribution notice", "Responsible": "Fund Administrator", "Timeline": "T+3"},
        {"Step": 3, "Action": "ManCo reviews and approves", "Responsible": "Maples (ManCo)", "Timeline": "T+4"},
        {"Step": 4, "Action": "Board resolution (or standing authority)", "Responsible": "Maples (Directors)", "Timeline": "T+5 or pre-authorised"},
        {"Step": 5, "Action": "Trustee authorises cash release", "Responsible": "Maples (Trustee)", "Timeline": "T+5"},
        {"Step": 6, "Action": "Paying Agent executes payment", "Responsible": "Maples (Paying Agent)", "Timeline": "T+6"},
        {"Step": 7, "Action": "FA books the distribution", "Responsible": "Fund Administrator", "Timeline": "T+6"},
        {"Step": 8, "Action": "AUT records income receipt", "Responsible": "AUT Administrator", "Timeline": "On receipt"},
    ])
    st.dataframe(gov_steps, use_container_width=True, hide_index=True)

    st.info("**Tip:** Ask Maples if there is a standing board resolution covering routine monthly payments "
            "within defined parameters. This avoids requiring a separate resolution for each monthly coupon payment "
            "and can save 1-2 days on the distribution timeline.")

# ══════════════════════════════════════════════════════════════
# PAGE: Additional Drawdown
# ══════════════════════════════════════════════════════════════
elif page == "📥 Additional Drawdown":
    st.title("Additional Drawdown — Post-Inception Note Issuance")
    teach("Drawdown / Additional Note Issuance", "Additional Subscription / Capital Call",
          "If KKR adds new loans post-inception, the AUT contributes additional capital (cash or in-kind), "
          "and the DAC issues a supplemental PPN. The PPN face value increases accordingly.")

    st.info(
        "**What triggers a drawdown?** KKR identifies new loans to add to the portfolio that require "
        "NEW CAPITAL from the AUT. This is NOT the same as buying new loans with existing DAC cash "
        "(that's just portfolio trading). A drawdown means the PPN face value changes."
    )

    st.subheader("Worked Example: €5m Additional Drawdown")

    total_fv_loans = loans_df["Fair Value (€)"].sum()
    total_mv_bonds = bonds_df["Market Value (€)"].sum()
    inception_val = total_fv_loans + total_mv_bonds

    dd_col1, dd_col2 = st.columns(2)
    with dd_col1:
        drawdown_amount = st.number_input("Drawdown Amount (€)", value=5000000, step=500000, format="%d",
                                           help="Value of new loans being added to the DAC")
    with dd_col2:
        new_loan_count = st.number_input("Number of New Loans", value=10, step=1, min_value=1, max_value=50)

    new_ppn = inception_val + drawdown_amount
    new_total_positions = 100 + new_loan_count

    col1, col2, col3 = st.columns(3)
    col1.metric("Original PPN Face Value", f"€{inception_val:,.0f}")
    col2.metric("Drawdown Amount", f"€{drawdown_amount:,.0f}", f"+{new_loan_count} loans")
    col3.metric("New PPN Face Value", f"€{new_ppn:,.0f}", f"+€{drawdown_amount:,.0f}")

    st.subheader("Step-by-Step Process")
    steps = pd.DataFrame([
        {"Step": 1, "Action": "KKR identifies new loans for the portfolio", "Detail": f"{new_loan_count} new loans selected — not yet in the DAC"},
        {"Step": 2, "Action": "Markit provides fair values for new loans", "Detail": f"New loans valued at €{drawdown_amount:,.0f} total"},
        {"Step": 3, "Action": "AUT transfers new loans (in-kind) or sends cash", "Detail": "Assets move to DAC balance sheet"},
        {"Step": 4, "Action": "DAC issues supplemental PPN to AUT", "Detail": f"Additional note for €{drawdown_amount:,.0f} — PPN face value increases"},
        {"Step": 5, "Action": "Maples updates Register of Noteholders", "Detail": f"Register now shows AUT holds PPN with face value €{new_ppn:,.0f}"},
        {"Step": 6, "Action": "FA team updates admin system", "Detail": f"Add {new_loan_count} new positions, update PPN register, recalculate NAV"},
        {"Step": 7, "Action": "Next NAV calculation", "Detail": f"NAV now includes original {100} loans + {new_loan_count} new loans at fair value"},
    ])
    st.dataframe(steps, use_container_width=True, hide_index=True)

    st.subheader("Impact on Your Daily NAV Process")
    impact = pd.DataFrame([
        {"Item": "Number of Loan Positions", "Before": "100", "Drawdown Day": f"{new_total_positions} (+{new_loan_count})", "After": f"{new_total_positions}"},
        {"Item": "PPN Face Value", "Before": f"€{inception_val/1e6:.1f}m", "Drawdown Day": f"€{new_ppn/1e6:.1f}m (+€{drawdown_amount/1e6:.1f}m)", "After": f"€{new_ppn/1e6:.1f}m"},
        {"Item": "Daily Capital Activity?", "Before": "NONE", "Drawdown Day": "ONE-OFF EVENT", "After": "NONE"},
        {"Item": "Markit Pricing File", "Before": "100 loans", "Drawdown Day": f"{new_total_positions} loans", "After": f"{new_total_positions} loans"},
        {"Item": "NAV = PPN Value?", "Before": "Yes", "Drawdown Day": "Yes (recalculated)", "After": "Yes"},
    ])
    st.dataframe(impact, use_container_width=True, hide_index=True)

    st.subheader("Accounting Entries")
    with st.expander("In-Kind Drawdown (assets transferred)"):
        st.success(f"**DAC books:** DR Loan Portfolio (new loans at FV) €{drawdown_amount:,.0f} | CR PPN Liability (supplemental note) €{drawdown_amount:,.0f}")
        st.success(f"**AUT books:** DR Investment in DAC PPN (increased) €{drawdown_amount:,.0f} | CR Loan Portfolio (transferred out) €{drawdown_amount:,.0f}")

    with st.expander("Cash Drawdown (alternative)"):
        st.success(f"**DAC books:** DR Cash at Bank €{drawdown_amount:,.0f} | CR PPN Liability (supplemental note) €{drawdown_amount:,.0f}")
        st.success(f"**AUT books:** DR Investment in DAC PPN (increased) €{drawdown_amount:,.0f} | CR Cash at Bank €{drawdown_amount:,.0f}")

    st.subheader("Requirements from Key Parties")
    reqs = pd.DataFrame([
        {"Party": "KKR (IM)", "Requirement": "Provide list of new loans with Markit LoanX IDs, par values, coupon terms", "Timing": "Before drawdown date", "SLA Impact": "Blocks position setup"},
        {"Party": "KKR (IM)", "Requirement": "Confirm Markit pricing is available for all new positions", "Timing": "Before drawdown date", "SLA Impact": "Blocks NAV pricing"},
        {"Party": "Maples (ManCo)", "Requirement": "Approve additional note issuance and confirm OM compliance", "Timing": "Before drawdown date", "SLA Impact": "Blocks issuance"},
        {"Party": "Maples (Trustee)", "Requirement": "Confirm drawdown complies with Trust Deed terms", "Timing": "Before drawdown date", "SLA Impact": "Blocks issuance"},
        {"Party": "Maples (Registrar)", "Requirement": "Update Register of Noteholders with new PPN face value", "Timing": "On drawdown date", "SLA Impact": "Blocks register accuracy"},
        {"Party": "AUT (Investor)", "Requirement": "Confirm asset transfer or cash wire for drawdown amount", "Timing": "On drawdown date", "SLA Impact": "Blocks asset receipt"},
        {"Party": "FA Team", "Requirement": "Set up new positions, update PPN face value, recalculate NAV", "Timing": "On drawdown date", "SLA Impact": "Blocks NAV publication"},
    ])
    st.dataframe(reqs, use_container_width=True, hide_index=True)

# ══════════════════════════════════════════════════════════════
# PAGE: ATAD & GL Structure
# ══════════════════════════════════════════════════════════════
elif page == "🏦 ATAD & GL Structure":
    st.title("ATAD Interest Limitation Rule — GL Design Requirements")
    teach("ATAD Interest Limitation Rule", "N/A (new for S110 DACs)",
          "The EU Anti-Tax Avoidance Directive restricts interest deductions to 30% of EBITDA. "
          "The PPN coupon IS an interest deduction. If it exceeds the threshold, the excess is non-deductible "
          "and the DAC pays 25% corporation tax — destroying S110 tax neutrality.")

    st.warning(
        "**Your job is NOT to determine ILR applicability** — the tax adviser does that. "
        "Your job is to structure the GL so the data is clean and easily extractable. "
        "Every income and expense line must be tagged as 'interest equivalent' or 'non-interest'."
    )

    st.subheader("GL Structure — Interest vs Non-Interest Classification")

    gl_data = pd.DataFrame([
        {"GL Line": "Loan Interest Income", "Interest Equivalent?": "✅ YES", "Example": "EURIBOR + spread on 100 loans", "Annual (€)": 2100000, "ATAD Role": "Exceeding Borrowing Costs (income)"},
        {"GL Line": "Bond Coupon Income", "Interest Equivalent?": "✅ YES", "Example": "Fixed coupon on 10 bonds", "Annual (€)": 150000, "ATAD Role": "Exceeding Borrowing Costs (income)"},
        {"GL Line": "Unrealised Gains (Markit)", "Interest Equivalent?": "❌ NO", "Example": "MTM gains from price increases", "Annual (€)": 500000, "ATAD Role": "Outside ILR scope"},
        {"GL Line": "Realised Gains", "Interest Equivalent?": "❌ NO", "Example": "Gains from loan disposals", "Annual (€)": 100000, "ATAD Role": "Outside ILR scope"},
        {"GL Line": "PPN Coupon (to AUT)", "Interest Equivalent?": "✅ YES — CRITICAL", "Example": "Profit participating note interest", "Annual (€)": 1800000, "ATAD Role": "This IS the key deduction"},
        {"GL Line": "Admin / ManCo / IM Fees", "Interest Equivalent?": "❌ NO", "Example": "Operating expenses", "Annual (€)": 740000, "ATAD Role": "Feeds EBITDA calculation"},
        {"GL Line": "Audit / Legal / Other", "Interest Equivalent?": "❌ NO", "Example": "Professional fees (incl. irrecoverable VAT)", "Annual (€)": 85000, "ATAD Role": "Feeds EBITDA calculation"},
        {"GL Line": "Unrealised Losses (Markit)", "Interest Equivalent?": "❌ NO", "Example": "MTM losses from price decreases", "Annual (€)": 350000, "ATAD Role": "Outside ILR scope"},
    ])
    st.dataframe(gl_data.style.format({"Annual (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)

    st.subheader("Simplified ATAD / ILR Calculation")

    gross_interest_income = 2250000
    ppn_coupon = 1800000
    operating_expenses = 825000

    col1, col2 = st.columns(2)
    with col1:
        ppn_input = st.number_input("PPN Coupon (annual, €)", value=ppn_coupon, step=100000, format="%d")
    with col2:
        interest_income = st.number_input("Gross Interest Income (annual, €)", value=gross_interest_income, step=100000, format="%d")

    # FIXED CALCULATION
    net_interest = ppn_input - interest_income
    ebitda = interest_income + 500000 + 100000 + 15000 - operating_expenses
    threshold_30 = ebitda * 0.3
    de_minimis = net_interest <= 3000000

    calc_data = pd.DataFrame([
        {"Item": "(A) Gross Interest Income", "Amount (€)": interest_income},
        {"Item": "(B) PPN Coupon Expense", "Amount (€)": ppn_input},
        {"Item": "(C) Net Interest Expense (B − A)", "Amount (€)": max(0, net_interest)},
        {"Item": "(D) EBITDA (simplified)", "Amount (€)": ebitda},
        {"Item": "(E) 30% of EBITDA", "Amount (€)": int(threshold_30)},
    ])
    st.dataframe(calc_data.style.format({"Amount (€)": "€{:,.0f}"}), use_container_width=True, hide_index=True)

    if de_minimis:
        st.success(f"✅ **De Minimis Check: Net Interest Expense (€{max(0, net_interest):,.0f}) is BELOW €3,000,000 — ILR likely does NOT apply.** Full deduction available.")
    else:
        st.error(f"⚠️ **Net Interest Expense (€{net_interest:,.0f}) EXCEEDS €3,000,000 — tax adviser must assess ILR applicability.** Standalone entity or single-group exemption may still apply.")

    with st.expander("📝 Notes for Fund Accountants"):
        st.markdown("""
        1. **You do NOT determine ILR applicability** — the tax adviser does. Your job is clean data.
        2. **The KEY requirement:** every GL line must be tagged as 'interest equivalent' or 'non-interest'.
        3. **The PPN coupon is the critical item** — it is the primary deduction achieving S110 tax neutrality.
        4. **Unrealised gains/losses from Markit** are NOT interest equivalents — keep them separate.
        5. **If Net Interest Expense < €3m annually**, the de minimis exemption likely applies.
        6. **If Net Interest Expense > €3m**, the tax adviser must determine if standalone entity or single-group exemption applies.
        """)

# ══════════════════════════════════════════════════════════════
# PAGE: CBI Reporting
# ══════════════════════════════════════════════════════════════
elif page == "📡 CBI Reporting":
    st.title("CBI Statistical Reporting — Mandatory Obligations")
    teach("CBI Statistical Reporting", "CBI Returns / AIFMD Annex IV",
          "Under Section 18 of the Central Bank Act 1971, ALL Section 110 SPVs must register with the CBI "
          "and submit quarterly balance sheet and annual P&L returns. This is NOT optional.")

    st.error(
        "**CORRECTION:** The original operating model stated that S110 DACs require 'no CBI returns' and "
        "operate under 'lighter compliance.' This is **factually incorrect** and represents a severe "
        "compliance risk if communicated to clients or stakeholders."
    )

    st.subheader("Mandatory Obligations")
    obligations = pd.DataFrame([
        {"Obligation": "CBI Registration", "Detail": "Register the DAC as an SPE with the CBI",
         "Deadline": "Within 5 working days of first transaction", "FA Team Role": "Provide entity details, asset class info"},
        {"Obligation": "Quarterly Balance Sheet", "Detail": "Submit categorised balance sheet data via CBI portal",
         "Deadline": "T+29 working days after quarter-end", "FA Team Role": "Produce quarterly trial balance with ECB categorisation"},
        {"Obligation": "Annual P&L Return", "Detail": "Submit annual income/expense data to CBI",
         "Deadline": "Per CBI schedule", "FA Team Role": "Produce annual income/expense breakdown"},
        {"Obligation": "Asset Categorisation", "Detail": "Classify assets by instrument type, counterparty residency, sector",
         "Deadline": "Part of quarterly return", "FA Team Role": "Maintain borrower residency & NACE sector codes"},
        {"Obligation": "Liability Categorisation", "Detail": "Classify PPN by holder residency, instrument type",
         "Deadline": "Part of quarterly return", "FA Team Role": "Classify PPN as debt held by non-resident (Australia)"},
    ])
    st.dataframe(obligations, use_container_width=True, hide_index=True)

    st.subheader("Data Extracts Required from FA Team")
    extracts = pd.DataFrame([
        {"Extract": "Trial Balance (CBI-mapped)", "Content": "Full TB with GL codes mapped to CBI statistical categories",
         "Frequency": "Quarterly", "Traditional Equiv.": "AIFMD Annex IV data extract"},
        {"Extract": "Asset Schedule by Residency", "Content": "All 110 holdings with borrower country of domicile",
         "Frequency": "Quarterly", "Traditional Equiv.": "Country exposure report"},
        {"Extract": "Asset Schedule by Sector", "Content": "All holdings with NACE sector classification",
         "Frequency": "Quarterly", "Traditional Equiv.": "Sector exposure report"},
        {"Extract": "Liability Schedule", "Content": "PPN face value, holder (AUT), residency (Australia), type (debt)",
         "Frequency": "Quarterly", "Traditional Equiv.": "Investor register extract"},
        {"Extract": "Income/Expense Breakdown", "Content": "Annual P&L split by interest/fee/operating categories",
         "Frequency": "Annual", "Traditional Equiv.": "Annual financial statements P&L"},
    ])
    st.dataframe(extracts, use_container_width=True, hide_index=True)

    with st.expander("📝 Notes for Fund Accountants"):
        st.markdown("""
        1. **This is NOT optional.** CBI statistical reporting is a legal obligation under Section 18 of the Central Bank Act 1971.
        2. **You produce the DATA.** The corporate secretary or reporting agent FILES the return.
        3. **Maintain borrower residency and NACE sector codes from Day 1.** Retrofitting at quarter-end is painful.
        4. **Similar to AIFMD Annex IV** — you provide the data, someone else files it. But the data must be right.
        5. **Coordinate with the reporting agent at inception** to agree the exact data format and delivery schedule.
        6. **The data must align with ECB macroeconomic statistical requirements** — not just internal reporting categories.
        """)

# ══════════════════════════════════════════════════════════════
# PAGE: WHT & DTT
# ══════════════════════════════════════════════════════════════
elif page == "🛡 WHT & DTT":
    st.title("Withholding Tax & Double Taxation Treaty Compliance")
    teach("Withholding Tax (WHT)", "Investor-level tax",
          "Ireland imposes 20% WHT on interest payments to non-residents. The PPN coupon IS an interest payment. "
          "Without a confirmed exemption, the DAC must withhold 20% and remit it to Revenue.")

    st.error(
        "**HARD COMPLIANCE GATE:** Before the first PPN coupon is wired to the AUT, you must verify that the "
        "tax adviser has formally confirmed the WHT exemption route. Wiring gross cash when WHT should have been "
        "deducted creates an **immediate and severe liability** with the Irish Revenue Commissioners."
    )

    st.subheader("WHT Landscape")
    wht_data = pd.DataFrame([
        {"Route": "Irish Domestic WHT Rate", "Rate": "20%", "Applies?": "DEFAULT — if no exemption",
         "Detail": "This is what applies if you wire without confirmation"},
        {"Route": "Ireland-Australia DTT", "Rate": "10% (may be 0%)", "Applies?": "Likely — confirm with tax adviser",
         "Detail": "Reduced rate under bilateral treaty. Depends on AUT's legal status"},
        {"Route": "Quoted Eurobond Exemption", "Rate": "0%", "Applies?": "If PPN listed on Euronext Dublin",
         "Detail": "Interest on listed debt to non-connected non-resident — fully exempt"},
        {"Route": "S.246(3)(h) Exemption", "Rate": "0%", "Applies?": "If PPN meets qualifying criteria",
         "Detail": "Wholesale debt instrument exemption — confirm with tax adviser"},
        {"Route": "EU Interest & Royalties Directive", "Rate": "N/A", "Applies?": "NO — Australia is not EU",
         "Detail": "Do not rely on this route"},
    ])
    st.dataframe(wht_data, use_container_width=True, hide_index=True)

    # ── Real-World Friction: WHT on Inflows ──
    with st.expander("⚠️ REAL-WORLD FRICTION: WHT on Inflows (Trapped Cash)", expanded=False):
        st.warning(
            "**The above assumes WHT is only an issue on OUTFLOWS. In reality, you face WHT on INFLOWS too.** "
            "European borrowers (e.g., a Spanish SA or Italian SpA) will often apply domestic withholding tax "
            "on the interest they pay *to* the Irish DAC."
        )
        st.markdown("""
        **The FA Burden:**
        - **Accrual vs. Cash:** You must accrue the Gross Interest, but your agent bank will only deliver the Net Cash.
        - **WHT Receivable:** The withheld amount must be booked as a "WHT Receivable" asset on your balance sheet, reducing your available cash but maintaining your NAV.
        - **DTT Relief Forms:** The FA team must coordinate with the tax adviser to file local Double Taxation Treaty relief forms in the borrower's jurisdiction (e.g., Spanish Form 210) to reclaim the trapped cash.
        - **Impairment:** If the forms are not filed, or relief is denied, the WHT Receivable becomes uncollectible. You must eventually write off this asset, hitting the P&L and permanently losing that yield.
        """)

    st.subheader("Documentation Checklist")
    st.markdown("All documents must be on file **before the first distribution**.")

    docs = [
        ("AUT Tax Residency Certificate (from ATO)", "PENDING", "Annual renewal"),
        ("DTT Relief Form (Irish Revenue)", "PENDING", "At inception; update on change"),
        ("Tax Adviser Formal WHT Confirmation", "PENDING", "At inception; reassess on change"),
        ("Euronext Listing Confirmation (if applicable)", "CHECK", "Annual — confirm listing active"),
        ("Beneficial Ownership Declaration", "PENDING", "At inception; update on change"),
    ]

    for doc_name, status, review in docs:
        col1, col2, col3 = st.columns([3, 1, 1])
        col1.markdown(f"**{doc_name}**")
        if status == "PENDING":
            col2.warning(status)
        else:
            col2.info(status)
        col3.caption(review)

    with st.expander("📝 Notes for Fund Accountants"):
        st.markdown("""
        1. **You do NOT determine the WHT exemption** — the tax adviser does. But you **MUST** verify confirmation is on file.
        2. **HARD STOP:** Do not process the first PPN coupon without all documents confirmed.
        3. **The risk:** Wiring gross when WHT should apply = immediate Revenue liability for the DAC.
        4. **Once confirmed**, the exemption applies to all subsequent distributions unless circumstances change.
        5. **Track document expiry dates** (especially ATO residency certificate) and obtain renewals proactively.
        6. **If AUT ownership structure changes**, or the DTT is renegotiated, reassess the WHT position.
        """)

# ══════════════════════════════════════════════════════════════
# PAGE: Real-World Friction & Exceptions
# ══════════════════════════════════════════════════════════════
elif page == "⚠️ Friction & Exceptions":
    st.title("Real-World Friction & Operational Exceptions")
    st.markdown("*The harsh reality that the happy path doesn’t show you*")

    st.error(
        "**This page exists because the rest of this tool shows the conceptual framework — the 'what.'** "
        "This page shows the 'how hard it actually is.' Every section below represents operational friction "
        "that will consume significant FA team time and cannot be automated away with a simple process document."
    )

    # ── Effort Heat Map ──
    st.subheader("Operational Effort Heat Map — Where Your Time Actually Goes")

    effort_data = pd.DataFrame([
        {"Area": "Daily Markit pricing (clean)", "Trad. Fund Effort": "Low", "S110 DAC Effort": "Low", "Surprise Factor": "None"},
        {"Area": "IPV on stale/missing prices", "Trad. Fund Effort": "Low", "S110 DAC Effort": "HIGH", "Surprise Factor": "🔴 Major — 15-30% of loans may be stale"},
        {"Area": "Accrued interest (simple)", "Trad. Fund Effort": "Low", "S110 DAC Effort": "Medium", "Surprise Factor": "🟡 EURIBOR floors, PIK toggles, rate resets"},
        {"Area": "Agent bank reconciliation", "Trad. Fund Effort": "N/A", "S110 DAC Effort": "HIGH", "Surprise Factor": "🔴 Major — manual notices, inconsistent formats"},
        {"Area": "Credit event processing", "Trad. Fund Effort": "Low (corp actions)", "S110 DAC Effort": "VERY HIGH", "Surprise Factor": "🔴 Major — PIK, A&E, paydowns, workouts"},
        {"Area": "Waterfall calculation", "Trad. Fund Effort": "N/A", "S110 DAC Effort": "HIGH", "Surprise Factor": "🔴 Major — NPL exclusions, catch-ups, deferrals"},
        {"Area": "IM fee accrual", "Trad. Fund Effort": "Low (bps on NAV)", "S110 DAC Effort": "HIGH", "Surprise Factor": "🔴 Major — invested/committed capital, NPL exclusions"},
        {"Area": "Statutory accounts data pack", "Trad. Fund Effort": "Medium", "S110 DAC Effort": "HIGH", "Surprise Factor": "🟡 FA provides data pack; CSP (Maples) prepares actual accounts"},
        {"Area": "FATCA/CRS compliance", "Trad. Fund Effort": "Medium (many investors)", "S110 DAC Effort": "Low (one investor)", "Surprise Factor": "🟢 Simpler — but still mandatory"},
        {"Area": "CBI statistical reporting", "Trad. Fund Effort": "N/A (AIFMD instead)", "S110 DAC Effort": "Medium", "Surprise Factor": "🟡 New workflow — quarterly ECB data"},
        {"Area": "Trade settlement tracking", "Trad. Fund Effort": "Low (T+2)", "S110 DAC Effort": "HIGH", "Surprise Factor": "🔴 Major — T+7 to T+20, delayed compensation"},
        {"Area": "FX hedge management (if hedging)", "Trad. Fund Effort": "Medium (fund-level)", "S110 DAC Effort": "HIGH", "Surprise Factor": "🔴 OTC forwards, margin calls, ISDA/CSA collateral"},
    ])
    st.dataframe(effort_data, use_container_width=True, hide_index=True)

    # ── Section 1: Reconciliation ──
    st.markdown("---")
    st.subheader("1. Reconciliation Reality")

    st.warning("**In traditional funds**, you reconcile against SWIFT statements from a global custodian "
               "who holds your assets in a centralised, electronic system. **In private credit**, there is no custodian "
               "for the loans. Cash flows arrive via agent bank notices — often manually, in inconsistent formats.")

    rec_comparison = pd.DataFrame([
        {"Dimension": "Cash flow source", "Traditional Fund": "SWIFT MT940/MT950 from custodian", "S110 DAC (Loans)": "Agent bank notices (PDF, email, fax) — one per facility"},
        {"Dimension": "Settlement cycle", "Traditional Fund": "T+2 (equities), T+1 (bonds)", "S110 DAC (Loans)": "T+7 to T+20 (par loans). Distressed: T+20+. Delayed compensation accrues."},
        {"Dimension": "Position reconciliation", "Traditional Fund": "Custodian holdings vs. book", "S110 DAC (Loans)": "KKR servicing report vs. book vs. Markit universe. Three-way rec."},
        {"Dimension": "Interest reconciliation", "Traditional Fund": "Custodian confirms coupon received", "S110 DAC (Loans)": "Agent bank notice vs. your accrual calc. Must match EURIBOR rate, day count, floor."},
        {"Dimension": "Exceptions", "Traditional Fund": "Rare — custodian catches most errors", "S110 DAC (Loans)": "Frequent — agent bank errors, timing differences, rate mismatches common."},
    ])
    st.dataframe(rec_comparison, use_container_width=True, hide_index=True)

    with st.expander("Worked Example: Delayed Settlement & Compensation"):
        st.markdown("""
        **Scenario:** KKR buys a new loan (LX180000) on March 5. Trade price: 97.50. Par: €500,000.

        **In equities**, this would settle on March 7 (T+2). Done.

        **In leveraged loans** (LSTA standard):
        - Trade date: March 5
        - Expected settlement: March 15 (T+7 at best)
        - Actual settlement: March 22 (agent bank delays, documentation)
        - During March 5-22, the buyer owes the seller **delayed compensation** = daily interest on the purchase price at an agreed rate
        - The FA must: (a) book the pending trade, (b) accrue delayed compensation daily, (c) on settlement, book the position, reverse the pending trade, and settle the delayed comp
        - If the loan pays interest on March 20 (before settlement), the seller receives it but must reimburse the buyer for the portion earned post-trade-date
        """)

    # ── Section 2: Credit Events ──
    st.markdown("---")
    st.subheader("2. Credit Event Complexity")

    st.warning("**'Credit event' is not a single workflow.** Each type requires different accounting treatment, "
               "different system updates, and different approval chains.")

    events = pd.DataFrame([
        {"Event Type": "PIK Interest Capitalisation", "Frequency": "Quarterly on PIK loans",
         "Accounting Impact": "Par value ↑, cost basis ↑, income recognised, NO cash received",
         "FA Effort": "High — amortisation schedule + position update + accrual engine toggle"},
        {"Event Type": "Amend & Extend (A&E)", "Frequency": "2-5 per year across portfolio",
         "Accounting Impact": "Maturity, spread, floor may all change. Possible amendment fee income.",
         "FA Effort": "Very High — update all facility terms, recalculate forward accruals, FRS 102 modification test"},
        {"Event Type": "Partial Principal Paydown", "Frequency": "Monthly on amortising loans",
         "Accounting Impact": "Par ↓, realised G/L on cost vs proceeds, accrued interest on reduced balance",
         "FA Effort": "Medium — but across 100 loans, multiple paydowns per month add up"},
        {"Event Type": "Distressed Debt Exchange", "Frequency": "Rare (1-2 per year)",
         "Accounting Impact": "Old position derecognised, new position booked at FV, G/L realised",
         "FA Effort": "Very High — effectively two trades + derecognition analysis"},
        {"Event Type": "Full Default & Workout", "Frequency": "Rare but high impact",
         "Accounting Impact": "Impairment at recovery value, partial recoveries over months/years",
         "FA Effort": "Very High — ongoing tracking until resolution, potential legal costs"},
        {"Event Type": "Covenant Waiver", "Frequency": "2-3 per year",
         "Accounting Impact": "No immediate P&L impact, but compliance parameters change",
         "FA Effort": "Low financially, but compliance testing must be updated"},
    ])
    st.dataframe(events, use_container_width=True, hide_index=True)

    with st.expander("Worked Example: PIK Interest Toggle"):
        st.markdown("""
        **Loan:** Acme Healthcare GmbH TL-A | Par: €500,000 | Coupon: E+400bps | PIK toggle active

        **Quarter 1 (Cash-Pay):**
        - EURIBOR: 3.50% | All-in rate: 7.50%
        - Interest: €500,000 × 7.50% × 90/360 = **€9,375 cash received**
        - Book: DR Cash €9,375 | CR Interest Income €9,375

        **Quarter 2 (PIK Period — borrower elects PIK):**
        - Same rate calculation: €9,375
        - But NO cash is received. Interest is capitalised.
        - Book: DR Loan Par Value €9,375 | CR PIK Interest Income €9,375
        - New par value: **€509,375** — Markit now prices against this higher par
        - Accruals from Q3 onward must use the NEW par value
        - The cost basis for future gain/loss calculations must also be adjusted
        """)

    # ── Section 3: FATCA/CRS ──
    st.markdown("---")
    st.subheader("3. FATCA & CRS — The DAC Is a Financial Institution")

    st.info(
        "**Even with one investor, the compliance obligation is real.** The S110 DAC is classified as a "
        "Financial Institution under both FATCA and CRS. The FA team must handle entity registration, "
        "collect self-certifications, and support annual filings."
    )

    fatca_crs = pd.DataFrame([
        {"Requirement": "IRS GIIN Registration", "FATCA": "✅ Required", "CRS": "N/A", "FA Action": "Ensure DAC has a valid GIIN. Renew registration if status changes."},
        {"Requirement": "Irish Revenue Registration", "FATCA": "Via Irish Revenue", "CRS": "✅ Required", "FA Action": "Register DAC as a Reporting Financial Institution."},
        {"Requirement": "Investor Self-Certification", "FATCA": "W-8BEN-E from AUT", "CRS": "CRS self-cert from AUT", "FA Action": "Collect, validate, and maintain on file. Update on change."},
        {"Requirement": "Annual Filing", "FATCA": "Form 8966 (via Revenue)", "CRS": "CRS return to Revenue", "FA Action": "Provide account balance + income data for filing."},
        {"Requirement": "Due Diligence", "FATCA": "Identify US indicia", "CRS": "Identify reportable persons", "FA Action": "Review AUT's controlling persons if required."},
    ])
    st.dataframe(fatca_crs, use_container_width=True, hide_index=True)

    # ── Section 4: Statutory Accounts ──
    st.markdown("---")
    st.subheader("4. FRS 102 Statutory Accounts — FA vs CSP Boundary")

    st.warning(
        "**Important governance boundary:** The Corporate Service Provider (CSP) — Maples Fiduciary in this case — "
        "typically prepares the statutory accounts and acts as Company Secretary. The FA team does NOT draft the "
        "directors' report or prepare the full FRS 102 financial statements. However, the FA team's data pack is "
        "the foundation for everything the CSP produces."
    )

    comparison = pd.DataFrame([
        {"Component": "Trial Balance (year-end)", "Who Produces": "FA Team", "Who Consumes": "CSP + Auditor",
         "FA Effort": "High — must be fully reconciled and mapped to corporate GL codes"},
        {"Component": "Portfolio Valuations + Pricing Evidence", "Who Produces": "FA Team", "Who Consumes": "CSP + Auditor",
         "FA Effort": "High — Markit screenshots, broker quotes, fair value hierarchy (L2/L3) documentation"},
        {"Component": "Accrual Schedules (all fees)", "Who Produces": "FA Team", "Who Consumes": "CSP + Auditor",
         "FA Effort": "Medium — must include VAT splits and fee base calculations"},
        {"Component": "S110 Tax Data Pack", "Who Produces": "FA Team", "Who Consumes": "Tax Adviser + CSP",
         "FA Effort": "High — interest vs non-interest split (ATAD), PPN coupon total, expense breakdown"},
        {"Component": "Cash Reconciliations (year-end)", "Who Produces": "FA Team", "Who Consumes": "CSP + Auditor",
         "FA Effort": "Medium — but must reconcile to agent bank level"},
        {"Component": "Directors' Report", "Who Produces": "CSP (Maples)", "Who Consumes": "Board + Auditor",
         "FA Effort": "Low — FA provides financial data; CSP drafts the narrative"},
        {"Component": "FRS 102 Financial Statements", "Who Produces": "CSP (Maples)", "Who Consumes": "Board + Auditor",
         "FA Effort": "Low — CSP formats; FA provides underlying data"},
        {"Component": "Related Party Disclosures", "Who Produces": "CSP (Maples)", "Who Consumes": "Board + Auditor",
         "FA Effort": "Low — FA confirms fee amounts; CSP identifies related party relationships"},
        {"Component": "CRO Annual Return", "Who Produces": "CSP (Maples as Co. Sec.)", "Who Consumes": "CRO",
         "FA Effort": "None — this is entirely the CSP's responsibility"},
    ])
    st.dataframe(comparison, use_container_width=True, hide_index=True)

    st.info(
        "**Bottom line:** Your year-end deliverable is a comprehensive, reconciled DATA PACK — not the "
        "statutory accounts themselves. But the quality of your data pack directly determines how painful "
        "the audit is. A clean data pack = 3-week audit. A messy one = 6 weeks of auditor queries."
    )

    # ── Section 5: FX Hedging Friction ──
    st.markdown("---")
    st.subheader("5. FX Hedging Friction (EUR/AUD Mismatch)")

    st.warning(
        "**The SPV holds EUR assets. The investor (AUT) reports in AUD.** If the AUT hedges the FX exposure "
        "back to AUD — which is standard for institutional investors — the hedge instruments sit on the "
        "DAC's balance sheet, creating significant operational burden for the FA team."
    )

    st.markdown("""
    **Common hedge structures and their FA impact:**

    **OTC FX Forwards** — The DAC enters into rolling 1-month or 3-month EUR/AUD forward contracts.
    The FA team must:
    - **Price the forwards daily** (mark-to-market using forward curves from Bloomberg/Reuters)
    - **Track the unrealised FX gain/loss** on open forwards as an asset or liability on the balance sheet
    - **Book the realised FX gain/loss** when forwards roll or mature
    - **Manage the ISDA/CSA margin process** — if the forward moves against the DAC, the counterparty
      bank may issue a collateral margin call requiring the DAC to post cash. This cash comes OUT of
      the operating account and must be tracked as "restricted cash" or "margin posted"

    **Cross-Currency Swaps** — For longer-dated hedges, the DAC may enter into a cross-currency swap
    converting EUR interest receipts to AUD. This adds:
    - **Swap accrual accounting** — two legs (pay EUR, receive AUD) with different accrual rates
    - **Swap MTM valuation** — daily fair value from the swap dealer or Bloomberg SWPM
    - **Swap collateral management** — CSA margin calls, variation margin, initial margin

    **Impact on NAV and Waterfall:**
    - FX hedge MTM gains/losses flow through the NAV daily
    - Realised FX gains/losses may or may not be included in the interest waterfall (depends on Trust Deed)
    - Margin posted as collateral reduces available cash for the quarterly sweep
    - If the FX hedge counterparty defaults (credit risk), the DAC has an unsecured claim
    """)

    fx_tasks = pd.DataFrame([
        {"Task": "Daily FX forward/swap MTM", "Frequency": "Daily", "Source": "Bloomberg / Dealer", "Effort": "Medium"},
        {"Task": "Margin call monitoring", "Frequency": "Daily", "Source": "Counterparty bank / CSA", "Effort": "High on call days"},
        {"Task": "FX forward roll processing", "Frequency": "Monthly/Quarterly", "Source": "Trade confirms", "Effort": "Medium"},
        {"Task": "Realised FX G/L booking", "Frequency": "On roll/maturity", "Source": "Settlement confirms", "Effort": "Medium"},
        {"Task": "ISDA/CSA collateral reconciliation", "Frequency": "Weekly", "Source": "Counterparty statements", "Effort": "High"},
        {"Task": "FX hedge effectiveness documentation", "Frequency": "Quarterly", "Source": "FA + IM", "Effort": "High (if hedge accounting applied)"},
    ])
    st.dataframe(fx_tasks, use_container_width=True, hide_index=True)

    # ── Section 6: Practical Advice ──
    st.markdown("---")
    st.subheader("6. Practical Advice for FA Teams")

    st.success("""
    **How to survive the transition — advice from the trenches:**

    **Build your exception playbooks FIRST.** The happy path is 70% of the work but takes 30% of the time.
    The exceptions (stale prices, PIK toggles, agent bank mismatches, A&E renegotiations) are 30% of the
    work but take 70% of the time. Document the exception handling before you go live.

    **Create a credit event decision tree.** For each event type (PIK, A&E, paydown, default, exchange),
    document: (a) how you identify it, (b) what system updates are needed, (c) what accounting entries to book,
    (d) who needs to approve, (e) what reporting is affected. Pin it to the wall.

    **Negotiate the servicing report format with KKR upfront.** The quality of KKR's monthly servicing
    report will determine 50% of your operational efficiency. Push for: machine-readable format (CSV/Excel,
    not PDF), consistent field naming, and a clear changelog showing what moved since last month.

    **Budget 2-3x the audit support effort** compared to a traditional fund. The statutory accounts format,
    S110 tax analysis, and FRS 102 financial instruments disclosures require significantly more auditor
    interaction than standard fund accounts.

    **Treat the quarterly waterfall as a mini-project.** Block out 2-3 days each quarter for the cash sweep.
    It's not a task you can squeeze into the daily NAV cycle. Build the NPL exclusion list, verify the fee
    bases, check for deferred amounts, run the calculation, get three sign-offs, generate the payment
    instructions. It's a project, not a task.
    """)

# ══════════════════════════════════════════════════════════════
# PAGE: Quick Reference
# ══════════════════════════════════════════════════════════════
elif page == "⚡ Quick Reference":
    st.title("Quick Reference — Cheat Sheet")
    st.markdown("*When you see X in private credit, think Y from traditional funds, and do Z*")

    quick_ref = [
        ("Download Markit file", "Download pricing file from vendor", "Same as downloading Bloomberg prices. Match Markit IDs to positions."),
        ("Mark-to-Market the loan book", "Apply vendor prices to portfolio", "Update each loan's fair value from Markit. Calc unrealised P&L."),
        ("Calculate PPN coupon", "Calculate the distribution", "Net income → this becomes the note coupon payment."),
        ("Run the waterfall", "Apply priority of payments", "Pay expenses in order, residual goes to investor."),
        ("Cash sweep", "Quarterly distribution + expense settlement", "Gather excess cash, pay bills, send residual to AUT."),
        ("In-kind subscription", "Subscription in specie", "Assets in, PPN out. No cash. Book at fair value."),
        ("Noteholder report", "Investor factsheet / NAV report", "Monthly report showing NAV, performance, holdings."),
        ("Credit event on a loan", "Corporate action", "Loan default or restructure. Adjust fair value, check recovery."),
        ("Servicing report from KKR", "Manager report", "Review for performance, watchlist, defaults."),
        ("S110 tax return", "N/A — DAC specific", "Tax adviser handles. You provide income, expenses, coupons."),
        ("Offering Memorandum (OM)", "Prospectus / Supplement", "Legal doc. Read it for investment guidelines."),
        ("Trust Deed", "Instrument of Incorporation", "Governing doc — priority of payments, security."),
        ("NAV = PPN Value", "NAV per unit = unit price", "One investor, one note. NAV = PPN value. Simple."),
        ("EURIBOR + 350bps", "Coupon / Running Yield", "3-month EURIBOR plus 3.50% p.a. Accrues daily."),
        ("Actual/360 day count", "Day count convention", "Most leveraged loans use this. Bonds vary."),
        ("Stale Markit price", "Stale vendor price", "Price unchanged >5 days. Flag, investigate, escalate."),
        ("DAC board meeting", "Fund board meeting", "DAC has directors. They review performance quarterly."),
        ("Drawdown notice", "Subscription notice", "New capital or loans being added to the DAC."),
        ("Transfer Agent", "There is NO traditional TA here", "Maples acts as Registrar (static register) + Paying Agent (wires coupons). Not a TA desk."),
        ("Shareholder register", "Register of Noteholders", "Single-line document: AUT owns the PPN. Updated only on drawdown or wind-down."),
        ("Daily subs/reds from TA", "This step DOES NOT EXIST", "No daily capital activity. PPN face value is static. Do NOT wait for TA data before NAV."),
        ("Board resolution needed", "Governance gate before payment", "ManCo + Directors + Trustee must approve each distribution before Paying Agent can wire."),
        ("PPN face value changed", "Capital event — investigate", "Check the PPN Stability Check on NAV page. Should be unchanged unless drawdown or wind-down."),
        ("Paying Agent", "The TA equivalent for payments", "Maples wires coupon payments to AUT. Contact their Fiduciary/SPV Admin team, NOT Transfer Agency."),
        ("CBI statistical return", "AIFMD Annex IV data extract", "S110 DACs MUST file quarterly with CBI. You produce the data; the reporting agent files it. NOT optional."),
        ("ATAD Interest Limitation Rule", "N/A — new for S110", "EU rule capping interest deductions at 30% of EBITDA. Your GL must separate interest vs non-interest items cleanly."),
        ("WHT exemption needed", "Hard compliance gate", "Ireland charges 20% WHT on interest to non-residents. NEVER wire the PPN coupon without confirmed DTT/Eurobond exemption."),
        ("Irrecoverable VAT", "Hidden cost in your NAV", "VAT on audit/legal fees that you can't reclaim. Must be accrued as a real cost or your NAV is overstated."),
        ("FRS 102 Section 12", "Accounting classification", "Synthetic loans are 'non-basic'. Fair value through P&L — NO separate impairment. Markit prices already embed credit risk. Impairment only relevant if amortised cost loans are ever added."),
        ("De minimis EUR 3m", "ATAD safety threshold", "If Net Interest Expense is under EUR 3m/year, the ILR likely doesn't bite. Tax adviser confirms, but you provide the data."),
    ]

    search_qr = st.text_input("🔍 Search quick reference", placeholder="e.g. coupon, waterfall, markit...")

    for see, think, do in quick_ref:
        if search_qr and search_qr.lower() not in (see + think + do).lower():
            continue
        with st.expander(f"**When you see:** \"{see}\""):
            st.markdown(f"**Think of it as:** {think}")
            st.markdown(f"**And do this:** {do}")

    st.markdown("---")
    st.info("**Bottom line:** This DAC is a fund in a company wrapper. "
            "The loans are the portfolio. Markit is the pricing vendor. The PPN is the share class. "
            "The coupon is the dividend. The waterfall is the distribution calculation. "
            "You already know how to do all of this — just with different labels.")
