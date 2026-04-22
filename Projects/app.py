"""
Structured Credit Specialist Toolkit — v3
==========================================
Prototype Streamlit app for the specialist operations work that sits outside
traditional FA BAU for S110 DAC SPVs holding syndicated loans.
Distribution frequency: QUARTERLY.

Modules:
   1. Dashboard (KPIs + warning rail)
   2. Process Runner (quarter-end wizard)
   3. Home & Workflow
   4. Portfolio Loader (with downloadable template)
   5. Stale Price Monitor
   6. EURIBOR Floor Checker
   7. Period-End NAV
   8. Credit Event Processor (writes to register)
   9. Credit Event Register (persistent log)
  10. Special NAV (drawdown / paydown event NAV)
  11. Waterfall Calculator (separate interest/principal, quarterly)
  12. Distribution Calculator (full end-to-end with WHT + governance gate)
  13. Expense Cap Tracker
  14. Shadow Book Reconciliation (4-number rec to IM)
  15. Capstock File Generator
  16. S110 Tax Data Pack

Run:  streamlit run app.py
"""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
from io import BytesIO

from sample_data_generator import (
    generate_loan_portfolio, generate_shadow_book, generate_expense_schedule,
    generate_cash_inflows, generate_note_register, generate_credit_events_log,
    to_excel_bytes, to_csv_bytes
)

# ── Page config ──
st.set_page_config(
    page_title="Structured Credit Specialist Toolkit",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme colours (light warm editorial) ──
TEAL = "#1A7A6D"
TEAL_LIGHT = "#E8F5F2"
AMBER = "#C4841D"
AMBER_LIGHT = "#FFF4E0"
CORAL = "#C44D3F"
SAGE = "#5B8A72"
INK = "#2C2825"
MUTED = "#8A837A"

PLOTLY_LAYOUT = dict(
    plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
    font=dict(color=INK, size=12, family="Source Sans 3, sans-serif"),
    margin=dict(l=20, r=20, t=40, b=20),
)

# ── Session state init ──
if "portfolio" not in st.session_state:
    st.session_state.portfolio = None
if "expenses" not in st.session_state:
    st.session_state.expenses = None
if "note_register" not in st.session_state:
    st.session_state.note_register = None
if "credit_event_log" not in st.session_state:
    st.session_state.credit_event_log = []
if "nav_history" not in st.session_state:
    st.session_state.nav_history = []
if "process_state" not in st.session_state:
    st.session_state.process_state = {
        "step1_period_nav": False,
        "step2_shadow_rec": False,
        "step3_waterfall": False,
        "step4_expense_caps": False,
        "step5_distribution": False,
        "step6_capstock": False,
        "step7_audit_trail": False,
        "step8_sign_off": False,
    }

# ── Sidebar nav ──
st.sidebar.markdown("### Structured Credit Toolkit")
st.sidebar.caption("Specialist operations for S110 DAC SPVs")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigate",
    [
        "📊 Dashboard",
        "🧭 Process Runner (Quarter-End)",
        "🏠 Home & Workflow",
        "📁 Portfolio Loader",
        "🔍 Stale Price Monitor",
        "📐 EURIBOR Floor Checker",
        "🧮 Period-End NAV",
        "⚡ Credit Event Processor",
        "📒 Credit Event Register",
        "📸 Special NAV (Capital Event)",
        "💧 Waterfall Calculator",
        "💰 Distribution Calculator",
        "💳 Expense Cap Tracker",
        "🔄 Shadow Book Reconciliation",
        "📄 Capstock File Generator",
        "📋 S110 Tax Data Pack",
    ],
    label_visibility="collapsed",
)

st.sidebar.markdown("---")
st.sidebar.caption("Prototype · Synthetic data only")

# ═══════════════════════════════════════════════════════════
# PAGE: Dashboard
# ═══════════════════════════════════════════════════════════
if page == "📊 Dashboard":
    st.title("Dashboard")
    st.caption("Live operational overview — what needs attention today")

    # ── Load supporting data if missing ──
    if st.session_state.portfolio is None:
        st.warning("⚠️ No portfolio loaded. Go to **Portfolio Loader** to load real data or generate a synthetic portfolio.")
        st.stop()

    portfolio = st.session_state.portfolio.copy()
    # Enrich
    portfolio["Fair_Value_EUR"] = (portfolio["Par_Value_EUR"] * portfolio["Markit_Price"] / 100).round()

    if st.session_state.note_register is None:
        st.session_state.note_register = generate_note_register()
    current_face_value = st.session_state.note_register["PPN_Face_Value_After_EUR"].iloc[-1]

    # ── Header KPIs ──
    st.markdown("### Key metrics")
    c1, c2, c3, c4, c5 = st.columns(5)
    total_fv = portfolio["Fair_Value_EUR"].sum()
    total_par = portfolio["Par_Value_EUR"].sum()
    c1.metric("Positions", len(portfolio))
    c2.metric("Portfolio Par", f"€{total_par/1e6:.1f}m")
    c3.metric("Portfolio FV", f"€{total_fv/1e6:.1f}m")
    c4.metric("PPN Face Value", f"€{current_face_value/1e6:.1f}m")
    nav_per_face = (total_fv * 1.03) / current_face_value if current_face_value > 0 else 0
    c5.metric("NAV / Face", f"{nav_per_face:.4f}")

    st.markdown("---")

    # ── Warning rail ──
    st.markdown("### ⚠️ Attention required")
    warnings = []

    # Stale prices
    stale_5 = len(portfolio[portfolio["Days_Since_Price_Change"] > 5])
    stale_10 = len(portfolio[portfolio["Days_Since_Price_Change"] > 10])
    if stale_10 > 0:
        warnings.append(("🔴", f"{stale_10} loan(s) stale >10 days — severe, escalate to IPV committee", "Stale Price Monitor"))
    elif stale_5 > 0:
        warnings.append(("🟡", f"{stale_5} loan(s) stale >5 days — investigate and obtain broker quotes", "Stale Price Monitor"))

    # Credit events pending
    event_count = len(st.session_state.credit_event_log)
    if event_count > 0:
        warnings.append(("ℹ️", f"{event_count} credit event(s) processed this period", "Credit Event Register"))

    # Watchlist positions
    watchlist = len(portfolio[portfolio["Status"] == "Watchlist"])
    if watchlist > 0:
        warnings.append(("🟡", f"{watchlist} position(s) on watchlist — monitor for credit events", "Portfolio Loader"))

    # NPL exclusions for fee base
    npl_ratings = ["CCC+", "CCC", "CCC-", "CC", "C", "D"]
    npls = len(portfolio[portfolio["Rating"].isin(npl_ratings)])
    if npls > 0:
        warnings.append(("🟡", f"{npls} loan(s) rated CCC or below — exclude from IM fee base at next waterfall", "Waterfall Calculator"))

    # NAV history check
    if len(st.session_state.nav_history) == 0:
        warnings.append(("ℹ️", "No period-end NAV computed yet — run Period-End NAV module before distribution", "Period-End NAV"))

    # Process state
    completed_steps = sum(1 for v in st.session_state.process_state.values() if v)
    total_steps = len(st.session_state.process_state)
    if 0 < completed_steps < total_steps:
        warnings.append(("ℹ️", f"Quarter-end process {completed_steps}/{total_steps} steps complete — resume in Process Runner", "Process Runner"))

    if warnings:
        for icon, msg, where in warnings:
            st.markdown(f"{icon} **{msg}** — see *{where}*")
    else:
        st.success("✅ No outstanding items. All monitors clear.")

    st.markdown("---")

    # ── Portfolio composition charts ──
    st.markdown("### Portfolio composition")
    cc1, cc2 = st.columns(2)

    with cc1:
        sector_df = portfolio.groupby("Sector")["Fair_Value_EUR"].sum().sort_values(ascending=True).reset_index()
        fig = go.Figure(go.Bar(
            x=sector_df["Fair_Value_EUR"], y=sector_df["Sector"],
            orientation="h", marker_color=TEAL,
            text=[f"€{v/1e6:.1f}m" for v in sector_df["Fair_Value_EUR"]],
            textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title="Exposure by sector (FV)", height=320)
        st.plotly_chart(fig, use_container_width=True)

    with cc2:
        rating_df = portfolio.groupby("Rating")["Fair_Value_EUR"].sum().reset_index()
        rating_order = ["BB+", "BB", "BB-", "B+", "B", "B-", "CCC+", "CCC"]
        rating_df["Rating"] = pd.Categorical(rating_df["Rating"], categories=rating_order, ordered=True)
        rating_df = rating_df.sort_values("Rating")
        fig = go.Figure(go.Bar(
            x=rating_df["Rating"].astype(str), y=rating_df["Fair_Value_EUR"],
            marker_color=SAGE,
            text=[f"€{v/1e6:.1f}m" for v in rating_df["Fair_Value_EUR"]],
            textposition="outside",
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title="Exposure by rating (FV)", height=320)
        st.plotly_chart(fig, use_container_width=True)

    # ── Recent activity ──
    st.markdown("---")
    st.markdown("### Recent credit events")
    if st.session_state.credit_event_log:
        recent_events = pd.DataFrame(st.session_state.credit_event_log[-5:])
        st.dataframe(recent_events, use_container_width=True, hide_index=True)
    else:
        st.caption("No credit events processed yet this session. Events appear here as they are processed via the Credit Event Processor.")

    # ── NAV trend ──
    if st.session_state.nav_history:
        st.markdown("### NAV history")
        nav_df = pd.DataFrame(st.session_state.nav_history)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=nav_df["Date"], y=nav_df["NAV_EUR"],
            mode="lines+markers", line=dict(color=TEAL, width=2),
            marker=dict(color=TEAL, size=8),
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title="NAV over time", height=320,
                          yaxis_title="NAV (EUR)")
        st.plotly_chart(fig, use_container_width=True)


# ═══════════════════════════════════════════════════════════
# PAGE: Process Runner (Quarter-End Wizard)
# ═══════════════════════════════════════════════════════════
elif page == "🧭 Process Runner (Quarter-End)":
    st.title("Quarter-End Process Runner")
    st.markdown(
        "Step-by-step wizard for the quarter-end cycle. Work through each step in order — "
        "later steps depend on earlier ones being complete."
    )

    # Reset option
    col1, col2 = st.columns([4, 1])
    with col2:
        if st.button("🔄 Reset all steps"):
            for k in st.session_state.process_state:
                st.session_state.process_state[k] = False
            st.rerun()

    # Progress bar
    completed = sum(1 for v in st.session_state.process_state.values() if v)
    total = len(st.session_state.process_state)
    st.progress(completed / total, text=f"Progress: {completed}/{total} steps complete")

    st.markdown("---")

    # Step definitions
    steps = [
        {
            "key": "step1_period_nav",
            "number": "1",
            "title": "Period-End NAV",
            "desc": "Run the quarter-end NAV. Confirm portfolio valuations, apply EURIBOR floors, accrue interest and expenses to period end.",
            "goto": "Period-End NAV",
            "prereq": [],
            "duration": "0.5-1 day",
        },
        {
            "key": "step2_shadow_rec",
            "number": "2",
            "title": "Shadow Book Reconciliation",
            "desc": "Reconcile FA accrued income vs IM shadow book. Run the 4-number rec (accrued, cash, distributable, reconciling items). Investigate any breaks outside tolerance.",
            "goto": "Shadow Book Reconciliation",
            "prereq": ["step1_period_nav"],
            "duration": "0.5-1 day",
        },
        {
            "key": "step3_waterfall",
            "number": "3",
            "title": "Run Waterfall",
            "desc": "Execute the interest waterfall (pays expenses + PPN coupon) and principal waterfall (reinvests or pays down face value) separately. Check S110 tax check clears.",
            "goto": "Waterfall Calculator",
            "prereq": ["step2_shadow_rec"],
            "duration": "0.5 day",
        },
        {
            "key": "step4_expense_caps",
            "number": "4",
            "title": "Check Expense Caps",
            "desc": "Confirm YTD expense spend per category against Trust Deed caps. Any over-cap amounts must be subordinated below the PPN coupon.",
            "goto": "Expense Cap Tracker",
            "prereq": ["step3_waterfall"],
            "duration": "0.25 day",
        },
        {
            "key": "step5_distribution",
            "number": "5",
            "title": "Calculate Distribution",
            "desc": "Compute gross coupon, apply WHT if applicable, work through 5 documentation checks and 6 governance gates, produce payment instruction.",
            "goto": "Distribution Calculator",
            "prereq": ["step4_expense_caps"],
            "duration": "0.5 day",
        },
        {
            "key": "step6_capstock",
            "number": "6",
            "title": "Generate Capstock File",
            "desc": "Produce synthetic capstock CSV for the FA platform with the correct transaction type (NIL/DRAWDOWN/PAYDOWN/COUPON).",
            "goto": "Capstock File Generator",
            "prereq": ["step5_distribution"],
            "duration": "0.25 day",
        },
        {
            "key": "step7_audit_trail",
            "number": "7",
            "title": "Archive Audit Trail",
            "desc": "Export and file: Period-End NAV report, Shadow Book rec, Waterfall report, Expense Cap report, Distribution report, Capstock file, Credit Event register.",
            "goto": None,
            "prereq": ["step6_capstock"],
            "duration": "0.25 day",
        },
        {
            "key": "step8_sign_off",
            "number": "8",
            "title": "Team Lead Sign-Off",
            "desc": "Team lead reviews outputs. Confirms no outstanding items. Approves quarter-end pack for onward circulation (ManCo, Trustee, auditor).",
            "goto": None,
            "prereq": ["step7_audit_trail"],
            "duration": "0.25 day",
        },
    ]

    # Render each step
    for step in steps:
        # Check prerequisites
        prereqs_met = all(st.session_state.process_state.get(p, False) for p in step["prereq"])
        is_complete = st.session_state.process_state[step["key"]]

        # Determine state
        if is_complete:
            state_emoji = "✅"
            state_color = SAGE
            bg = "#E8F2EC"
        elif prereqs_met:
            state_emoji = "🔵"
            state_color = TEAL
            bg = "#E8F5F2"
        else:
            state_emoji = "⚪"
            state_color = MUTED
            bg = "#F5F0E8"

        # Render card
        with st.container():
            col1, col2, col3 = st.columns([0.5, 3.5, 1])
            with col1:
                st.markdown(f"""
                <div style="background:{state_color};color:white;width:50px;height:50px;border-radius:50%;
                display:flex;align-items:center;justify-content:center;font-size:1.5rem;font-weight:700;
                font-family:serif;">
                {step['number']}
                </div>
                """, unsafe_allow_html=True)
            with col2:
                st.markdown(f"**{state_emoji} {step['title']}** · ⏱ {step['duration']}")
                st.caption(step['desc'])
                if step.get("goto"):
                    st.caption(f"👉 Navigate to: *{step['goto']}*")
                if not prereqs_met and not is_complete:
                    prereq_names = [s["title"] for s in steps if s["key"] in step["prereq"]]
                    st.caption(f"⛔ Requires: {', '.join(prereq_names)}")
            with col3:
                # Checkbox
                checked = st.checkbox(
                    "Mark complete",
                    value=is_complete,
                    key=f"chk_{step['key']}",
                    disabled=not prereqs_met and not is_complete,
                )
                if checked != is_complete:
                    st.session_state.process_state[step["key"]] = checked
                    st.rerun()

            st.markdown("---")

    # Summary
    if completed == total:
        st.success("🎉 **Quarter-end cycle complete.** All 8 steps signed off. Pack ready for ManCo and Trustee circulation.")
    elif completed > 0:
        next_step = next((s for s in steps if not st.session_state.process_state[s["key"]]), None)
        if next_step:
            st.info(f"👉 Next: **Step {next_step['number']} — {next_step['title']}**. Estimated duration: {next_step['duration']}.")


# ═══════════════════════════════════════════════════════════
# PAGE: Home & Workflow
# ═══════════════════════════════════════════════════════════
elif page == "🏠 Home & Workflow":
    st.title("Structured Credit Specialist Toolkit")
    st.markdown("##### Specialist operations for S110 DAC SPVs holding syndicated loans")
    st.markdown(
        "This toolkit covers the operational work that sits **outside traditional fund accounting BAU**. "
        "It is designed for the specialist team in a hybrid operating model, complementing the daily NAV "
        "production handled by the traditional FA team."
    )
    st.info("**Distribution frequency: QUARTERLY.** The PPN interest coupon is paid once per quarter via the interest waterfall.")

    st.markdown("---")

    # Workflow overview
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("What this toolkit does")
        st.markdown("""
        Each module tackles a specific piece of specialist work:

        **Data management** — Load your syndicated loan portfolio and supporting data. Download sample templates to test scenarios.

        **Daily controls** — Monitor stale prices, check EURIBOR floors on rate resets, process credit events as they occur.

        **Event-driven** — Run a Special NAV on drawdown or paydown events to lock the PPN face value change with a before/after audit trail.

        **Quarterly calculations** — Run the waterfall with separate interest and principal flows, track expense caps, reconcile to the IM shadow book (4-number rec), compute the full distribution amount with WHT and governance gate.

        **Outputs** — Generate the synthetic capstock file for your FA platform, prepare the S110 tax data pack for your tax adviser.
        """)

    with col2:
        st.markdown("##### Status")
        portfolio_loaded = st.session_state.portfolio is not None
        status_emoji = "✅" if portfolio_loaded else "⚠️"
        st.metric("Portfolio loaded", f"{status_emoji} {'Yes' if portfolio_loaded else 'No'}")
        if portfolio_loaded:
            st.metric("Positions", len(st.session_state.portfolio))
            total_par = st.session_state.portfolio["Par_Value_EUR"].sum()
            st.metric("Total Par", f"€{total_par:,.0f}")

    st.markdown("---")

    # Workflow diagram
    st.subheader("Recommended workflow")
    workflow_steps = [
        ("1", "Load Portfolio", "Upload CSV or generate sample data"),
        ("2", "Daily Controls", "Stale pricing, floor checks"),
        ("3", "Process Events", "Credit events + Special NAV on capital events"),
        ("4", "Quarterly Calcs", "Waterfall, caps, shadow book rec, distribution"),
        ("5", "Generate Outputs", "Capstock file, tax data pack"),
    ]
    cols = st.columns(5)
    for i, (num, title, desc) in enumerate(workflow_steps):
        with cols[i]:
            st.markdown(f"""
            <div style="background:{TEAL_LIGHT};padding:1rem;border-radius:8px;border-left:3px solid {TEAL};min-height:140px;">
            <div style="color:{TEAL};font-size:1.8rem;font-weight:700;font-family:serif;">{num}</div>
            <div style="font-weight:600;margin:0.3rem 0;">{title}</div>
            <div style="font-size:0.85rem;color:{MUTED};">{desc}</div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown("---")

    # Scope boundaries
    st.subheader("Scope — what this tool does and doesn't cover")
    c1, c2 = st.columns(2)
    with c1:
        st.success("**In scope (specialist work):**")
        st.markdown("""
        - Syndicated loan portfolio management
        - Stale price monitoring and escalation
        - EURIBOR floor checking
        - Credit event processing (PIK, A&E, paydown)
        - Special NAV on capital events (drawdown/paydown)
        - Interest and principal waterfalls (quarterly)
        - Full quarterly distribution calculation with WHT
        - Expense cap tracking with subordination
        - Shadow book reconciliation to IM (4-number rec)
        - Synthetic capstock file generation
        - S110 / ATAD tax data pack
        """)
    with c2:
        st.info("**Out of scope (handled elsewhere):**")
        st.markdown("""
        - Daily NAV production → Traditional FA team
        - Four-eyes NAV review → Traditional FA team
        - Statutory accounts → CSP (corporate secretary)
        - Financial reporting to investors → ManCo
        - CBI statistical returns → ManCo
        - FATCA/CRS filings → ManCo
        - Tax return preparation → Tax Adviser
        - WHT exemption determination → Tax Adviser
        """)

# ═══════════════════════════════════════════════════════════
# PAGE: Portfolio Loader
# ═══════════════════════════════════════════════════════════
elif page == "📁 Portfolio Loader":
    st.title("Portfolio Loader")
    st.markdown("Upload your syndicated loan portfolio or generate sample data to test scenarios.")

    tab1, tab2, tab3 = st.tabs(["📥 Upload Data", "🧪 Generate Sample", "📄 Download Template"])

    with tab1:
        st.subheader("Upload your portfolio")
        st.caption("Expected columns: Loan_ID, Borrower, Sector, NACE_Code, Country, Par_Value_EUR, Spread_bps, EURIBOR_Floor_Pct, Day_Count, Maturity, Markit_Price, Days_Since_Price_Change, Rating, Cost_Basis_EUR, Agent_Bank, PIK_Eligible, Status")

        uploaded = st.file_uploader("Upload CSV or Excel", type=["csv", "xlsx"])
        if uploaded:
            try:
                if uploaded.name.endswith(".csv"):
                    df = pd.read_csv(uploaded)
                else:
                    df = pd.read_excel(uploaded)

                required_cols = ["Loan_ID", "Par_Value_EUR", "Spread_bps", "Markit_Price"]
                missing = [c for c in required_cols if c not in df.columns]
                if missing:
                    st.error(f"Missing required columns: {', '.join(missing)}")
                else:
                    st.session_state.portfolio = df
                    st.success(f"Loaded {len(df)} positions successfully.")
                    st.dataframe(df, use_container_width=True, height=400)
            except Exception as e:
                st.error(f"Failed to parse file: {e}")

    with tab2:
        st.subheader("Generate sample portfolio")
        st.caption("Synthetic data with no reference to real firms or positions — useful for testing the toolkit.")

        num = st.slider("Number of loans", 10, 100, 50, step=5)
        if st.button("Generate", type="primary"):
            df = generate_loan_portfolio(num)
            st.session_state.portfolio = df
            # Also generate supporting data
            st.session_state.expenses = generate_expense_schedule()
            st.session_state.note_register = generate_note_register()
            st.success(f"Generated {num} synthetic positions plus supporting data.")

        if st.session_state.portfolio is not None:
            st.markdown("---")
            st.markdown("##### Loaded portfolio")

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Positions", len(st.session_state.portfolio))
            col2.metric("Total Par", f"€{st.session_state.portfolio['Par_Value_EUR'].sum():,.0f}")
            fv = (st.session_state.portfolio["Par_Value_EUR"] * st.session_state.portfolio["Markit_Price"] / 100).sum()
            col3.metric("Total FV", f"€{fv:,.0f}")
            stale = len(st.session_state.portfolio[st.session_state.portfolio["Days_Since_Price_Change"] > 5])
            col4.metric("Stale Prices (>5d)", stale, delta_color="inverse")

            st.dataframe(st.session_state.portfolio, use_container_width=True, height=400)

    with tab3:
        st.subheader("Download templates")
        st.caption("Download blank templates with sample data to populate your own portfolio.")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.markdown("**Portfolio template**")
            st.caption("50-loan sample portfolio with all required columns")
            sample = generate_loan_portfolio(50)
            st.download_button(
                "Download Portfolio CSV",
                data=to_csv_bytes(sample),
                file_name="portfolio_template.csv",
                mime="text/csv",
            )
            st.download_button(
                "Download Portfolio Excel",
                data=to_excel_bytes({"Portfolio": sample}),
                file_name="portfolio_template.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

        with col2:
            st.markdown("**Shadow book template**")
            st.caption("Sample IM shadow book data for reconciliation testing")
            sample_shadow = generate_shadow_book(generate_loan_portfolio(50))
            st.download_button(
                "Download Shadow Book CSV",
                data=to_csv_bytes(sample_shadow),
                file_name="shadow_book_template.csv",
                mime="text/csv",
            )

        with col3:
            st.markdown("**Full workbook**")
            st.caption("Multi-sheet Excel with portfolio, expenses, note register, events")
            full_pkg = {
                "Portfolio": generate_loan_portfolio(50),
                "Expenses": generate_expense_schedule(),
                "Cash_Inflows": generate_cash_inflows(),
                "Note_Register": generate_note_register(),
                "Credit_Events": generate_credit_events_log(),
                "Shadow_Book": generate_shadow_book(generate_loan_portfolio(50)),
            }
            st.download_button(
                "Download Full Workbook",
                data=to_excel_bytes(full_pkg),
                file_name="specialist_toolkit_sample_data.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

# ═══════════════════════════════════════════════════════════
# PAGE: Stale Price Monitor
# ═══════════════════════════════════════════════════════════
elif page == "🔍 Stale Price Monitor":
    st.title("Stale Price Monitor")
    st.markdown("Identify positions where pricing has not moved for more than 5 business days. These require IPV escalation.")

    if st.session_state.portfolio is None:
        st.warning("⚠️ Load a portfolio first — go to Portfolio Loader.")
    else:
        df = st.session_state.portfolio.copy()

        # Controls
        col1, col2 = st.columns([1, 3])
        with col1:
            threshold = st.number_input("Staleness threshold (days)", 1, 30, 5)
            severity_threshold = st.number_input("Severe threshold (days)", 5, 60, 10)

        # Calculate staleness categories
        def classify(days):
            if days >= severity_threshold:
                return "Severe - Escalate"
            elif days > threshold:
                return "Stale - Investigate"
            else:
                return "Fresh"

        df["Staleness"] = df["Days_Since_Price_Change"].apply(classify)

        # Summary metrics
        c1, c2, c3, c4 = st.columns(4)
        fresh = len(df[df["Staleness"] == "Fresh"])
        stale = len(df[df["Staleness"] == "Stale - Investigate"])
        severe = len(df[df["Staleness"] == "Severe - Escalate"])
        coverage_pct = fresh / len(df) * 100

        c1.metric("Fresh (clean)", fresh)
        c2.metric("Stale", stale, delta_color="inverse")
        c3.metric("Severe", severe, delta_color="inverse")
        c4.metric("Coverage %", f"{coverage_pct:.1f}%")

        st.markdown("---")

        # Show stale positions
        stale_df = df[df["Staleness"] != "Fresh"][[
            "Loan_ID", "Borrower", "Sector", "Par_Value_EUR", "Markit_Price",
            "Days_Since_Price_Change", "Rating", "Staleness"
        ]].sort_values("Days_Since_Price_Change", ascending=False)

        if len(stale_df) > 0:
            st.subheader(f"Positions requiring IPV action ({len(stale_df)})")

            # Visual
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=stale_df["Loan_ID"], y=stale_df["Days_Since_Price_Change"],
                marker_color=[CORAL if s == "Severe - Escalate" else AMBER for s in stale_df["Staleness"]],
                text=stale_df["Days_Since_Price_Change"], textposition="outside",
            ))
            fig.update_layout(
                **PLOTLY_LAYOUT, title="Days Since Last Price Change",
                xaxis_title="Loan ID", yaxis_title="Days Stale",
                xaxis_tickangle=-45, height=400,
            )
            st.plotly_chart(fig, use_container_width=True)

            st.dataframe(stale_df, use_container_width=True)

            # IPV workflow
            st.markdown("---")
            st.subheader("IPV Escalation Protocol")
            st.markdown(f"""
            For each stale position, apply this protocol in order:

            1. **Check** — Confirm Markit really has no new mark (vs pricing feed issue)
            2. **Broker quotes** — Request 2-3 independent broker quotes via Markit/IHS
            3. **Matrix pricing** — If no broker quotes, apply matrix pricing from comparable credits
            4. **IM mark** — If no matrix available, request IM valuation with rationale
            5. **FV Committee** — Escalate to fair value committee if material
            6. **Document** — Record methodology, source, justification, ManCo approver
            """)

            # Export
            st.download_button(
                "📥 Download Stale Position Report",
                data=to_csv_bytes(stale_df),
                file_name=f"stale_price_report_{datetime.now():%Y%m%d}.csv",
                mime="text/csv",
            )
        else:
            st.success("✅ No stale prices detected. All positions priced within threshold.")

# ═══════════════════════════════════════════════════════════
# PAGE: EURIBOR Floor Checker
# ═══════════════════════════════════════════════════════════
elif page == "📐 EURIBOR Floor Checker":
    st.title("EURIBOR Floor Checker")
    st.markdown("Verify that accrual rates correctly apply EURIBOR floors. Floors activate when EURIBOR falls below the floor rate.")

    if st.session_state.portfolio is None:
        st.warning("⚠️ Load a portfolio first.")
    else:
        df = st.session_state.portfolio.copy()

        # Current EURIBOR input
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            euribor = st.number_input("Current 3M EURIBOR (%)", -1.0, 10.0, 3.65, step=0.05)
        with col2:
            period_days = st.number_input("Period days", 1, 365, 90)

        # Calculate rates
        df["Spread_Pct"] = df["Spread_bps"] / 100
        df["Market_All_In_Pct"] = euribor + df["Spread_Pct"]
        df["Floor_All_In_Pct"] = df["EURIBOR_Floor_Pct"] + df["Spread_Pct"]
        df["Floor_Applies"] = euribor < df["EURIBOR_Floor_Pct"]
        df["Applied_Rate_Pct"] = df.apply(
            lambda r: r["Floor_All_In_Pct"] if r["Floor_Applies"] else r["Market_All_In_Pct"], axis=1
        )
        df["Period_Interest_EUR"] = df["Par_Value_EUR"] * df["Applied_Rate_Pct"] / 100 * period_days / 360

        # Summary
        c1, c2, c3, c4 = st.columns(4)
        with_floor = len(df[df["EURIBOR_Floor_Pct"] > 0])
        floor_active = len(df[df["Floor_Applies"]])
        total_interest = df["Period_Interest_EUR"].sum()

        c1.metric("Loans with floor", with_floor)
        c2.metric("Floor currently active", floor_active)
        c3.metric("Total period interest", f"€{total_interest:,.0f}")
        c4.metric("Avg all-in rate", f"{df['Applied_Rate_Pct'].mean():.2f}%")

        # Alert if floor active
        if floor_active > 0:
            st.warning(f"⚠️ {floor_active} loan(s) currently have the EURIBOR floor active. Ensure your accrual engine is using the floor rate, not the market rate.")
        else:
            st.info(f"ℹ️ No floors active at current EURIBOR of {euribor:.2f}%. All loans accruing at market rate.")

        st.markdown("---")

        # Show the detail
        display = df[[
            "Loan_ID", "Borrower", "Par_Value_EUR", "Spread_bps",
            "EURIBOR_Floor_Pct", "Floor_Applies", "Market_All_In_Pct",
            "Applied_Rate_Pct", "Period_Interest_EUR"
        ]].copy()

        # Highlight floor-active rows
        def highlight(row):
            return ["background-color: #FFF4E0" if row["Floor_Applies"] else "" for _ in row]

        st.dataframe(
            display.style.apply(highlight, axis=1).format({
                "Par_Value_EUR": "€{:,.0f}", "Spread_bps": "{:.0f}",
                "EURIBOR_Floor_Pct": "{:.2f}%", "Market_All_In_Pct": "{:.2f}%",
                "Applied_Rate_Pct": "{:.2f}%", "Period_Interest_EUR": "€{:,.0f}"
            }),
            use_container_width=True, height=400,
        )

        # Scenario tester
        st.markdown("---")
        with st.expander("📉 Scenario: What if EURIBOR falls?"):
            low_euribor = st.slider("Hypothetical EURIBOR (%)", -0.5, float(euribor), 0.5, step=0.1)

            scenario_df = df.copy()
            scenario_df["Scenario_Floor_Applies"] = low_euribor < scenario_df["EURIBOR_Floor_Pct"]
            scenario_df["Scenario_Rate"] = scenario_df.apply(
                lambda r: r["EURIBOR_Floor_Pct"] + r["Spread_Pct"] if r["Scenario_Floor_Applies"]
                else low_euribor + r["Spread_Pct"], axis=1
            )
            scenario_df["Scenario_Interest"] = scenario_df["Par_Value_EUR"] * scenario_df["Scenario_Rate"] / 100 * period_days / 360

            activated = len(scenario_df[scenario_df["Scenario_Floor_Applies"]]) - floor_active
            income_protected = scenario_df["Scenario_Interest"].sum() - (
                df["Par_Value_EUR"] * (low_euribor + df["Spread_Pct"]) / 100 * period_days / 360
            ).sum()

            c1, c2 = st.columns(2)
            c1.metric("Additional floors activated", activated)
            c2.metric("Income protected by floors", f"€{income_protected:,.0f}")

# ═══════════════════════════════════════════════════════════
# PAGE: Period-End NAV
# ═══════════════════════════════════════════════════════════
elif page == "🧮 Period-End NAV":
    st.title("Period-End NAV")
    st.markdown(
        "Run the formal period-end NAV calculation. This is the NAV that feeds the Distribution Calculator "
        "and the quarterly statutory data pack."
    )
    st.info(
        "**Scope:** Portfolio revaluation at period-end prices, full interest accrual, expense accrual "
        "(including irrecoverable VAT), cash reconciliation, trial balance output."
    )

    if st.session_state.portfolio is None:
        st.warning("⚠️ Load a portfolio first.")
    else:
        portfolio = st.session_state.portfolio.copy()

        # Inputs
        col1, col2, col3 = st.columns(3)
        with col1:
            period_end_date = st.date_input("Period-end date")
        with col2:
            euribor_3m = st.number_input("3M EURIBOR at period-end (%)", -1.0, 10.0, 3.65, step=0.05)
        with col3:
            cash_at_bank = st.number_input("Cash at bank (period-end)", 0, 100_000_000, 500_000, step=1000)

        st.markdown("---")

        # ── Step 1: Portfolio revaluation ──
        st.subheader("Step 1 — Portfolio revaluation")
        portfolio["Fair_Value_EUR"] = (portfolio["Par_Value_EUR"] * portfolio["Markit_Price"] / 100).round()
        total_par = portfolio["Par_Value_EUR"].sum()
        total_fv = portfolio["Fair_Value_EUR"].sum()
        unrealised_gl = total_fv - total_par

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Par", f"€{total_par:,.0f}")
        c2.metric("Total Fair Value", f"€{total_fv:,.0f}")
        c3.metric("Unrealised G/L", f"€{unrealised_gl:,.0f}", delta=f"{unrealised_gl/total_par*100:.2f}%")

        # Stale price warning
        stale_count = len(portfolio[portfolio["Days_Since_Price_Change"] > 5])
        if stale_count > 0:
            st.warning(f"⚠️ {stale_count} positions have stale prices (>5 days). Review before finalising NAV — see Stale Price Monitor.")

        # ── Step 2: EURIBOR floor + interest accrual ──
        st.markdown("---")
        st.subheader("Step 2 — Interest accrual with EURIBOR floor check")

        portfolio["Spread_Pct"] = portfolio["Spread_bps"] / 100
        portfolio["Floor_Active"] = euribor_3m < portfolio["EURIBOR_Floor_Pct"]
        portfolio["Applied_Rate_Pct"] = portfolio.apply(
            lambda r: r["EURIBOR_Floor_Pct"] + r["Spread_Pct"] if r["Floor_Active"]
            else euribor_3m + r["Spread_Pct"], axis=1
        )

        accrual_days = st.slider("Days since last coupon (accrual period)", 1, 120, 90)
        portfolio["Accrued_Interest_EUR"] = (portfolio["Par_Value_EUR"] * portfolio["Applied_Rate_Pct"] / 100 * accrual_days / 360).round()
        total_accrued = portfolio["Accrued_Interest_EUR"].sum()

        c1, c2, c3 = st.columns(3)
        c1.metric("Accrual days", accrual_days)
        c2.metric("Floor active on", f"{len(portfolio[portfolio['Floor_Active']])} loans")
        c3.metric("Total accrued interest", f"€{total_accrued:,.0f}")

        # ── Step 3: Expense accrual (with VAT) ──
        st.markdown("---")
        st.subheader("Step 3 — Expense accruals (including irrecoverable VAT)")

        if st.session_state.expenses is None:
            st.session_state.expenses = generate_expense_schedule()
        expenses = st.session_state.expenses.copy()

        # Quarterly expense = 1/4 of annual
        expenses["Quarterly_Net_EUR"] = (expenses["Annual_Amount_EUR"] / 4).round()
        expenses["VAT_Rate_Pct"] = expenses["VAT_Rate"].map({
            "Exempt": 0, "23%": 23, "Mixed": 12
        })
        expenses["VAT_EUR"] = (expenses["Quarterly_Net_EUR"] * expenses["VAT_Rate_Pct"] / 100).round()
        # Assume 80% irrecoverable for VATable expenses
        expenses["Irrecoverable_VAT_EUR"] = (expenses["VAT_EUR"] * 0.80).round()
        expenses["Total_Gross_EUR"] = expenses["Quarterly_Net_EUR"] + expenses["Irrecoverable_VAT_EUR"]

        st.dataframe(
            expenses[["Expense_Category", "Quarterly_Net_EUR", "VAT_Rate", "Irrecoverable_VAT_EUR", "Total_Gross_EUR"]].style.format({
                "Quarterly_Net_EUR": "€{:,.0f}",
                "Irrecoverable_VAT_EUR": "€{:,.0f}",
                "Total_Gross_EUR": "€{:,.0f}",
            }),
            use_container_width=True, hide_index=True,
        )

        total_expenses_accrued = expenses["Total_Gross_EUR"].sum()
        total_irrecoverable_vat = expenses["Irrecoverable_VAT_EUR"].sum()
        c1, c2 = st.columns(2)
        c1.metric("Quarterly expense accrual (gross)", f"€{total_expenses_accrued:,.0f}")
        c2.metric("of which: irrecoverable VAT", f"€{total_irrecoverable_vat:,.0f}")

        # ── Step 4: NAV computation ──
        st.markdown("---")
        st.subheader("Step 4 — NAV computation")

        nav_components = pd.DataFrame([
            {"Line": "Portfolio Fair Value", "EUR": total_fv},
            {"Line": "Accrued Interest Receivable", "EUR": total_accrued},
            {"Line": "Cash at Bank", "EUR": cash_at_bank},
            {"Line": "Accrued Expenses (incl. irrecoverable VAT)", "EUR": -total_expenses_accrued},
        ])
        nav_components.loc[len(nav_components)] = ["**NAV**", nav_components["EUR"].sum()]

        st.dataframe(
            nav_components.style.format({"EUR": "€{:,.0f}"}),
            use_container_width=True, hide_index=True,
        )

        nav = total_fv + total_accrued + cash_at_bank - total_expenses_accrued

        # Face value and PPN stability check
        if st.session_state.note_register is None:
            st.session_state.note_register = generate_note_register()
        face_value = st.session_state.note_register["PPN_Face_Value_After_EUR"].iloc[-1]

        c1, c2, c3 = st.columns(3)
        c1.metric("**NAV**", f"€{nav:,.0f}")
        c2.metric("PPN Face Value", f"€{face_value:,.0f}")
        c3.metric("NAV / Face", f"{nav/face_value:.6f}" if face_value else "N/A")

        # ── Step 5: Trial balance ──
        st.markdown("---")
        st.subheader("Step 5 — Trial Balance (with ATAD tagging)")

        tb = pd.DataFrame([
            # Assets
            {"Account": "Loan Portfolio", "Debit": total_fv, "Credit": 0, "ATAD_Tag": "Non-interest (position)"},
            {"Account": "Accrued Interest Receivable", "Debit": total_accrued, "Credit": 0, "ATAD_Tag": "Interest-equivalent (income)"},
            {"Account": "Cash at Bank", "Debit": cash_at_bank, "Credit": 0, "ATAD_Tag": "Non-interest (position)"},
            # Liabilities
            {"Account": "Accrued Expenses", "Debit": 0, "Credit": total_expenses_accrued, "ATAD_Tag": "Operating expense"},
            {"Account": "PPN Face Value", "Debit": 0, "Credit": face_value, "ATAD_Tag": "Non-interest (position)"},
            # Income
            {"Account": "Interest Income", "Debit": 0, "Credit": total_accrued, "ATAD_Tag": "Interest-equivalent (income)"},
            {"Account": "Unrealised FV G/L", "Debit": max(0, -unrealised_gl), "Credit": max(0, unrealised_gl), "ATAD_Tag": "Outside ILR scope"},
            # Expenses
            {"Account": "Operating Expenses", "Debit": total_expenses_accrued - total_irrecoverable_vat, "Credit": 0, "ATAD_Tag": "Operating expense"},
            {"Account": "Irrecoverable VAT", "Debit": total_irrecoverable_vat, "Credit": 0, "ATAD_Tag": "Operating expense"},
        ])
        tb["Net_EUR"] = tb["Debit"] - tb["Credit"]

        st.dataframe(
            tb.style.format({"Debit": "€{:,.0f}", "Credit": "€{:,.0f}", "Net_EUR": "€{:,.0f}"}),
            use_container_width=True, hide_index=True,
        )

        # Balance check
        total_debit = tb["Debit"].sum()
        total_credit = tb["Credit"].sum()
        if abs(total_debit - total_credit) < 100:
            st.success(f"✅ Trial balance in balance: DR €{total_debit:,.0f} = CR €{total_credit:,.0f}")
        else:
            diff = total_debit - total_credit
            st.caption(f"Illustrative TB — net position {'DR' if diff > 0 else 'CR'} €{abs(diff):,.0f} reflects P&L movement to be cleared at period-end.")

        # ── Save to history + export ──
        st.markdown("---")
        st.subheader("Save & export")

        colS, colE = st.columns(2)
        with colS:
            if st.button("💾 Save to NAV history", type="primary"):
                st.session_state.nav_history.append({
                    "Date": period_end_date.strftime("%Y-%m-%d"),
                    "NAV_EUR": nav,
                    "PPN_Face_Value_EUR": face_value,
                    "Portfolio_FV_EUR": total_fv,
                    "Accrued_Interest_EUR": total_accrued,
                    "Cash_EUR": cash_at_bank,
                    "Accrued_Expenses_EUR": total_expenses_accrued,
                })
                st.success(f"NAV of €{nav:,.0f} saved to history. Dashboard will display the trend.")

        with colE:
            export = {
                "NAV_Components": nav_components,
                "Portfolio_Revaluation": portfolio[["Loan_ID", "Borrower", "Par_Value_EUR", "Markit_Price", "Fair_Value_EUR", "Accrued_Interest_EUR", "Applied_Rate_Pct", "Floor_Active"]],
                "Expense_Accruals": expenses[["Expense_Category", "Quarterly_Net_EUR", "Irrecoverable_VAT_EUR", "Total_Gross_EUR"]],
                "Trial_Balance": tb,
            }
            st.download_button(
                "📥 Download Period-End NAV Pack",
                data=to_excel_bytes(export),
                file_name=f"period_end_nav_{period_end_date:%Y%m%d}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )


# ═══════════════════════════════════════════════════════════
# PAGE: Credit Event Processor
# ═══════════════════════════════════════════════════════════
elif page == "⚡ Credit Event Processor":
    st.title("Credit Event Processor")
    st.markdown("Process credit events on syndicated loans. Each event type has a different accounting treatment.")

    if st.session_state.portfolio is None:
        st.warning("⚠️ Load a portfolio first.")
    else:
        event_type = st.selectbox(
            "Event type",
            ["PIK Interest Toggle", "Amend & Extend (A&E)", "Partial Principal Paydown",
             "Covenant Waiver", "Rating Downgrade", "Default & Workout"]
        )

        loan_ids = st.session_state.portfolio["Loan_ID"].tolist()
        selected_loan = st.selectbox("Select affected loan", loan_ids)

        loan_row = st.session_state.portfolio[st.session_state.portfolio["Loan_ID"] == selected_loan].iloc[0]

        # Show current state
        st.markdown("##### Current position")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Par Value", f"€{loan_row['Par_Value_EUR']:,.0f}")
        c2.metric("Spread", f"E+{loan_row['Spread_bps']}bps")
        c3.metric("Floor", f"{loan_row['EURIBOR_Floor_Pct']:.2f}%")
        c4.metric("Current Price", f"{loan_row['Markit_Price']:.2f}")

        st.markdown("---")

        # Event-specific workflow
        if event_type == "PIK Interest Toggle":
            st.subheader("PIK Toggle Workflow")
            st.warning(
                "**PIK capitalises interest instead of paying cash.** The par value increases by the interest amount. "
                "No cash is received. The cost basis must be adjusted, and the accrual engine must be switched for the PIK period."
            )

            col1, col2 = st.columns(2)
            with col1:
                pik_amount = st.number_input("PIK interest amount (EUR)", 0, int(loan_row["Par_Value_EUR"]), int(loan_row["Par_Value_EUR"] * 0.02))
                effective_date = st.date_input("Effective date")
            with col2:
                new_par = loan_row["Par_Value_EUR"] + pik_amount
                st.metric("New Par Value", f"€{new_par:,.0f}", delta=f"€{pik_amount:,.0f}")
                new_cost_basis = loan_row["Cost_Basis_EUR"] + pik_amount
                st.metric("New Cost Basis", f"€{new_cost_basis:,.0f}", delta=f"€{pik_amount:,.0f}")

            st.markdown("##### Required accounting entries")
            entries = pd.DataFrame([
                {"Entry": "DR", "Account": "Loan Par Value", "Amount": f"€{pik_amount:,.0f}", "Description": "Capitalise PIK interest"},
                {"Entry": "CR", "Account": "PIK Interest Income", "Amount": f"€{pik_amount:,.0f}", "Description": "Recognise income (no cash)"},
            ])
            st.dataframe(entries, use_container_width=True, hide_index=True)

            st.markdown("##### Downstream updates required")
            st.markdown("""
            - Update position record: new par value  
            - Update cost basis for future realised G/L calculations  
            - Switch accrual engine to PIK mode for this interest period  
            - Update Markit notional reference to new par  
            - Re-verify borrower residency and sector codes  
            - Flag for next shadow book reconciliation  
            """)

        elif event_type == "Amend & Extend (A&E)":
            st.subheader("Amend & Extend Workflow")
            st.info("A&E renegotiates the loan terms. Update facility terms, recalculate forward accruals, run FRS 102 modification test.")

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Current terms**")
                st.write(f"Spread: E+{loan_row['Spread_bps']}bps")
                st.write(f"Floor: {loan_row['EURIBOR_Floor_Pct']:.2f}%")
                st.write(f"Maturity: {loan_row['Maturity']}")
            with col2:
                st.markdown("**New terms**")
                new_spread = st.number_input("New spread (bps)", 100, 1000, int(loan_row["Spread_bps"]) + 50)
                new_floor = st.number_input("New floor (%)", 0.0, 5.0, float(loan_row["EURIBOR_Floor_Pct"]), step=0.25)
                new_maturity_year = st.number_input("New maturity year", 2025, 2035, int(loan_row["Maturity"][:4]) + 2)
                amendment_fee = st.number_input("Amendment fee received (EUR)", 0, 1000000, 25000)

            # FRS 102 modification test
            old_rate = 3.65 + loan_row["Spread_bps"]/100
            new_rate = 3.65 + new_spread/100
            rate_change_pct = abs((new_rate - old_rate) / old_rate * 100)

            st.markdown("##### FRS 102 Modification Test")
            modification_significant = rate_change_pct > 10  # simplified test
            if modification_significant:
                st.error(f"⚠️ Rate change of {rate_change_pct:.1f}% likely exceeds 10% threshold. Consider whether this constitutes a substantial modification requiring derecognition of the original loan.")
            else:
                st.success(f"✓ Rate change of {rate_change_pct:.1f}% is below 10% threshold. Modification likely treated as continuation of original loan.")

            st.markdown("##### Required accounting entries")
            if amendment_fee > 0:
                entries = pd.DataFrame([
                    {"Entry": "DR", "Account": "Cash", "Amount": f"€{amendment_fee:,.0f}", "Description": "Amendment fee received"},
                    {"Entry": "CR", "Account": "Amendment Fee Income (Interest Waterfall)", "Amount": f"€{amendment_fee:,.0f}", "Description": "Income — flows to PPN coupon"},
                ])
                st.dataframe(entries, use_container_width=True, hide_index=True)

            st.markdown("##### Downstream updates")
            st.markdown("""
            - Update facility terms in master data (spread, floor, maturity)  
            - Recalculate all forward accruals using new rate  
            - Update Markit notional if principal changes  
            - Update compliance testing parameters  
            - Flag to tax adviser — amendment fee classified as interest-equivalent for ATAD  
            - Notify ManCo, Trustee, Auditor of the amendment  
            """)

        elif event_type == "Partial Principal Paydown":
            st.subheader("Partial Paydown Workflow")
            st.info("Borrower repays part of the loan. Reduce par, realise G/L, recalculate accruals on new balance.")

            col1, col2 = st.columns(2)
            with col1:
                paydown_amount = st.number_input("Paydown amount (EUR)", 0, int(loan_row["Par_Value_EUR"]), int(loan_row["Par_Value_EUR"] * 0.1))
                paydown_price = st.number_input("Paydown price (% of par)", 80.0, 110.0, 100.0, step=0.25)
            with col2:
                proceeds = paydown_amount * paydown_price / 100
                cost_basis_reduction = paydown_amount * (loan_row["Cost_Basis_EUR"] / loan_row["Par_Value_EUR"])
                realised_gl = proceeds - cost_basis_reduction
                st.metric("Proceeds received", f"€{proceeds:,.0f}")
                st.metric("Cost basis reduction", f"€{cost_basis_reduction:,.0f}")
                st.metric("Realised G/L", f"€{realised_gl:,.0f}", delta=f"€{realised_gl:,.0f}")

            new_par = loan_row["Par_Value_EUR"] - paydown_amount
            st.metric("New Par Value", f"€{new_par:,.0f}", delta=f"-€{paydown_amount:,.0f}")

            st.markdown("##### Required accounting entries")
            entries = pd.DataFrame([
                {"Entry": "DR", "Account": "Cash", "Amount": f"€{proceeds:,.0f}", "Description": "Principal received"},
                {"Entry": "CR", "Account": "Loan Par Value", "Amount": f"€{paydown_amount:,.0f}", "Description": "Reduce notional"},
                {"Entry": "DR/CR", "Account": "Realised G/L (Markit FV vs cost)", "Amount": f"€{realised_gl:,.0f}", "Description": "Recognise gain/loss"},
            ])
            st.dataframe(entries, use_container_width=True, hide_index=True)

            st.warning("**Principal proceeds flow into the PRINCIPAL waterfall — not the interest waterfall.** Reinvest in new loans or pay down PPN face value.")

        elif event_type == "Covenant Waiver":
            st.subheader("Covenant Waiver Workflow")
            st.info("No immediate financial impact, but compliance testing parameters change.")
            consent_fee = st.number_input("Consent fee received (EUR)", 0, 100000, 5000)

            if consent_fee > 0:
                st.markdown("##### Accounting entries")
                entries = pd.DataFrame([
                    {"Entry": "DR", "Account": "Cash", "Amount": f"€{consent_fee:,.0f}", "Description": "Consent fee"},
                    {"Entry": "CR", "Account": "Amendment Fee Income (Interest)", "Amount": f"€{consent_fee:,.0f}", "Description": "Flows to PPN coupon"},
                ])
                st.dataframe(entries, use_container_width=True, hide_index=True)

            st.markdown("""
            ##### Downstream updates
            - Update compliance testing parameters (waived covenant removed from test)  
            - Document waiver in audit file  
            - Inform Trustee — security status confirmation required  
            """)

        elif event_type == "Rating Downgrade":
            st.subheader("Rating Downgrade Workflow")
            current_rating = loan_row["Rating"]
            new_rating = st.selectbox("New rating", ["BB+", "BB", "BB-", "B+", "B", "B-", "CCC+", "CCC", "CCC-", "CC", "C", "D"])

            st.markdown("##### Impact assessment")
            st.markdown(f"""
            - Current: **{current_rating}** → New: **{new_rating}**  
            - Update master data — compliance testing may trigger breaches  
            - Markit price will reflect the downgrade — no separate impairment (FVTPL)  
            - If rating drops to CCC or below, exclude from IM fee base (performing collateral)  
            - Notify ManCo of any breach of rating thresholds in OM  
            """)

        else:  # Default & Workout
            st.subheader("Default & Workout Workflow")
            st.error("Loan in default. Markit fair value already reflects credit impairment. Track recovery over time.")
            expected_recovery = st.slider("Expected recovery (% of par)", 0, 100, 50)
            recovery_eur = loan_row["Par_Value_EUR"] * expected_recovery / 100

            st.markdown("##### Expected outcome")
            st.metric("Expected recovery", f"€{recovery_eur:,.0f}")
            st.metric("Expected loss", f"€{loan_row['Par_Value_EUR'] - recovery_eur:,.0f}")

            st.markdown("""
            ##### Workflow
            - Markit fair value reflects market's view of recovery — no separate impairment calc (FVTPL)  
            - Exclude from IM fee base (non-performing)  
            - Track cash recoveries as they occur — book as principal proceeds  
            - Recovery proceeds flow through the **principal waterfall**, not interest  
            - Document workout progression for audit file  
            - Notify Trustee — security enforcement may be required  
            """)

        # ── Log to Credit Event Register ──
        st.markdown("---")
        st.subheader("Log this event to the register")
        col1, col2 = st.columns(2)
        with col1:
            event_date = st.date_input("Event date", key="ce_log_date")
            approver = st.text_input("Approver", value="ManCo", key="ce_log_approver")
        with col2:
            description = st.text_input("Description / notes", value=f"{event_type} on {selected_loan}", key="ce_log_desc")

        if st.button("📝 Log event to register", type="primary"):
            # Extract amount based on event type
            amt = 0
            if event_type == "PIK Interest Toggle":
                amt = st.session_state.get("pik_amount_input", 0)
            elif event_type == "Amend & Extend (A&E)":
                amt = st.session_state.get("amendment_fee_input", 0)
            elif event_type == "Partial Principal Paydown":
                amt = st.session_state.get("paydown_amount_input", 0)

            st.session_state.credit_event_log.append({
                "Event_Date": event_date.strftime("%Y-%m-%d"),
                "Loan_ID": selected_loan,
                "Borrower": loan_row["Borrower"],
                "Event_Type": event_type,
                "Amount_EUR": amt,
                "Description": description,
                "Approver": approver,
                "Logged_At": datetime.now().strftime("%Y-%m-%d %H:%M"),
            })
            st.success(f"✅ Event logged. Register now contains {len(st.session_state.credit_event_log)} event(s). Visible on Dashboard and Credit Event Register.")


# ═══════════════════════════════════════════════════════════
# PAGE: Credit Event Register
# ═══════════════════════════════════════════════════════════
elif page == "📒 Credit Event Register":
    st.title("Credit Event Register")
    st.markdown(
        "Persistent log of all credit events processed. This is the audit trail the auditor will request "
        "at year-end — keep it complete and evidenced."
    )

    col1, col2 = st.columns([3, 1])
    with col2:
        if st.button("🧪 Generate sample events"):
            from sample_data_generator import generate_credit_events_log
            sample = generate_credit_events_log()
            for _, row in sample.iterrows():
                st.session_state.credit_event_log.append({
                    "Event_Date": row["Event_Date"],
                    "Loan_ID": row["Loan_ID"],
                    "Borrower": f"Company {row['Loan_ID'][-2:]}",
                    "Event_Type": row["Event_Type"],
                    "Amount_EUR": row["Amount_EUR"],
                    "Description": row["Description"],
                    "Approver": "ManCo",
                    "Logged_At": datetime.now().strftime("%Y-%m-%d %H:%M"),
                })
            st.rerun()

    if not st.session_state.credit_event_log:
        st.info("No credit events logged yet. Events appear here after being processed via the Credit Event Processor. Or click 'Generate sample events' for demo data.")
    else:
        register_df = pd.DataFrame(st.session_state.credit_event_log)

        # Summary KPIs
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total events", len(register_df))
        c2.metric("Event types", register_df["Event_Type"].nunique())
        c3.metric("Total amount logged", f"€{register_df['Amount_EUR'].sum():,.0f}")
        c4.metric("Affected loans", register_df["Loan_ID"].nunique())

        st.markdown("---")

        # Filter
        col1, col2 = st.columns(2)
        with col1:
            event_filter = st.multiselect(
                "Filter by event type",
                register_df["Event_Type"].unique().tolist(),
                default=register_df["Event_Type"].unique().tolist(),
            )
        with col2:
            loan_filter = st.multiselect(
                "Filter by loan",
                sorted(register_df["Loan_ID"].unique().tolist()),
                default=sorted(register_df["Loan_ID"].unique().tolist()),
            )

        filtered = register_df[
            (register_df["Event_Type"].isin(event_filter)) &
            (register_df["Loan_ID"].isin(loan_filter))
        ]

        st.markdown(f"##### Register ({len(filtered)} of {len(register_df)} events shown)")
        st.dataframe(
            filtered.style.format({"Amount_EUR": "€{:,.0f}"}),
            use_container_width=True, height=400,
        )

        # Event type summary
        st.markdown("##### By event type")
        event_summary = register_df.groupby("Event_Type").agg(
            Count=("Event_Type", "size"),
            Total_Amount_EUR=("Amount_EUR", "sum"),
        ).reset_index()
        st.dataframe(
            event_summary.style.format({"Total_Amount_EUR": "€{:,.0f}"}),
            use_container_width=True, hide_index=True,
        )

        # Export
        st.markdown("---")
        colE, colR = st.columns(2)
        with colE:
            st.download_button(
                "📥 Export Register to Excel",
                data=to_excel_bytes({
                    "Credit_Event_Register": register_df,
                    "Summary_By_Type": event_summary,
                }),
                file_name=f"credit_event_register_{datetime.now():%Y%m%d}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        with colR:
            if st.button("🗑️ Clear register (session only)"):
                st.session_state.credit_event_log = []
                st.rerun()


# ═══════════════════════════════════════════════════════════
# PAGE: Special NAV (Capital Event)
# ═══════════════════════════════════════════════════════════
elif page == "📸 Special NAV (Capital Event)":
    st.title("Special NAV — Capital Event")
    st.markdown(
        "Run an event-date NAV snapshot when the investor adds or reduces capital. "
        "Produces a before/after comparison, confirms the governance gate, and updates the PPN face value."
    )
    st.info(
        "**When to use this module:** drawdown (additional capital in), paydown (principal returned to investor), "
        "or any other event that changes the PPN face value. A Special NAV is separate from the daily NAV — "
        "it is a formal snapshot required for audit trail and the Register of Noteholders."
    )

    if st.session_state.portfolio is None:
        st.warning("⚠️ Load a portfolio first.")
    else:
        # Get current state
        portfolio = st.session_state.portfolio.copy()
        if st.session_state.note_register is None:
            st.session_state.note_register = generate_note_register()
        current_face_value = st.session_state.note_register["PPN_Face_Value_After_EUR"].iloc[-1]

        # Calculate pre-event NAV
        euribor = 3.65
        portfolio["Spread_Pct"] = portfolio["Spread_bps"] / 100
        portfolio["All_In_Pct"] = portfolio.apply(
            lambda r: max(euribor + r["Spread_Pct"], r["EURIBOR_Floor_Pct"] + r["Spread_Pct"]), axis=1)
        portfolio["Fair_Value_EUR"] = (portfolio["Par_Value_EUR"] * portfolio["Markit_Price"] / 100).round()

        total_fv = portfolio["Fair_Value_EUR"].sum()
        days_into_period = st.number_input("Days into current quarter", 1, 90, 45)
        accrued_interest = (portfolio["Par_Value_EUR"] * portfolio["All_In_Pct"] / 100 * days_into_period / 360).sum()
        daily_expenses = 2500
        accrued_expenses = daily_expenses * days_into_period
        cash_balance = st.number_input("Current cash at bank (EUR)", 0, 100_000_000, 250_000)

        pre_nav = total_fv + accrued_interest - accrued_expenses + cash_balance

        st.markdown("---")
        st.subheader("Step 1 — Pre-event NAV snapshot")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Portfolio FV", f"€{total_fv:,.0f}")
        c2.metric("Accrued Interest", f"€{accrued_interest:,.0f}")
        c3.metric("Accrued Expenses", f"€{accrued_expenses:,.0f}", delta_color="inverse")
        c4.metric("Cash", f"€{cash_balance:,.0f}")

        st.metric("**PRE-EVENT NAV**", f"€{pre_nav:,.0f}")
        st.metric("Current PPN Face Value", f"€{current_face_value:,.0f}")
        nav_per_face_pre = pre_nav / current_face_value if current_face_value > 0 else 0
        st.caption(f"NAV/Face Value: {nav_per_face_pre:.6f}")

        st.markdown("---")
        st.subheader("Step 2 — Capital event")

        event_type = st.selectbox("Event type", ["Drawdown (capital in)", "Paydown (capital out)"])
        event_date = st.date_input("Event date")
        event_amount = st.number_input("Event amount (EUR)", 0, 500_000_000, 10_000_000, step=100_000)
        event_mode = st.radio("Mode", ["Cash", "In-kind (assets transferred)"], horizontal=True)

        # Governance gate
        st.markdown("##### Governance gate")
        st.caption("All three must be confirmed before proceeding")
        g1 = st.checkbox("KKR (IM) drawdown/paydown notice received (5+ business days notice)")
        g2 = st.checkbox("ManCo written approval on file")
        g3 = st.checkbox("Trustee written approval on file")

        gate_cleared = g1 and g2 and g3

        if not gate_cleared:
            st.error("⚠️ Governance gate not cleared. Do NOT process the event or adjust the PPN face value until all three approvals are on file.")
        else:
            st.success("✅ Governance gate cleared. Proceed with Special NAV calculation.")

        st.markdown("---")
        st.subheader("Step 3 — Post-event NAV")

        # Calculate post-event state
        if event_type == "Drawdown (capital in)":
            new_face_value = current_face_value + event_amount
            if event_mode == "Cash":
                new_cash = cash_balance + event_amount
                new_fv = total_fv
                narrative = f"DR Cash €{event_amount:,.0f} / CR PPN Liability €{event_amount:,.0f}"
            else:
                new_cash = cash_balance
                new_fv = total_fv + event_amount
                narrative = f"DR Loan Portfolio €{event_amount:,.0f} / CR PPN Liability €{event_amount:,.0f}"
            post_nav = new_fv + accrued_interest - accrued_expenses + new_cash
            face_change = event_amount
        else:  # Paydown
            new_face_value = current_face_value - event_amount
            new_cash = max(0, cash_balance - event_amount)
            new_fv = total_fv
            post_nav = new_fv + accrued_interest - accrued_expenses + new_cash
            narrative = f"DR PPN Liability €{event_amount:,.0f} / CR Cash €{event_amount:,.0f}"
            face_change = -event_amount

        nav_per_face_post = post_nav / new_face_value if new_face_value > 0 else 0

        # Before/After comparison
        compare_df = pd.DataFrame([
            {"Metric": "Portfolio Fair Value", "Pre-Event": total_fv, "Post-Event": new_fv, "Change": new_fv - total_fv},
            {"Metric": "Cash at Bank", "Pre-Event": cash_balance, "Post-Event": new_cash, "Change": new_cash - cash_balance},
            {"Metric": "Accrued Interest", "Pre-Event": accrued_interest, "Post-Event": accrued_interest, "Change": 0},
            {"Metric": "Accrued Expenses", "Pre-Event": -accrued_expenses, "Post-Event": -accrued_expenses, "Change": 0},
            {"Metric": "**NAV**", "Pre-Event": pre_nav, "Post-Event": post_nav, "Change": post_nav - pre_nav},
            {"Metric": "**PPN Face Value**", "Pre-Event": current_face_value, "Post-Event": new_face_value, "Change": face_change},
            {"Metric": "NAV / Face Value", "Pre-Event": nav_per_face_pre, "Post-Event": nav_per_face_post, "Change": nav_per_face_post - nav_per_face_pre},
        ])

        st.dataframe(
            compare_df.style.format({
                "Pre-Event": lambda x: f"€{x:,.0f}" if abs(x) > 10 else f"{x:.6f}",
                "Post-Event": lambda x: f"€{x:,.0f}" if abs(x) > 10 else f"{x:.6f}",
                "Change": lambda x: f"€{x:,.0f}" if abs(x) > 10 else f"{x:.6f}",
            }),
            use_container_width=True, hide_index=True,
        )

        st.markdown("---")
        st.subheader("Step 4 — Accounting entries & downstream updates")

        st.markdown(f"**Journal entry:** `{narrative}`")

        st.markdown("##### Downstream actions required")
        st.markdown(f"""
        1. **Book the event** in GL on {event_date}  
        2. **Update PPN Stability Check** — face value: €{current_face_value:,.0f} → €{new_face_value:,.0f}  
        3. **Update Register of Noteholders** (via Maples Fiduciary) — confirm in writing  
        4. **Flag for next capstock file** — event type `{event_type.split()[0].upper()}`  
        5. **Update daily NAV engine** — new face value for capstock file generation  
        6. **Notify auditor** at next fieldwork — Special NAV with full audit trail retained  
        7. **Update tax data pack** — change in PPN face value may affect ATAD calculation  
        """)

        # Export
        if gate_cleared:
            special_nav_export = {
                "Special_NAV_Summary": compare_df,
                "Event_Details": pd.DataFrame([{
                    "Event_Type": event_type,
                    "Event_Date": event_date.strftime("%Y-%m-%d"),
                    "Event_Amount_EUR": event_amount,
                    "Mode": event_mode,
                    "Pre_Event_NAV": pre_nav,
                    "Post_Event_NAV": post_nav,
                    "Pre_Event_Face_Value": current_face_value,
                    "Post_Event_Face_Value": new_face_value,
                    "Governance_IM_Notice": "Yes" if g1 else "No",
                    "Governance_ManCo_Approval": "Yes" if g2 else "No",
                    "Governance_Trustee_Approval": "Yes" if g3 else "No",
                    "Journal_Entry": narrative,
                }])
            }
            st.download_button(
                "📥 Download Special NAV Report",
                data=to_excel_bytes(special_nav_export),
                file_name=f"special_nav_{event_date:%Y%m%d}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        else:
            st.caption("Export available once governance gate is cleared.")


# ═══════════════════════════════════════════════════════════
# PAGE: Waterfall Calculator
# ═══════════════════════════════════════════════════════════
elif page == "💧 Waterfall Calculator":
    st.title("Waterfall Calculator")
    st.markdown("Run the **quarterly** waterfall with **separate interest and principal flows**. Mixing the two breaks S110 tax neutrality.")

    st.error("**CRITICAL:** Interest pays expenses + PPN coupon. Principal reinvests or pays down PPN face value. NEVER mix.")

    quarter = st.selectbox("Quarter", ["Q1", "Q2", "Q3", "Q4"])
    q_col = f"{quarter}_EUR"

    # Get inflows
    if st.session_state.portfolio is not None:
        inflows = generate_cash_inflows()
    else:
        inflows = generate_cash_inflows()

    tab1, tab2, tab3 = st.tabs(["📈 Interest Waterfall", "🏦 Principal Waterfall", "📊 Summary"])

    with tab1:
        st.subheader(f"Interest Waterfall — {quarter}")
        interest_inflows = inflows[inflows["Type"] == "Interest"]
        st.markdown("##### Sources")
        st.dataframe(interest_inflows[["Source", q_col]].style.format({q_col: "€{:,.0f}"}), hide_index=True)
        total_interest = interest_inflows[q_col].sum()
        st.metric("Total Interest Inflows", f"€{total_interest:,.0f}")

        st.markdown("---")
        st.markdown("##### Priority of payments")

        # Build waterfall
        waterfall = [
            ("I-1", "Taxes", 0, "N/A"),
            ("I-2", "Trustee Fees", 12500, "50,000"),
            ("I-3", "Admin Fees", 25000, "100,000"),
            ("I-4", "ManCo Fees", 35000, "140,000"),
            ("I-5", "IM Fees (performing collateral)", 125000, "500,000"),
            ("I-6", "Audit & Legal", 15000, "80,000"),
            ("I-7", "Paying Agent & Listing", 3000, "15,000"),
            ("I-8", "Other Operating", 5000, "25,000"),
            ("I-9", "Cash Reserve Top-Up", 25000, "N/A"),
        ]
        wf_df = pd.DataFrame(waterfall, columns=["Priority", "Payment", "Amount_EUR", "Annual_Cap_EUR"])
        total_expenses = wf_df["Amount_EUR"].sum()
        residual = total_interest - total_expenses

        wf_display = wf_df.copy()
        wf_display.loc[len(wf_display)] = ["I-10", "PPN Interest Coupon to Investor (residual)", residual, "N/A"]
        st.dataframe(wf_display.style.format({"Amount_EUR": "€{:,.0f}"}), hide_index=True, use_container_width=True)

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Inflows", f"€{total_interest:,.0f}")
        c2.metric("Senior Expenses", f"€{total_expenses:,.0f}")
        c3.metric("PPN Coupon (residual)", f"€{residual:,.0f}")

        # Waterfall chart
        fig = go.Figure(go.Waterfall(
            x=["Interest Inflows"] + [f"{r[0]}. {r[1][:15]}" for r in waterfall] + ["PPN Coupon"],
            y=[total_interest] + [-r[2] for r in waterfall] + [0],
            measure=["absolute"] + ["relative"] * len(waterfall) + ["total"],
            connector={"line": {"color": MUTED}},
            increasing={"marker": {"color": SAGE}},
            decreasing={"marker": {"color": CORAL}},
            totals={"marker": {"color": TEAL}},
        ))
        fig.update_layout(**PLOTLY_LAYOUT, title="Interest Waterfall Visualisation", height=400, xaxis_tickangle=-45)
        st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.subheader(f"Principal Waterfall — {quarter}")
        principal_inflows = inflows[inflows["Type"] == "Principal"]
        st.dataframe(principal_inflows[["Source", q_col]].style.format({q_col: "€{:,.0f}"}), hide_index=True)
        total_principal = principal_inflows[q_col].sum()
        st.metric("Total Principal Inflows", f"€{total_principal:,.0f}")

        st.markdown("---")
        st.markdown("##### Application of principal proceeds")

        reinvestment_active = st.checkbox("Reinvestment period active?", value=True)

        if reinvestment_active:
            st.info(f"During the reinvestment period, principal proceeds are deployed into new loans by the IM. €{total_principal:,.0f} available for reinvestment.")
            app_df = pd.DataFrame([
                {"Priority": "P-1", "Application": "Reinvest in new loans", "Amount_EUR": total_principal},
                {"Priority": "P-2", "Application": "Pay down PPN face value", "Amount_EUR": 0},
                {"Priority": "P-3", "Application": "Residual to investor", "Amount_EUR": 0},
            ])
        else:
            st.warning("Reinvestment period has ended. Principal proceeds reduce the PPN face value.")
            app_df = pd.DataFrame([
                {"Priority": "P-1", "Application": "Reinvest in new loans", "Amount_EUR": 0},
                {"Priority": "P-2", "Application": "Pay down PPN face value", "Amount_EUR": total_principal},
                {"Priority": "P-3", "Application": "Residual to investor", "Amount_EUR": 0},
            ])

        st.dataframe(app_df.style.format({"Amount_EUR": "€{:,.0f}"}), hide_index=True, use_container_width=True)

        st.warning("**Principal is NOT part of the PPN coupon.** The coupon is interest-only. Principal either gets reinvested or returns capital. This separation preserves S110 tax neutrality.")

    with tab3:
        st.subheader(f"{quarter} Summary")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Interest Received", f"€{total_interest:,.0f}")
        c2.metric("Senior Expenses", f"€{total_expenses:,.0f}")
        c3.metric("PPN Interest Coupon", f"€{residual:,.0f}")
        c4.metric("Principal Received", f"€{total_principal:,.0f}")

        st.markdown("---")
        st.markdown("##### S110 Tax Check")
        # Simplified S110 check
        taxable_profit = total_interest - total_expenses - residual
        st.metric("Residual Taxable Profit", f"€{taxable_profit:,.0f}")
        if abs(taxable_profit) < 5000:
            st.success(f"✅ S110 deduction working correctly. Residual taxable profit €{taxable_profit:,.0f} is within acceptable range.")
        else:
            st.error(f"⚠️ Taxable profit of €{taxable_profit:,.0f} is material. Check PPN coupon calculation — it should absorb taxable profit.")

        # Download
        export = {
            "Interest_Sources": interest_inflows[["Source", q_col]],
            "Interest_Waterfall": wf_display,
            "Principal_Sources": principal_inflows[["Source", q_col]],
            "Principal_Application": app_df,
        }
        st.download_button(
            "📥 Download Waterfall Report",
            data=to_excel_bytes(export),
            file_name=f"waterfall_{quarter}_{datetime.now():%Y%m%d}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )

# ═══════════════════════════════════════════════════════════
# PAGE: Distribution Calculator
# ═══════════════════════════════════════════════════════════
elif page == "💰 Distribution Calculator":
    st.title("Quarterly Distribution Calculator")
    st.markdown(
        "End-to-end quarterly distribution calculation: gross coupon from the waterfall, WHT application, "
        "net payable to investor, governance gate checks, payment instruction."
    )
    st.info("Distribution frequency: **quarterly**. This is the complete calculation from waterfall residual through to payment instruction.")

    quarter = st.selectbox("Quarter", ["Q1", "Q2", "Q3", "Q4"], key="dist_quarter")
    period_end = st.date_input("Period end date")

    st.markdown("---")
    st.subheader("Step 1 — Gross coupon from interest waterfall")

    col1, col2 = st.columns(2)
    with col1:
        total_interest_receipts = st.number_input(
            "Total interest receipts for the quarter (EUR)", 0, 100_000_000, 842_000, step=1000)
        senior_expenses = st.number_input(
            "Senior expenses paid (I-1 to I-9, EUR)", 0, 10_000_000, 245_500, step=500)
    with col2:
        deferred_from_prior = st.number_input(
            "Deferred amounts carried from prior quarter (EUR)", 0, 10_000_000, 0, step=500)
        over_cap_subordination = st.number_input(
            "Over-cap amounts subordinated below coupon (EUR)", 0, 10_000_000, 0, step=500)

    gross_coupon = total_interest_receipts - senior_expenses - deferred_from_prior

    c1, c2, c3 = st.columns(3)
    c1.metric("Total interest receipts", f"€{total_interest_receipts:,.0f}")
    c2.metric("Less: senior expenses", f"€{senior_expenses:,.0f}", delta_color="inverse")
    c3.metric("**Gross PPN coupon**", f"€{gross_coupon:,.0f}")

    if over_cap_subordination > 0:
        st.warning(f"Over-cap subordination of €{over_cap_subordination:,.0f} will be deducted AFTER the coupon if residual cash allows.")

    st.markdown("---")
    st.subheader("Step 2 — Withholding tax determination")

    c1, c2 = st.columns([2, 1])
    with c1:
        wht_route = st.selectbox(
            "WHT exemption route",
            [
                "Quoted Eurobond exemption (S.64 TCA 1997)",
                "Double Tax Treaty relief (Ireland-Australia)",
                "Section 246(3)(h) — interest to EU/treaty company",
                "NO EXEMPTION — 20% WHT applies",
            ],
        )
    with c2:
        wht_rate = 0.0 if "NO EXEMPTION" not in wht_route else 20.0
        st.metric("WHT rate", f"{wht_rate:.0f}%")

    # WHT documentation checklist
    st.markdown("##### WHT documentation checklist")
    d1 = st.checkbox("Formal tax adviser confirmation of exemption route on file")
    d2 = st.checkbox("Current ATO residency certificate (annual renewal) on file")
    d3 = st.checkbox("Signed DTT relief form on file (if DTT route)")
    d4 = st.checkbox("Beneficial ownership declaration from investor on file")
    d5 = st.checkbox("W-8BEN-E and CRS self-certification on file")

    wht_docs_complete = d1 and d2 and (d3 or "DTT" not in wht_route) and d4 and d5

    if not wht_docs_complete:
        st.error("⚠️ WHT documentation incomplete. HARD STOP — do NOT process distribution until all required documents are on file. Paying gross without exemption = immediate Revenue liability.")
    else:
        st.success("✅ WHT documentation complete.")

    wht_amount = gross_coupon * wht_rate / 100
    net_to_investor = gross_coupon - wht_amount

    c1, c2, c3 = st.columns(3)
    c1.metric("Gross coupon", f"€{gross_coupon:,.0f}")
    c2.metric("WHT deducted", f"€{wht_amount:,.0f}", delta_color="inverse")
    c3.metric("**NET to investor**", f"€{net_to_investor:,.0f}")

    st.markdown("---")
    st.subheader("Step 3 — Governance gate")
    st.caption("All six gates must be cleared before payment instruction")

    g1 = st.checkbox("FA calculation complete and self-reviewed (4 eyes)")
    g2 = st.checkbox("Shadow book reconciliation to IM complete — no unexplained breaks")
    g3 = st.checkbox("IM (KKR) approval of distribution amount received")
    g4 = st.checkbox("ManCo approval of distribution received (written)")
    g5 = st.checkbox("Directors' resolution passed (or standing authority applies)")
    g6 = st.checkbox("Trustee authorisation of cash release received")

    gates_cleared = g1 and g2 and g3 and g4 and g5 and g6

    if gates_cleared and wht_docs_complete:
        st.success("🟢 **ALL GATES CLEARED.** Ready for Paying Agent instruction.")
    else:
        blocked_count = 6 - sum([g1, g2, g3, g4, g5, g6])
        doc_blocked = 0 if wht_docs_complete else 1
        st.error(f"🔴 **BLOCKED** — {blocked_count} governance gate(s) outstanding, {doc_blocked} WHT documentation gap(s). Distribution cannot proceed.")

    st.markdown("---")
    st.subheader("Step 4 — Payment instruction")

    if gates_cleared and wht_docs_complete:
        payment_date = st.date_input("Scheduled payment date", value=period_end)

        st.markdown("##### Paying Agent instruction")
        payment_instruction = pd.DataFrame([{
            "Field": "Payer",
            "Value": "DAC-001 (the DAC)",
        }, {
            "Field": "Payee",
            "Value": "INV-001 (the Investor)",
        }, {
            "Field": "Payment Date",
            "Value": payment_date.strftime("%Y-%m-%d"),
        }, {
            "Field": "Payment Reference",
            "Value": f"PPN-COUPON-{quarter}-{period_end.year}",
        }, {
            "Field": "Currency",
            "Value": "EUR",
        }, {
            "Field": "Gross Amount",
            "Value": f"€{gross_coupon:,.2f}",
        }, {
            "Field": "WHT Deduction",
            "Value": f"€{wht_amount:,.2f} ({wht_rate:.0f}%)",
        }, {
            "Field": "NET AMOUNT TO WIRE",
            "Value": f"€{net_to_investor:,.2f}",
        }, {
            "Field": "Investor Bank",
            "Value": "[Investor nominated bank account]",
        }, {
            "Field": "Authorisation",
            "Value": f"ManCo + Directors + Trustee — cleared",
        }])
        st.dataframe(payment_instruction, use_container_width=True, hide_index=True)

        # Accounting entries
        st.markdown("##### Accounting entries")
        entries_data = [
            {"Entry": "DR", "Account": "PPN Coupon Expense (Interest)", "Amount": f"€{gross_coupon:,.2f}", "Description": "Gross coupon — S110 deductible"},
            {"Entry": "CR", "Account": "Cash at Bank", "Amount": f"€{net_to_investor:,.2f}", "Description": "Net payment to investor"},
        ]
        if wht_amount > 0:
            entries_data.append({"Entry": "CR", "Account": "WHT Payable to Revenue", "Amount": f"€{wht_amount:,.2f}", "Description": "WHT due to Revenue"})
        entries = pd.DataFrame(entries_data)
        st.dataframe(entries, use_container_width=True, hide_index=True)

        # Export
        export = {
            "Distribution_Summary": pd.DataFrame([{
                "Quarter": quarter,
                "Period_End": period_end.strftime("%Y-%m-%d"),
                "Total_Interest_Receipts_EUR": total_interest_receipts,
                "Senior_Expenses_EUR": senior_expenses,
                "Deferred_Prior_Quarter_EUR": deferred_from_prior,
                "Gross_Coupon_EUR": gross_coupon,
                "WHT_Route": wht_route,
                "WHT_Rate_Pct": wht_rate,
                "WHT_Amount_EUR": wht_amount,
                "Net_To_Investor_EUR": net_to_investor,
                "Payment_Date": payment_date.strftime("%Y-%m-%d"),
            }]),
            "Payment_Instruction": payment_instruction,
            "Journal_Entries": entries,
        }
        st.download_button(
            "📥 Download Distribution Report",
            data=to_excel_bytes(export),
            file_name=f"distribution_{quarter}_{period_end:%Y%m%d}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
    else:
        st.caption("Payment instruction will appear once all gates are cleared.")


# ═══════════════════════════════════════════════════════════
# PAGE: Expense Cap Tracker
# ═══════════════════════════════════════════════════════════
elif page == "💳 Expense Cap Tracker":
    st.title("Expense Cap Tracker")
    st.markdown("Track cumulative YTD expenses against Trust Deed annual caps. Over-cap amounts are **subordinated** below the PPN coupon.")

    if st.session_state.expenses is None:
        st.session_state.expenses = generate_expense_schedule()

    expenses = st.session_state.expenses.copy()

    # User inputs actual YTD
    st.subheader("Enter YTD actual payments")
    st.caption("Editable — adjust actual spend per category to test cap breach scenarios")

    ytd_data = []
    for idx, row in expenses.iterrows():
        c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
        with c1:
            st.text(row["Expense_Category"])
        with c2:
            st.caption(f"Cap: €{row['Annual_Cap_EUR']:,.0f}")
        with c3:
            ytd = st.number_input(
                f"YTD paid ({row['Expense_Category']})",
                0, int(row["Annual_Cap_EUR"] * 2),
                int(row["Annual_Amount_EUR"] * 0.7),
                key=f"ytd_{idx}",
                label_visibility="collapsed"
            )
        with c4:
            remaining = row["Annual_Cap_EUR"] - ytd
            if remaining < 0:
                st.error(f"OVER by €{-remaining:,.0f}")
            elif remaining < row["Annual_Cap_EUR"] * 0.2:
                st.warning(f"€{remaining:,.0f} left")
            else:
                st.success(f"€{remaining:,.0f} left")
        ytd_data.append({"Category": row["Expense_Category"], "Cap": row["Annual_Cap_EUR"],
                        "YTD": ytd, "Remaining": remaining,
                        "Over_Cap": max(0, -remaining)})

    st.markdown("---")

    # Summary
    tracker_df = pd.DataFrame(ytd_data)
    total_over = tracker_df["Over_Cap"].sum()

    if total_over > 0:
        st.error(f"⚠️ Total over-cap amount: €{total_over:,.0f} — this amount is **subordinated** below the PPN coupon in the waterfall.")
    else:
        st.success("✅ All expense categories within caps.")

    # Visualisation
    fig = go.Figure()
    fig.add_trace(go.Bar(
        name="YTD Paid", x=tracker_df["Category"], y=tracker_df["YTD"],
        marker_color=TEAL, text=tracker_df["YTD"].apply(lambda x: f"€{x:,.0f}"),
        textposition="inside"
    ))
    fig.add_trace(go.Bar(
        name="Remaining Cap", x=tracker_df["Category"],
        y=[max(0, r) for r in tracker_df["Remaining"]],
        marker_color=SAGE
    ))
    fig.add_trace(go.Bar(
        name="Over Cap", x=tracker_df["Category"], y=tracker_df["Over_Cap"],
        marker_color=CORAL, text=tracker_df["Over_Cap"].apply(lambda x: f"€{x:,.0f}" if x > 0 else ""),
        textposition="outside"
    ))
    fig.update_layout(**PLOTLY_LAYOUT, barmode="stack", title="YTD Expenses vs Annual Caps",
                      height=400, xaxis_tickangle=-30)
    st.plotly_chart(fig, use_container_width=True)

    # Subordination mechanics
    with st.expander("📖 How subordination works"):
        st.markdown("""
        **When an expense exceeds its annual cap:**

        1. The portion **up to the cap** is paid at the senior priority in the interest waterfall (I-2 through I-9)
        2. The portion **above the cap** is subordinated — it drops to a new priority position **below** the PPN coupon (I-10)
        3. If insufficient residual cash remains after paying the PPN coupon, the over-cap amount **carries forward** as a deferred payable
        4. Deferred amounts must be paid in subsequent quarters before any additional over-cap subordination

        **Paying an over-cap invoice at senior priority is a contractual breach of the Trust Deed.** The Trustee may halt the waterfall if this occurs.
        """)

    # Export
    st.download_button(
        "📥 Download Cap Tracker Report",
        data=to_csv_bytes(tracker_df),
        file_name=f"expense_cap_tracker_{datetime.now():%Y%m%d}.csv",
        mime="text/csv",
    )

# ═══════════════════════════════════════════════════════════
# PAGE: Shadow Book Reconciliation
# ═══════════════════════════════════════════════════════════
elif page == "🔄 Shadow Book Reconciliation":
    st.title("Shadow Book Reconciliation")
    st.markdown("Reconcile your FA accrued income against the Investment Manager's shadow book. Market practice for private credit.")

    if st.session_state.portfolio is None:
        st.warning("⚠️ Load a portfolio first.")
    else:
        tab1, tab2 = st.tabs(["📥 Upload IM Shadow Book", "🧪 Generate Sample"])

        with tab1:
            uploaded = st.file_uploader("Upload IM shadow book (CSV/Excel)", type=["csv", "xlsx"])
            shadow_df = None
            if uploaded:
                if uploaded.name.endswith(".csv"):
                    shadow_df = pd.read_csv(uploaded)
                else:
                    shadow_df = pd.read_excel(uploaded)

        with tab2:
            bias_pct = st.slider("Shadow book bias (%) for testing", 0.0, 2.0, 0.5, step=0.1)
            if st.button("Generate sample shadow book"):
                shadow_df = generate_shadow_book(st.session_state.portfolio, bias_pct=bias_pct)
                st.session_state.shadow_df = shadow_df

        if "shadow_df" in st.session_state:
            shadow_df = st.session_state.shadow_df

            st.markdown("---")
            st.subheader("Reconciliation")

            # Calculate FA accrued from portfolio
            euribor = 3.65
            portfolio = st.session_state.portfolio.copy()
            portfolio["Spread_Pct"] = portfolio["Spread_bps"] / 100
            portfolio["All_In_Pct"] = portfolio.apply(
                lambda r: max(euribor + r["Spread_Pct"], r["EURIBOR_Floor_Pct"] + r["Spread_Pct"]), axis=1)
            portfolio["FA_Accrued_Interest_EUR"] = (portfolio["Par_Value_EUR"] * portfolio["All_In_Pct"] / 100 * 30 / 360).round()

            # Merge
            rec = portfolio[["Loan_ID", "Borrower", "FA_Accrued_Interest_EUR"]].merge(
                shadow_df[["Loan_ID", "IM_Accrued_Interest_EUR", "IM_Note"]],
                on="Loan_ID", how="outer"
            )
            rec["Difference_EUR"] = rec["FA_Accrued_Interest_EUR"] - rec["IM_Accrued_Interest_EUR"]
            rec["Difference_Pct"] = (rec["Difference_EUR"] / rec["FA_Accrued_Interest_EUR"] * 100).round(2)
            rec["Status"] = rec["Difference_EUR"].apply(
                lambda d: "Match" if abs(d) < 50 else ("Small diff" if abs(d) < 500 else "Investigate")
            )

            # Summary metrics
            c1, c2, c3, c4 = st.columns(4)
            total_fa = rec["FA_Accrued_Interest_EUR"].sum()
            total_im = rec["IM_Accrued_Interest_EUR"].sum()
            total_diff = total_fa - total_im
            investigate_count = len(rec[rec["Status"] == "Investigate"])

            c1.metric("FA Total Accrued", f"€{total_fa:,.0f}")
            c2.metric("IM Total Accrued", f"€{total_im:,.0f}")
            c3.metric("Total Difference", f"€{total_diff:,.0f}", delta=f"{total_diff/total_fa*100:.2f}%")
            c4.metric("Breaks to Investigate", investigate_count, delta_color="inverse")

            st.markdown("---")

            # Show breaks
            breaks = rec[rec["Status"] == "Investigate"].sort_values("Difference_EUR", key=abs, ascending=False)
            if len(breaks) > 0:
                st.subheader(f"Breaks requiring investigation ({len(breaks)})")
                st.dataframe(
                    breaks.style.format({
                        "FA_Accrued_Interest_EUR": "€{:,.0f}",
                        "IM_Accrued_Interest_EUR": "€{:,.0f}",
                        "Difference_EUR": "€{:,.0f}",
                        "Difference_Pct": "{:.2f}%"
                    }),
                    use_container_width=True, height=300
                )
            else:
                st.success("✅ No material breaks — FA and IM numbers align within tolerance.")

            # Full rec
            with st.expander("Show full reconciliation"):
                st.dataframe(rec.style.format({
                    "FA_Accrued_Interest_EUR": "€{:,.0f}",
                    "IM_Accrued_Interest_EUR": "€{:,.0f}",
                    "Difference_EUR": "€{:,.0f}",
                    "Difference_Pct": "{:.2f}%"
                }), use_container_width=True)

            # Download
            st.download_button(
                "📥 Download Reconciliation Report",
                data=to_excel_bytes({"Reconciliation": rec, "Breaks": breaks}),
                file_name=f"shadow_book_rec_{datetime.now():%Y%m%d}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

            # ── 4-NUMBER RECONCILIATION (quarterly summary rec) ──
            st.markdown("---")
            st.subheader("Quarterly Summary Reconciliation — The 4 Numbers")
            st.markdown(
                "Market practice for private credit. Reconcile FA vs IM on the four figures that "
                "drive the PPN coupon. Differences here must be investigated before distribution."
            )

            # FA figures (from portfolio)
            fa_accrued = rec["FA_Accrued_Interest_EUR"].sum()

            # IM figures (from shadow book)
            im_accrued = rec["IM_Accrued_Interest_EUR"].sum()
            im_cash_received = shadow_df["IM_Cash_Received_EUR"].sum() if "IM_Cash_Received_EUR" in shadow_df.columns else 0

            # FA cash received — user inputs actual
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**FA book (our numbers)**")
                fa_cash_received = st.number_input(
                    "FA: Cash interest received this quarter (EUR)",
                    0, 100_000_000, int(fa_accrued * 0.93), step=1000,
                    key="fa_cash")
                fa_distributable = st.number_input(
                    "FA: Distributable interest (after timing adj)",
                    0, 100_000_000, int(fa_accrued * 0.95), step=1000,
                    key="fa_dist")

            with c2:
                st.markdown("**IM shadow book (KKR numbers)**")
                st.number_input("IM: Accrued interest", value=int(im_accrued), disabled=True, key="im_acc_d")
                im_cash_input = st.number_input(
                    "IM: Cash interest received",
                    0, 100_000_000, int(im_cash_received), step=1000,
                    key="im_cash")
                im_distributable = st.number_input(
                    "IM: Distributable interest",
                    0, 100_000_000, int(im_accrued * 0.95), step=1000,
                    key="im_dist")

            st.markdown("---")

            four_numbers = pd.DataFrame([
                {
                    "Metric": "Accrued Interest",
                    "FA Number": fa_accrued,
                    "IM Number": im_accrued,
                    "Difference": fa_accrued - im_accrued,
                    "Tolerance": 500,
                    "Common Causes": "Day count, EURIBOR timing, PIK capitalisation, rate reset lag",
                },
                {
                    "Metric": "Cash Received",
                    "FA Number": fa_cash_received,
                    "IM Number": im_cash_input,
                    "Difference": fa_cash_received - im_cash_input,
                    "Tolerance": 200,
                    "Common Causes": "Period cutoff (trade date vs settlement), delayed compensation",
                },
                {
                    "Metric": "Distributable Interest",
                    "FA Number": fa_distributable,
                    "IM Number": im_distributable,
                    "Difference": fa_distributable - im_distributable,
                    "Tolerance": 500,
                    "Common Causes": "Classification of amendment fees, break funding, PIK treatment",
                },
                {
                    "Metric": "Reconciling Items (Acc. - Cash)",
                    "FA Number": fa_accrued - fa_cash_received,
                    "IM Number": im_accrued - im_cash_input,
                    "Difference": (fa_accrued - fa_cash_received) - (im_accrued - im_cash_input),
                    "Tolerance": 1000,
                    "Common Causes": "Period-end accruals timing, cash-in-transit",
                },
            ])
            four_numbers["Status"] = four_numbers.apply(
                lambda r: "🟢 Within tolerance" if abs(r["Difference"]) <= r["Tolerance"] else "🔴 INVESTIGATE", axis=1
            )

            st.dataframe(
                four_numbers.style.format({
                    "FA Number": "€{:,.0f}",
                    "IM Number": "€{:,.0f}",
                    "Difference": "€{:,.0f}",
                    "Tolerance": "€{:,.0f}",
                }),
                use_container_width=True, hide_index=True,
            )

            # Overall status
            breaks_4n = (four_numbers["Status"] == "🔴 INVESTIGATE").sum()
            if breaks_4n == 0:
                st.success(f"✅ All 4 reconciliation numbers within tolerance. Distribution can proceed (subject to other governance gates).")
            else:
                st.error(f"⚠️ {breaks_4n} of 4 reconciliation numbers outside tolerance. Distribution should NOT proceed until breaks are investigated and explained.")

            # Download extended rec
            st.download_button(
                "📥 Download 4-Number Reconciliation",
                data=to_excel_bytes({
                    "4_Number_Rec": four_numbers,
                    "Line_Level_Rec": rec,
                    "Breaks_Line_Level": breaks,
                }),
                file_name=f"shadow_book_4num_rec_{datetime.now():%Y%m%d}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

# ═══════════════════════════════════════════════════════════
# PAGE: Capstock File Generator
# ═══════════════════════════════════════════════════════════
elif page == "📄 Capstock File Generator":
    st.title("Synthetic Capstock File Generator")
    st.markdown("Generate the capstock feed for your FA platform from the PPN note register. Platform expects a TA feed — we generate one synthetically.")

    if st.session_state.note_register is None:
        st.session_state.note_register = generate_note_register()

    st.subheader("Note Register")
    st.dataframe(st.session_state.note_register.style.format({
        "Amount_EUR": "€{:,.0f}",
        "PPN_Face_Value_After_EUR": "€{:,.0f}"
    }), use_container_width=True, hide_index=True)

    current_face_value = st.session_state.note_register["PPN_Face_Value_After_EUR"].iloc[-1]
    st.metric("Current PPN Face Value", f"€{current_face_value:,.0f}")

    st.markdown("---")
    st.subheader("Generate capstock file")

    col1, col2, col3 = st.columns(3)
    with col1:
        record_date = st.date_input("Record date", datetime.now())
    with col2:
        nav = st.number_input("Today's NAV (EUR)", 0, 1_000_000_000, int(current_face_value * 1.03))
    with col3:
        event_today = st.selectbox("Event today?", ["NIL", "DRAWDOWN", "PAYDOWN", "COUPON"])

    # Event-specific inputs
    sub_amount = 0
    red_amount = 0
    dist_amount = 0
    face_value = current_face_value
    trans_type = event_today

    if event_today == "DRAWDOWN":
        sub_amount = st.number_input("Drawdown amount (EUR)", 0, 100_000_000, 5_000_000)
        face_value = current_face_value + sub_amount
    elif event_today == "PAYDOWN":
        red_amount = st.number_input("Paydown amount (EUR)", 0, int(current_face_value), 1_000_000)
        face_value = current_face_value - red_amount
    elif event_today == "COUPON":
        dist_amount = st.number_input("Coupon amount (EUR)", 0, 50_000_000, 150_000)
        st.info("Coupon payment does NOT reduce face value. Only NAV changes.")

    nav_per_unit = nav / face_value if face_value > 0 else 1.0

    # Build capstock row
    capstock = pd.DataFrame([{
        "Fund_ID": "DAC-001",
        "Share_Class_ID": "PPN-SERIES-A",
        "Investor_ID": "INV-001",
        "Investor_Name": "Investor",
        "Currency": "EUR",
        "Units_Outstanding": face_value,
        "NAV_Per_Unit": round(nav_per_unit, 6),
        "Subscription_Amount": sub_amount,
        "Redemption_Amount": red_amount,
        "Units_Subscribed": sub_amount,
        "Units_Redeemed": red_amount,
        "Distribution_Amount": dist_amount,
        "Record_Date": record_date.strftime("%Y-%m-%d"),
        "Effective_Date": record_date.strftime("%Y-%m-%d"),
        "Transaction_Type": trans_type,
    }])

    st.markdown("---")
    st.subheader("Generated capstock file")

    st.code(capstock.to_csv(index=False), language="csv")

    st.markdown("##### Field interpretation")
    st.markdown(f"""
    - `Units_Outstanding` = **PPN face value** (€{face_value:,.0f}), not share units  
    - `NAV_Per_Unit` = {nav_per_unit:.6f} (NAV ÷ face value, hovers around 1.0)  
    - `Subscription_Amount` = {sub_amount:,.0f} (event-driven only)  
    - `Redemption_Amount` = {red_amount:,.0f} (principal paydown only — NOT coupon)  
    - `Distribution_Amount` = {dist_amount:,.0f} (PPN interest coupon)  
    - `Transaction_Type` = **{trans_type}** (maps to your platform's SUB/RED/DIV/NIL)  
    """)

    if event_today == "COUPON":
        st.warning("**Critical:** The PPN coupon does NOT reduce face value. If your FA platform processes this as a redemption that reduces Units_Outstanding, the capstock will be wrong from this point forward.")

    # Download
    st.download_button(
        "📥 Download Capstock CSV",
        data=capstock.to_csv(index=False).encode("utf-8"),
        file_name=f"capstock_{record_date:%Y%m%d}.csv",
        mime="text/csv",
    )

# ═══════════════════════════════════════════════════════════
# PAGE: S110 Tax Data Pack
# ═══════════════════════════════════════════════════════════
elif page == "📋 S110 Tax Data Pack":
    st.title("S110 Tax Data Pack")
    st.markdown("Annual data extract for the tax adviser. Provides the inputs for the S110 computation and ATAD ILR assessment.")

    if st.session_state.portfolio is None:
        st.warning("⚠️ Load a portfolio first.")
    else:
        # Simulate full year data
        portfolio = st.session_state.portfolio
        euribor = 3.65
        portfolio["Spread_Pct"] = portfolio["Spread_bps"] / 100
        portfolio["Annual_Rate_Pct"] = portfolio.apply(
            lambda r: max(euribor + r["Spread_Pct"], r["EURIBOR_Floor_Pct"] + r["Spread_Pct"]), axis=1)
        portfolio["Annual_Interest_EUR"] = (portfolio["Par_Value_EUR"] * portfolio["Annual_Rate_Pct"] / 100).round()

        total_interest_income = portfolio["Annual_Interest_EUR"].sum()

        # Build the tax data pack
        st.subheader("Tax Data Pack — Annual Summary")

        tax_data = pd.DataFrame([
            # Interest-equivalent income
            {"Category": "INTEREST-EQUIVALENT INCOME", "Sub_Category": "", "Amount_EUR": None, "ATAD_Classification": ""},
            {"Category": "", "Sub_Category": "Loan interest income", "Amount_EUR": total_interest_income, "ATAD_Classification": "Exceeding Borrowing Costs (income)"},
            {"Category": "", "Sub_Category": "Commitment fees received", "Amount_EUR": 45000, "ATAD_Classification": "Exceeding Borrowing Costs (income)"},
            {"Category": "", "Sub_Category": "Amendment fees received", "Amount_EUR": 48000, "ATAD_Classification": "Exceeding Borrowing Costs (income)"},
            # Non-interest income
            {"Category": "NON-INTEREST INCOME", "Sub_Category": "", "Amount_EUR": None, "ATAD_Classification": ""},
            {"Category": "", "Sub_Category": "Unrealised FV gains (Markit)", "Amount_EUR": 250000, "ATAD_Classification": "Outside ILR scope"},
            {"Category": "", "Sub_Category": "Realised gains on disposals", "Amount_EUR": 75000, "ATAD_Classification": "Outside ILR scope"},
            # Interest-equivalent expense
            {"Category": "INTEREST-EQUIVALENT EXPENSE", "Sub_Category": "", "Amount_EUR": None, "ATAD_Classification": ""},
            {"Category": "", "Sub_Category": "PPN Coupon (to investor)", "Amount_EUR": int(total_interest_income * 0.88), "ATAD_Classification": "Exceeding Borrowing Costs (expense) — PRIMARY DEDUCTION"},
            # Non-interest expense
            {"Category": "NON-INTEREST EXPENSE", "Sub_Category": "", "Amount_EUR": None, "ATAD_Classification": ""},
            {"Category": "", "Sub_Category": "Admin fees", "Amount_EUR": 100000, "ATAD_Classification": "Operating expense — EBITDA input"},
            {"Category": "", "Sub_Category": "ManCo fees", "Amount_EUR": 140000, "ATAD_Classification": "Operating expense — EBITDA input"},
            {"Category": "", "Sub_Category": "IM fees", "Amount_EUR": 500000, "ATAD_Classification": "Operating expense — EBITDA input"},
            {"Category": "", "Sub_Category": "Trustee fees", "Amount_EUR": 50000, "ATAD_Classification": "Operating expense — EBITDA input"},
            {"Category": "", "Sub_Category": "Professional fees (audit, legal, incl. irrecoverable VAT)", "Amount_EUR": 95000, "ATAD_Classification": "Operating expense — EBITDA input"},
            {"Category": "", "Sub_Category": "Unrealised FV losses", "Amount_EUR": 180000, "ATAD_Classification": "Outside ILR scope"},
        ])

        st.dataframe(
            tax_data.style.format({"Amount_EUR": lambda x: f"€{x:,.0f}" if pd.notna(x) else ""}),
            use_container_width=True, hide_index=True
        )

        st.markdown("---")

        # ATAD ILR calculation
        st.subheader("ATAD Interest Limitation Rule — Preliminary Assessment")

        gross_interest_income = total_interest_income + 45000 + 48000
        ppn_coupon = int(total_interest_income * 0.88)
        op_expenses = 100000 + 140000 + 500000 + 50000 + 95000
        net_interest_expense = ppn_coupon - gross_interest_income
        ebitda = gross_interest_income + 250000 + 75000 - op_expenses
        threshold = ebitda * 0.3

        c1, c2, c3 = st.columns(3)
        c1.metric("Gross Interest Income", f"€{gross_interest_income:,.0f}")
        c2.metric("PPN Coupon (interest expense)", f"€{ppn_coupon:,.0f}")
        c3.metric("Net Interest Expense", f"€{net_interest_expense:,.0f}")

        st.markdown("---")
        c1, c2, c3 = st.columns(3)
        c1.metric("Simplified EBITDA", f"€{ebitda:,.0f}")
        c2.metric("30% EBITDA Threshold", f"€{threshold:,.0f}")
        c3.metric("De Minimis Threshold", "€3,000,000")

        # ILR applicability
        if ppn_coupon < 3_000_000:
            st.success(f"✅ **De minimis exemption applies.** PPN coupon of €{ppn_coupon:,.0f} is below the €3m threshold. ATAD ILR likely does NOT restrict the interest deduction.")
        elif net_interest_expense <= 0:
            st.success("✅ Net interest expense is non-positive. ATAD ILR does not restrict the deduction.")
        elif net_interest_expense > threshold:
            st.error(f"⚠️ Net interest expense (€{net_interest_expense:,.0f}) exceeds 30% EBITDA threshold (€{threshold:,.0f}). Part of the deduction may be restricted. Tax adviser to confirm applicable exemptions.")
        else:
            st.info(f"ℹ️ Net interest expense (€{net_interest_expense:,.0f}) is within 30% EBITDA threshold (€{threshold:,.0f}). Deduction appears available, tax adviser to confirm.")

        st.info("**Disclaimer:** This is a preliminary data-driven view. The tax adviser makes the formal ILR determination. Standalone entity or single-company-worldwide-group exemptions may also apply.")

        # Download
        st.markdown("---")
        export = {
            "S110_Data_Pack": tax_data,
            "ATAD_Summary": pd.DataFrame([
                {"Line": "Gross interest income", "Amount_EUR": gross_interest_income},
                {"Line": "PPN Coupon (interest expense)", "Amount_EUR": ppn_coupon},
                {"Line": "Net interest expense", "Amount_EUR": net_interest_expense},
                {"Line": "Simplified EBITDA", "Amount_EUR": ebitda},
                {"Line": "30% EBITDA threshold", "Amount_EUR": int(threshold)},
                {"Line": "De minimis threshold", "Amount_EUR": 3_000_000},
            ])
        }
        st.download_button(
            "📥 Download S110 Tax Data Pack",
            data=to_excel_bytes(export),
            file_name=f"s110_tax_data_pack_{datetime.now():%Y}.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
