# Structured Credit Specialist Toolkit — v3

Prototype Streamlit app for the specialist operational work on S110 DAC SPVs holding syndicated loans. Designed to complement traditional FA daily NAV production — this app handles the work that sits **outside** traditional FA BAU.

**Distribution frequency: QUARTERLY.**

## What's new in v3

- **Dashboard** — live KPIs, warning rail, portfolio composition charts, recent events, NAV trend
- **Process Runner** — 8-step quarter-end wizard with locked-gate transitions
- **Period-End NAV module** — full 5-step NAV calculation with ATAD-tagged trial balance
- **Credit Event Register** — persistent audit trail of all processed credit events
- Credit Event Processor now writes to the register automatically

## What's in the app

Sixteen modules:

1. **Dashboard** — KPIs, warning rail, composition charts, NAV trend
2. **Process Runner (Quarter-End)** — 8-step wizard with prerequisite gating
3. **Home & Workflow** — scope, workflow diagram, in/out of scope
4. **Portfolio Loader** — upload or generate synthetic portfolio; download templates
5. **Stale Price Monitor** — IPV escalation for positions with prices unchanged >5 days
6. **EURIBOR Floor Checker** — verifies accrual rates against facility floors; scenario tester
7. **Period-End NAV** — full NAV calc with revaluation, floor check, VAT split, trial balance
8. **Credit Event Processor** — guided workflows for PIK, A&E, paydown, waiver, downgrade, default
9. **Credit Event Register** — persistent log with filters, summary, export
10. **Special NAV (Capital Event)** — before/after snapshot for drawdowns/paydowns with governance gate
11. **Waterfall Calculator** — separate interest and principal waterfalls with S110 tax check
12. **Distribution Calculator** — quarterly coupon with WHT, 5 doc checks, 6 governance gates
13. **Expense Cap Tracker** — YTD cap monitoring with subordination logic
14. **Shadow Book Reconciliation** — line-level rec + 4-number quarterly summary rec
15. **Capstock File Generator** — synthetic CSV feed for FA platform
16. **S110 Tax Data Pack** — annual extract with ATAD ILR preliminary assessment

## Installation

```bash
pip install -r requirements.txt
streamlit run app.py
```

The app will launch in your browser at `http://localhost:8501`.

## File structure

```
specialist_app/
├── app.py                       # Main Streamlit app (16 modules)
├── sample_data_generator.py     # Synthetic data module
├── requirements.txt             # Python dependencies
├── README.md                    # This file
└── .streamlit/
    └── config.toml              # Light theme configuration
```

## Recommended workflow

**First run:** Navigate to Portfolio Loader > Generate Sample > click Generate. This populates the session with synthetic data for all modules.

**Daily:** Check the **Dashboard** for warnings; review **Stale Price Monitor**; process any **Credit Events** that occurred.

**Quarter-end cycle:** Use the **Process Runner** module to walk through the 8 steps in order:
1. Period-End NAV
2. Shadow Book Reconciliation
3. Waterfall Calculator
4. Expense Cap Tracker
5. Distribution Calculator
6. Capstock File Generator
7. Archive Audit Trail
8. Team Lead Sign-Off

Each step unlocks only when its predecessors are marked complete. The progress bar shows current position. You can reset and restart the cycle at any time.

**Annually:** Generate the **S110 Tax Data Pack** for the tax adviser.

## Data persistence across modules

Three session-level stores keep data flowing between modules:

- **`portfolio`** — populated by Portfolio Loader, read by almost every module
- **`credit_event_log`** — populated by Credit Event Processor + Register "Generate sample" button; displayed on Dashboard and Register
- **`nav_history`** — populated by Period-End NAV's "Save to history" button; displayed as a trend chart on the Dashboard
- **`process_state`** — tracks the 8-step wizard completion

All data is session-only and lost on app restart. For production, wire in SQLite or Postgres.

## Governance gates built into the app

**Special NAV module:**
- IM drawdown/paydown notice received
- ManCo written approval on file
- Trustee written approval on file

**Distribution Calculator module:**

*WHT documentation (5 items):*
- Tax adviser exemption confirmation
- ATO residency certificate (annual)
- DTT relief form (if DTT route)
- Beneficial ownership declaration
- W-8BEN-E and CRS self-certification

*Governance gates (6 items):*
- FA calculation complete and 4-eyes reviewed
- Shadow book rec complete — no unexplained breaks
- IM approval received
- ManCo approval (written)
- Directors' resolution (or standing authority)
- Trustee authorisation of cash release

Only when all are confirmed does the app unlock the payment instruction.

## Synthetic data notes

- All firm names are generic (Company AA, Company AB, etc.)
- Loan IDs are synthetic (SL100001+)
- Sectors are generic high-level categories with NACE codes
- EURIBOR assumed at 3.65% for rate calculations (adjustable in the app)
- No reference to any specific Investment Manager, administrator, or investor
- "The Investor" / "IM" / "ManCo" / "CSP" terminology throughout

## Scope boundaries

**What this tool does:**
- Specialist ops outside traditional FA BAU
- Credit events, Special NAV, Period-End NAV, waterfalls, caps, shadow book rec, distribution calc, capstock, tax data pack

**What this tool does NOT do:**
- Daily NAV production (Traditional FA team handles)
- Statutory accounts (CSP handles)
- Financial or regulatory reporting to investors/CBI (ManCo handles)
- Tax computations (Tax Adviser handles)

## Deployment

This is a **prototype** designed for local use or deployment on Streamlit Community Cloud. For production, consider:

- Replace session state with persistent storage (SQLite, Postgres)
- Add authentication (Streamlit-Authenticator or OIDC)
- Wire in real pricing sources (Markit API, Bloomberg)
- Replace synthetic data with actual GL and portfolio feeds
- Add audit trail for all user actions
- Build approval workflow integration (ManCo / Trustee sign-off)

## Streamlit Community Cloud deployment

1. Push the `specialist_app_v3` folder to your GitHub repo
2. In Streamlit Cloud, create a new app pointing at `specialist_app_v3/app.py`
3. The `.streamlit/config.toml` light theme will apply automatically
4. No secrets required — all data is synthetic and session-based

## License

Prototype / proof-of-concept. Not for production use without adaptation.
