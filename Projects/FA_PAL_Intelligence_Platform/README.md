# FA P&L Intelligence Platform

A self-contained fund administration P&L analysis tool. No dependency on upstream data formats — users download standardised CSV templates, populate with their data, and get a full interactive dashboard with forecasting and AI-generated insights.

## Philosophy

> "Take the data in any day and not depend on upstream providers. This slows progress and adds dependencies."

This tool eliminates format ambiguity by providing structured templates. Fill them in, upload, analyse. No waiting for upstream systems to change their exports.

---

## Quick Start

### Option 1: Streamlit App (Interactive Dashboard)

```bash
# Install dependencies
pip install -r requirements.txt

# Run the app
streamlit run app.py
```

Then open `http://localhost:8501` in your browser.

### Option 2: Python CLI (No Web Server Required)

The CLI script (`pnl_cli.py`) has **zero external dependencies** — it runs on Python 3.8+ with only standard library modules.

```bash
# Generate blank templates
python pnl_cli.py templates

# Generate templates with sample data
python pnl_cli.py templates-sample

# Validate your CSV files
python pnl_cli.py validate error_payouts.csv client_repricing.csv

# Generate HTML dashboard report
python pnl_cli.py report error_payouts.csv client_repricing.csv client_attrition.csv

# Full analysis: validate + CSV exports + HTML report
python pnl_cli.py analyse error_payouts.csv client_repricing.csv client_attrition.csv operational_costs.csv
```

---

## Project Structure

```
fa_pnl_platform/
├── app.py              # Streamlit interactive dashboard
├── pnl_cli.py          # Standalone Python CLI (zero dependencies)
├── requirements.txt    # Python dependencies (Streamlit version only)
├── README.md           # This file
├── templates/          # Generated CSV templates (created by CLI)
└── analysis_output/    # Analysis outputs (created by CLI)
```

---

## Templates

Four CSV templates cover the key P&L pressure points:

### 1. Error Payouts (`error_payouts.csv`)

Track all error events with root cause classification and financial impact.

| Column | Required | Type | Description |
|--------|----------|------|-------------|
| `date` | ✓ | Date | Error event date (YYYY-MM-DD) |
| `fund_name` | ✓ | Text | Fund name |
| `fund_type` | ✓ | Text | UCITS or AIF |
| `error_type` | ✓ | Text | NAV Misstatement, Pricing Error, Distribution Error, etc. |
| `root_cause` | ✓ | Text | Stale FX Rate, OTC Valuation Miss, Corporate Action Missed, etc. |
| `payout_usd` | ✓ | Number | Dollar amount paid out |
| `detected_by` | | Text | How error was caught |
| `resolution_days` | | Number | Days to resolve |

### 2. Client Repricing (`client_repricing.csv`)

Log every fee renegotiation for revenue erosion modelling.

| Column | Required | Type | Description |
|--------|----------|------|-------------|
| `date` | ✓ | Date | Repricing event date |
| `client_name` | ✓ | Text | Client identifier |
| `aum_usd_m` | ✓ | Number | Assets under management ($M) |
| `old_fee_bps` | ✓ | Number | Previous fee in basis points |
| `new_fee_bps` | ✓ | Number | New fee in basis points |
| `trigger` | ✓ | Text | What triggered the repricing |
| `contract_end_date` | | Date | Contract expiry |
| `relationship_years` | | Number | Years as client |

### 3. Client Attrition (`client_attrition.csv`)

Current client roster with health signals for churn prediction.

| Column | Required | Type | Description |
|--------|----------|------|-------------|
| `client_name` | ✓ | Text | Client identifier |
| `aum_usd_m` | ✓ | Number | AUM ($M) |
| `annual_revenue_usd` | ✓ | Number | Annual revenue from client |
| `escalations_12m` | ✓ | Number | Service escalations in last 12 months |
| `errors_12m` | ✓ | Number | Errors affecting client in last 12 months |
| `nps_score` | | Number | Net Promoter Score (0-100) |
| `relationship_years` | | Number | Years as client |
| `status` | | Text | Stable, Watch, At Risk |

### 4. Operational Costs (`operational_costs.csv`)

Monthly cost data for profitability analysis.

| Column | Required | Type | Description |
|--------|----------|------|-------------|
| `month` | ✓ | Text | Month (YYYY-MM) |
| `cost_category` | ✓ | Text | Headcount, Technology, Vendor, etc. |
| `amount_usd` | ✓ | Number | Cost amount |
| `sub_category` | | Text | More specific category |
| `fund_segment` | | Text | UCITS, AIF, All |
| `headcount` | | Number | Relevant headcount |
| `notes` | | Text | Additional notes |

---

## Dashboard Features

### KPI Summary
- Total error payouts
- Revenue lost from repricing (annualised)
- Revenue at risk from potential churn
- Total operational costs
- Net P&L impact

### Section 01: Error Cost Analysis
- Monthly error payout trend (bar chart)
- Root cause distribution (donut chart)
- Full error event log sorted by impact

### Section 02: Client Revenue Erosion
- Cumulative revenue impact over time
- Fee compression by client (old vs new)
- Repricing event log with annual revenue delta

### Section 03: Client Health & Churn Risk
- Risk vs Revenue bubble chart (size = AUM)
- Risk score computed from: escalations (×15) + errors (×10) + (100-NPS)(×0.3)
- Client health table sorted by risk score

### Section 04: AI Insights
- Pattern-detected critical alerts (top error root cause, competitive pressure)
- Churn signals (at-risk client identification)
- Opportunity recommendations (automation, retention)

---

## Roadmap

### Phase 1 (Current)
- ✅ Template-driven data input
- ✅ Upload validation with detailed logging
- ✅ Interactive Plotly dashboard (Streamlit)
- ✅ Static HTML report (CLI)
- ✅ Risk scoring model
- ✅ AI-generated insights

### Phase 2 (Next)
- [ ] Format-agnostic ingestion (accept messy upstream data)
- [ ] Column mapping heuristics (fuzzy match to schema)
- [ ] Data cleansing pipeline (dedup, outlier detection)
- [ ] Historical trend comparison (period-over-period)

### Phase 3 (Future)
- [ ] Anthropic API integration for natural language insights
- [ ] Predictive forecasting with ML models (GARCH, gradient boosting)
- [ ] CBI regulatory compliance checks
- [ ] Automated report generation and email distribution
- [ ] Integration with internal data sources (APIs, databases)

---

## Technical Notes

- **Streamlit app** requires Python 3.8+ and the packages in `requirements.txt`
- **CLI script** runs on Python 3.8+ with zero external dependencies (standard library only)
- **Sample data** is embedded in both versions for immediate demo use
- All charts use Chart.js (CLI HTML reports) or Plotly (Streamlit)
- The risk scoring model is a simple weighted composite — designed to be replaced with a proper ML model in Phase 3

---

## License

Internal use — JP Morgan Fund Administration Product Team.
