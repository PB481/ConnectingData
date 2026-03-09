"""
FA P&L Intelligence Platform — Standalone Python Script
========================================================
Runs without Streamlit. Generates templates, validates uploads,
produces an HTML report with embedded charts, and exports analysis to CSV.

Usage:
    python pnl_cli.py templates          Generate blank CSV templates
    python pnl_cli.py templates-sample   Generate CSV templates with sample data
    python pnl_cli.py validate <files>   Validate one or more CSV files
    python pnl_cli.py report <files>     Validate + generate HTML dashboard report
    python pnl_cli.py analyse <files>    Full analysis with CSV exports + HTML report

Examples:
    python pnl_cli.py templates
    python pnl_cli.py validate error_payouts.csv client_repricing.csv
    python pnl_cli.py report error_payouts.csv client_repricing.csv client_attrition.csv
    python pnl_cli.py analyse *.csv
"""

import sys
import os
import json
import csv
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ═══════════════════════════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════════════════════════
SCHEMAS = {
    "error_payouts": {
        "display": "Error Payouts",
        "required": ["date", "fund_name", "fund_type", "error_type", "root_cause", "payout_usd"],
        "optional": ["detected_by", "resolution_days"],
        "types": {"payout_usd": "number", "resolution_days": "number", "date": "date"},
    },
    "client_repricing": {
        "display": "Client Repricing",
        "required": ["date", "client_name", "aum_usd_m", "old_fee_bps", "new_fee_bps", "trigger"],
        "optional": ["contract_end_date", "relationship_years"],
        "types": {"aum_usd_m": "number", "old_fee_bps": "number", "new_fee_bps": "number", "relationship_years": "number", "date": "date"},
    },
    "client_attrition": {
        "display": "Client Attrition & Risk",
        "required": ["client_name", "aum_usd_m", "annual_revenue_usd", "escalations_12m", "errors_12m"],
        "optional": ["nps_score", "relationship_years", "status"],
        "types": {"aum_usd_m": "number", "annual_revenue_usd": "number", "escalations_12m": "number", "errors_12m": "number", "nps_score": "number", "relationship_years": "number"},
    },
    "operational_costs": {
        "display": "Operational Costs",
        "required": ["month", "cost_category", "amount_usd"],
        "optional": ["sub_category", "fund_segment", "headcount", "notes"],
        "types": {"amount_usd": "number", "headcount": "number"},
    },
}

SAMPLE_DATA = {
    "error_payouts": [
        ["2025-10-15", "IE UCITS Global Equity", "UCITS", "NAV Misstatement", "Stale FX Rate", "312400", "Automated Check", "2"],
        ["2025-10-28", "IE AIF Credit Opportunities", "AIF", "Pricing Error", "OTC Valuation Miss", "287000", "Client Query", "5"],
        ["2025-11-05", "IE UCITS Fixed Income", "UCITS", "Distribution Error", "Accrual Calculation", "198500", "Internal Audit", "3"],
        ["2025-11-18", "IE UCITS Multi-Asset", "UCITS", "NAV Misstatement", "Corporate Action Missed", "156200", "Automated Check", "1"],
        ["2025-12-02", "IE AIF Real Assets", "AIF", "Pricing Error", "Vendor Feed Lag", "124800", "Automated Check", "2"],
        ["2025-12-14", "IE UCITS EM Equity", "UCITS", "NAV Misstatement", "Stale FX Rate", "245000", "Reconciliation", "4"],
        ["2026-01-08", "IE UCITS Global Equity", "UCITS", "Trade Processing", "Settlement Fail", "89000", "Operations", "3"],
        ["2026-01-22", "IE AIF Private Debt", "AIF", "Pricing Error", "OTC Valuation Miss", "178000", "Client Query", "7"],
        ["2026-02-03", "IE UCITS ESG Screened", "UCITS", "NAV Misstatement", "Index Rebalance Miss", "134500", "Automated Check", "1"],
        ["2026-02-15", "IE UCITS Fixed Income", "UCITS", "Distribution Error", "Coupon Accrual", "92000", "Internal Audit", "2"],
        ["2026-02-28", "IE AIF Credit Opportunities", "AIF", "Pricing Error", "Vendor Feed Lag", "201300", "Reconciliation", "3"],
        ["2026-03-05", "IE UCITS Multi-Asset", "UCITS", "NAV Misstatement", "Stale FX Rate", "168000", "Automated Check", "1"],
    ],
    "client_repricing": [
        ["2025-07-01", "Client Alpha", "4200", "3.2", "2.4", "Competitor bid", "2026-06-30", "8"],
        ["2025-08-15", "Client Beta", "6800", "2.8", "2.2", "Volume tier", "2027-03-31", "12"],
        ["2025-09-01", "Client Gamma", "3100", "3.5", "2.6", "Service issues", "2026-09-30", "5"],
        ["2025-10-20", "Client Delta", "8500", "2.1", "1.8", "Contract renewal", "2028-12-31", "15"],
        ["2025-11-10", "Client Epsilon", "2700", "4.0", "3.1", "Competitor bid", "2026-11-30", "3"],
        ["2026-01-05", "Client Zeta", "5400", "2.5", "2.1", "Volume tier", "2027-06-30", "10"],
        ["2026-01-25", "Client Eta", "1800", "3.8", "3.2", "Contract renewal", "2026-12-31", "6"],
        ["2026-02-12", "Client Theta", "3600", "3.0", "2.4", "Competitor bid", "2027-02-28", "7"],
    ],
    "client_attrition": [
        ["Client Alpha", "4200", "1344000", "4", "3", "45", "8", "At Risk"],
        ["Client Beta", "6800", "1496000", "1", "1", "72", "12", "Stable"],
        ["Client Gamma", "3100", "1085000", "6", "5", "32", "5", "At Risk"],
        ["Client Delta", "8500", "1530000", "0", "0", "85", "15", "Stable"],
        ["Client Epsilon", "2700", "1080000", "3", "2", "55", "3", "Watch"],
        ["Client Zeta", "5400", "1134000", "1", "1", "78", "10", "Stable"],
        ["Client Eta", "1800", "684000", "2", "3", "48", "6", "Watch"],
        ["Client Theta", "3600", "1080000", "5", "4", "38", "7", "At Risk"],
        ["Client Iota", "4100", "943000", "0", "1", "82", "9", "Stable"],
        ["Client Kappa", "2200", "748000", "3", "2", "60", "4", "Watch"],
    ],
    "operational_costs": [
        ["2025-10", "Headcount", "Fund Accounting", "420000", "UCITS", "35", ""],
        ["2025-10", "Technology", "Systems", "125000", "All", "0", ""],
        ["2025-10", "Vendor", "Pricing Services", "85000", "All", "0", ""],
        ["2025-11", "Headcount", "Fund Accounting", "425000", "UCITS", "35", ""],
        ["2025-11", "Technology", "Systems", "125000", "All", "0", ""],
        ["2025-12", "Headcount", "Fund Accounting", "430000", "UCITS", "36", ""],
        ["2025-12", "Technology", "Systems", "140000", "All", "0", "Platform upgrade"],
        ["2026-01", "Headcount", "Fund Accounting", "430000", "UCITS", "36", ""],
        ["2026-01", "Vendor", "Pricing Services", "90000", "All", "0", "Price increase"],
        ["2026-02", "Headcount", "Fund Accounting", "435000", "UCITS", "36", ""],
    ],
}


# ═══════════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════════
def fmt_currency(val):
    abs_val = abs(val)
    sign = "-" if val < 0 else ""
    if abs_val >= 1_000_000:
        return f"{sign}${abs_val / 1_000_000:.1f}M"
    if abs_val >= 1_000:
        return f"{sign}${abs_val / 1_000:.0f}K"
    return f"{sign}${abs_val:.0f}"


def print_header(text):
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}")


def print_ok(msg):
    print(f"  ✓ {msg}")


def print_warn(msg):
    print(f"  ⚠ {msg}")


def print_err(msg):
    print(f"  ✗ {msg}")


def read_csv_file(filepath):
    """Read a CSV file and return headers + rows as list of dicts."""
    with open(filepath, "r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames or []
        rows = [row for row in reader if any(v.strip() for v in row.values())]
    return headers, rows


def detect_type(headers, filename):
    fn = filename.lower()
    for key, schema in SCHEMAS.items():
        if key in fn:
            return key
        matched = sum(1 for r in schema["required"] if r in headers)
        if matched >= len(schema["required"]) * 0.7:
            return key
    return None


def is_number(val):
    try:
        float(val)
        return True
    except (ValueError, TypeError):
        return False


def is_date(val):
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y", "%Y-%m"):
        try:
            datetime.strptime(val.strip(), fmt)
            return True
        except (ValueError, AttributeError):
            continue
    return False


def to_float(val, default=0.0):
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def validate_file(headers, rows, schema_key):
    schema = SCHEMAS[schema_key]
    log = []
    passed, warns, errs = 0, 0, 0

    for req in schema["required"]:
        if req in headers:
            log.append(("pass", f'Required column "{req}" found'))
            passed += 1
        else:
            log.append(("fail", f'Missing required column "{req}"'))
            errs += 1

    for opt in schema["optional"]:
        if opt in headers:
            log.append(("pass", f'Optional column "{opt}" found'))
            passed += 1
        else:
            log.append(("warn", f'Optional column "{opt}" missing'))
            warns += 1

    for col, expected in schema["types"].items():
        if col not in headers:
            continue
        bad = 0
        for row in rows:
            val = row.get(col, "").strip()
            if not val:
                continue
            if expected == "number" and not is_number(val):
                bad += 1
            elif expected == "date" and not is_date(val):
                bad += 1
        if bad > 0:
            log.append(("warn", f'{bad} rows have invalid {expected} in "{col}"'))
            warns += 1
        else:
            log.append(("pass", f'Column "{col}" type check passed ({expected})'))
            passed += 1

    if len(rows) == 0:
        log.append(("fail", "File is empty"))
        errs += 1
    else:
        log.append(("pass", f"{len(rows)} data rows loaded"))
        passed += 1

    return passed, warns, errs, log


# ═══════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════
def cmd_templates(with_sample=False):
    print_header("Generating CSV Templates")
    output_dir = Path("templates")
    output_dir.mkdir(exist_ok=True)

    for key, schema in SCHEMAS.items():
        headers = schema["required"] + schema["optional"]
        suffix = "_sample" if with_sample else ""
        filepath = output_dir / f"{key}{suffix}.csv"

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            if with_sample and key in SAMPLE_DATA:
                for row in SAMPLE_DATA[key]:
                    writer.writerow(row)

        print_ok(f"{filepath} ({len(headers)} columns" + (f", {len(SAMPLE_DATA.get(key, []))} rows" if with_sample else "") + ")")

    print(f"\n  Templates saved to ./{output_dir}/")


def cmd_validate(filepaths):
    print_header("Validating Files")
    all_data = {}
    total_p, total_w, total_e = 0, 0, 0

    for fp in filepaths:
        if not os.path.exists(fp):
            print_err(f"File not found: {fp}")
            continue

        headers, rows = read_csv_file(fp)
        detected = detect_type(headers, os.path.basename(fp))

        if not detected:
            print_err(f"{fp}: Could not match to any template schema")
            continue

        schema = SCHEMAS[detected]
        print(f"\n  📄 {fp} → {schema['display']}")

        passed, warns, errs, log = validate_file(headers, rows, detected)
        total_p += passed
        total_w += warns
        total_e += errs

        for level, msg in log:
            {"pass": print_ok, "warn": print_warn, "fail": print_err}[level](msg)

        all_data[detected] = rows

    print(f"\n  Summary: ✓{total_p}  ⚠{total_w}  ✗{total_e}")
    return all_data


def cmd_report(filepaths):
    all_data = cmd_validate(filepaths)
    if not all_data:
        print_err("No valid data to generate report.")
        return

    print_header("Generating HTML Dashboard Report")
    html = generate_html_report(all_data)
    output_path = Path("pnl_report.html")
    output_path.write_text(html, encoding="utf-8")
    print_ok(f"Report saved to {output_path}")
    print(f"  Open in browser: file://{output_path.resolve()}")


def cmd_analyse(filepaths):
    all_data = cmd_validate(filepaths)
    if not all_data:
        print_err("No valid data to analyse.")
        return

    print_header("Running Analysis")
    output_dir = Path("analysis_output")
    output_dir.mkdir(exist_ok=True)

    # Error analysis
    if "error_payouts" in all_data:
        rows = all_data["error_payouts"]
        total = sum(to_float(r.get("payout_usd", 0)) for r in rows)
        print_ok(f"Total error payouts: {fmt_currency(total)}")

        causes = defaultdict(float)
        for r in rows:
            causes[r.get("root_cause", "Unknown")] += to_float(r.get("payout_usd", 0))

        cause_file = output_dir / "error_root_causes.csv"
        with open(cause_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["root_cause", "total_payout_usd", "pct_of_total"])
            for cause, val in sorted(causes.items(), key=lambda x: -x[1]):
                w.writerow([cause, f"{val:.0f}", f"{val/total*100:.1f}%"])
        print_ok(f"Root cause analysis → {cause_file}")

    # Repricing analysis
    if "client_repricing" in all_data:
        rows = all_data["client_repricing"]
        total_lost = 0
        repricing_out = []
        for r in rows:
            delta = (to_float(r.get("old_fee_bps", 0)) - to_float(r.get("new_fee_bps", 0))) / 10000 * to_float(r.get("aum_usd_m", 0)) * 1_000_000
            total_lost += delta
            repricing_out.append({
                "client": r.get("client_name", ""),
                "aum_m": r.get("aum_usd_m", ""),
                "old_bps": r.get("old_fee_bps", ""),
                "new_bps": r.get("new_fee_bps", ""),
                "annual_revenue_lost": f"{delta:.0f}",
                "trigger": r.get("trigger", ""),
            })
        print_ok(f"Total revenue lost from repricing: {fmt_currency(total_lost)}/yr")

        rp_file = output_dir / "repricing_impact.csv"
        with open(rp_file, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["client", "aum_m", "old_bps", "new_bps", "annual_revenue_lost", "trigger"])
            w.writeheader()
            w.writerows(repricing_out)
        print_ok(f"Repricing impact → {rp_file}")

    # Attrition analysis
    if "client_attrition" in all_data:
        rows = all_data["client_attrition"]
        scored = []
        for r in rows:
            esc = to_float(r.get("escalations_12m", 0))
            err = to_float(r.get("errors_12m", 0))
            nps = to_float(r.get("nps_score", 50)) or 50
            risk = min(100, int(esc * 15 + err * 10 + (100 - nps) * 0.3))
            scored.append({
                "client": r.get("client_name", ""),
                "aum_m": r.get("aum_usd_m", ""),
                "annual_revenue": r.get("annual_revenue_usd", ""),
                "risk_score": risk,
                "status": r.get("status", ""),
            })
        scored.sort(key=lambda x: -x["risk_score"])

        at_file = output_dir / "client_risk_scores.csv"
        with open(at_file, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["client", "aum_m", "annual_revenue", "risk_score", "status"])
            w.writeheader()
            w.writerows(scored)
        print_ok(f"Client risk scores → {at_file}")

        high_risk = [s for s in scored if s["risk_score"] > 60]
        print_ok(f"High-risk clients (>60): {len(high_risk)}")

    # Generate HTML report
    html = generate_html_report(all_data)
    report_path = output_dir / "pnl_dashboard.html"
    report_path.write_text(html, encoding="utf-8")
    print_ok(f"Dashboard report → {report_path}")

    print(f"\n  All outputs saved to ./{output_dir}/")


# ═══════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════
def generate_html_report(all_data):
    """Generate a self-contained HTML dashboard report from processed data."""

    errors = all_data.get("error_payouts", [])
    repricing = all_data.get("client_repricing", [])
    attrition = all_data.get("client_attrition", [])
    costs = all_data.get("operational_costs", [])

    total_error = sum(to_float(r.get("payout_usd", 0)) for r in errors)
    total_rev_lost = sum(
        (to_float(r.get("old_fee_bps", 0)) - to_float(r.get("new_fee_bps", 0))) / 10000
        * to_float(r.get("aum_usd_m", 0)) * 1_000_000
        for r in repricing
    )
    total_costs = sum(to_float(r.get("amount_usd", 0)) for r in costs)

    # Monthly error data for chart
    monthly_errors = defaultdict(float)
    for r in errors:
        m = r.get("date", "")[:7]
        if m:
            monthly_errors[m] += to_float(r.get("payout_usd", 0))
    months_sorted = sorted(monthly_errors.keys())
    month_labels = json.dumps(months_sorted)
    month_values = json.dumps([round(monthly_errors[m] / 1000, 1) for m in months_sorted])

    # Root causes for chart
    cause_totals = defaultdict(float)
    for r in errors:
        cause_totals[r.get("root_cause", "Unknown")] += to_float(r.get("payout_usd", 0))
    cause_sorted = sorted(cause_totals.items(), key=lambda x: -x[1])
    cause_labels = json.dumps([c[0] for c in cause_sorted])
    cause_values = json.dumps([c[1] for c in cause_sorted])

    # Error table rows
    error_rows_html = ""
    for r in sorted(errors, key=lambda x: -to_float(x.get("payout_usd", 0))):
        payout = to_float(r.get("payout_usd", 0))
        error_rows_html += f"""<tr>
            <td>{r.get('date','')}</td><td>{r.get('fund_name','')}</td>
            <td>{r.get('error_type','')}</td><td>{r.get('root_cause','')}</td>
            <td style="color:#f04848">${payout:,.0f}</td>
            <td>{r.get('detected_by','—')}</td><td>{r.get('resolution_days','—')}</td>
        </tr>"""

    # Repricing table rows
    reprice_rows_html = ""
    for r in repricing:
        delta = (to_float(r.get("old_fee_bps", 0)) - to_float(r.get("new_fee_bps", 0))) / 10000 * to_float(r.get("aum_usd_m", 0)) * 1_000_000
        reprice_rows_html += f"""<tr>
            <td>{r.get('date','')}</td><td>{r.get('client_name','')}</td>
            <td>{r.get('aum_usd_m','')}</td><td>{r.get('old_fee_bps','')}</td>
            <td>{r.get('new_fee_bps','')}</td>
            <td style="color:#f04848">-${abs(delta):,.0f}</td>
            <td>{r.get('trigger','')}</td>
        </tr>"""

    # Attrition table
    attrition_rows_html = ""
    scored_clients = []
    for r in attrition:
        esc = to_float(r.get("escalations_12m", 0))
        err = to_float(r.get("errors_12m", 0))
        nps = to_float(r.get("nps_score", 50)) or 50
        risk = min(100, int(esc * 15 + err * 10 + (100 - nps) * 0.3))
        scored_clients.append({"name": r.get("client_name", ""), "risk": risk, "rev": to_float(r.get("annual_revenue_usd", 0)), "aum": to_float(r.get("aum_usd_m", 0))})
        color = "#f04848" if risk > 60 else "#eda025" if risk > 35 else "#12c47a"
        attrition_rows_html += f"""<tr>
            <td>{r.get('client_name','')}</td><td>{r.get('aum_usd_m','')}</td>
            <td>${to_float(r.get('annual_revenue_usd',0)):,.0f}</td>
            <td>{r.get('escalations_12m','')}</td><td>{r.get('errors_12m','')}</td>
            <td>{r.get('nps_score','—')}</td>
            <td><div style="width:70px;height:5px;background:#1a2540;border-radius:3px"><div style="width:{risk}%;height:100%;background:{color};border-radius:3px"></div></div></td>
        </tr>"""

    # Churn chart data
    churn_data = json.dumps(scored_clients)

    at_risk_count = sum(1 for s in scored_clients if s["risk"] > 60)
    at_risk_rev = sum(s["rev"] for s in scored_clients if s["risk"] > 60)

    # Insights
    insights_html = ""
    if errors:
        top_cause = cause_sorted[0] if cause_sorted else ("Unknown", 0)
        total_err = sum(c[1] for c in cause_sorted)
        pct = int(top_cause[1] / total_err * 100) if total_err > 0 else 0
        insights_html += f'<div class="insight critical"><span class="tag critical">CRITICAL · ERROR PATTERN</span>"{top_cause[0]}" is the #1 root cause at {fmt_currency(top_cause[1])} ({pct}% of total). Recommend targeted remediation.</div>'

    if repricing:
        comp = [r for r in repricing if "competitor" in r.get("trigger", "").lower()]
        if comp:
            insights_html += f'<div class="insight critical"><span class="tag critical">CRITICAL · COMPETITIVE PRESSURE</span>{len(comp)} repricing events from competitor bids. Proactive QBR programme recommended.</div>'

    if at_risk_count > 0:
        insights_html += f'<div class="insight critical"><span class="tag critical">CRITICAL · CHURN SIGNAL</span>{at_risk_count} clients at risk with {fmt_currency(at_risk_rev)} combined annual revenue.</div>'

    insights_html += '<div class="insight"><span class="tag info">OPPORTUNITY · AUTOMATION</span>Automated pre-NAV checks could catch the majority of error types in this dataset.</div>'
    insights_html += '<div class="insight"><span class="tag info">OPPORTUNITY · RETENTION</span>Expanding QBRs to all top-tier clients strengthens the #1 retention differentiator.</div>'

    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FA P&L Intelligence Report</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root {{ --bg:#0a0e17; --bg2:#131c30; --border:#243352; --t0:#f0f4fa; --t1:#c2ccdf; --t2:#8494b2; --t3:#5a6d8e;
  --red:#f04848; --amber:#eda025; --green:#12c47a; --blue:#3a7bfd; --purple:#9b6dff; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'IBM Plex Sans',sans-serif; background:var(--bg); color:var(--t0); padding:32px; }}
.header {{ text-align:center; margin-bottom:32px; }}
.header h1 {{ font-size:28px; font-weight:700; margin-bottom:6px; }}
.header p {{ color:var(--t2); font-size:13px; }}
.kpis {{ display:grid; grid-template-columns:repeat(5,1fr); gap:14px; margin-bottom:28px; }}
.kpi {{ background:var(--bg2); border:1px solid var(--border); border-radius:10px; padding:18px; position:relative; overflow:hidden; }}
.kpi::after {{ content:''; position:absolute; top:0; left:0; right:0; height:2px; }}
.kpi.r::after {{ background:var(--red); }} .kpi.a::after {{ background:var(--amber); }}
.kpi.g::after {{ background:var(--green); }} .kpi.b::after {{ background:var(--blue); }}
.kpi-l {{ font-size:11px; color:var(--t3); text-transform:uppercase; letter-spacing:.7px; margin-bottom:6px; }}
.kpi-v {{ font-family:'IBM Plex Mono',monospace; font-size:22px; font-weight:500; }}
.kpi-d {{ font-size:11px; font-family:'IBM Plex Mono',monospace; color:var(--t3); margin-top:4px; }}
.sec {{ display:flex; align-items:center; gap:10px; margin:28px 0 16px; padding-bottom:10px; border-bottom:1px solid var(--border); }}
.sec-n {{ font-family:'IBM Plex Mono',monospace; font-size:11px; color:var(--blue); background:rgba(58,123,253,.12); padding:3px 8px; border-radius:4px; }}
.sec-t {{ font-size:16px; font-weight:600; }}
.grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
.panel {{ background:var(--bg2); border:1px solid var(--border); border-radius:10px; padding:22px; }}
.panel-full {{ grid-column:1/-1; }}
.chart-box {{ height:280px; position:relative; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ text-align:left; padding:10px 12px; color:var(--t3); font-size:10px; text-transform:uppercase; border-bottom:1px solid var(--border); }}
td {{ padding:10px 12px; border-bottom:1px solid rgba(36,51,82,.4); color:var(--t1); font-family:'IBM Plex Mono',monospace; font-size:11px; }}
.insight {{ padding:14px 16px; background:#0c1220; border-radius:8px; margin-bottom:8px; border-left:3px solid var(--blue); font-size:12px; line-height:1.7; color:var(--t1); }}
.insight.critical {{ border-left-color:var(--red); }} .insight.warning {{ border-left-color:var(--amber); }}
.tag {{ font-size:9px; font-family:'IBM Plex Mono',monospace; text-transform:uppercase; display:block; margin-bottom:4px; }}
.tag.critical {{ color:var(--red); }} .tag.warning {{ color:var(--amber); }} .tag.info {{ color:var(--blue); }}
.footer {{ margin-top:32px; text-align:center; font-size:11px; color:var(--t3); font-family:'IBM Plex Mono',monospace; }}
@media(max-width:900px) {{ .kpis,.grid {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>FA P&L Intelligence Report</h1>
  <p>Generated {now} · Fund Administration Product Team</p>
</div>

<div class="kpis">
  <div class="kpi r"><div class="kpi-l">Error Payouts</div><div class="kpi-v" style="color:var(--red)">{fmt_currency(total_error)}</div><div class="kpi-d">{len(errors)} events</div></div>
  <div class="kpi a"><div class="kpi-l">Revenue Lost (Repricing)</div><div class="kpi-v" style="color:var(--amber)">{fmt_currency(total_rev_lost)}/yr</div><div class="kpi-d">{len(repricing)} clients</div></div>
  <div class="kpi r"><div class="kpi-l">Revenue at Risk (Churn)</div><div class="kpi-v" style="color:var(--red)">{fmt_currency(at_risk_rev)}</div><div class="kpi-d">{at_risk_count} at risk</div></div>
  <div class="kpi b"><div class="kpi-l">Total Costs</div><div class="kpi-v" style="color:var(--blue)">{fmt_currency(total_costs)}</div><div class="kpi-d">{len(costs)} items</div></div>
  <div class="kpi g"><div class="kpi-l">Net P&L Impact</div><div class="kpi-v" style="color:var(--green)">{fmt_currency(-(total_error+total_rev_lost))}</div><div class="kpi-d">Errors + Repricing</div></div>
</div>

<div class="sec"><span class="sec-n">01</span><span class="sec-t">Error Cost Analysis</span></div>
<div class="grid">
  <div class="panel"><div class="chart-box"><canvas id="c1"></canvas></div></div>
  <div class="panel"><div class="chart-box"><canvas id="c2"></canvas></div></div>
  <div class="panel panel-full">
    <table><thead><tr><th>Date</th><th>Fund</th><th>Type</th><th>Root Cause</th><th>Payout</th><th>Detected By</th><th>Days</th></tr></thead>
    <tbody>{error_rows_html}</tbody></table>
  </div>
</div>

<div class="sec"><span class="sec-n">02</span><span class="sec-t">Client Revenue Erosion</span></div>
<div class="grid">
  <div class="panel panel-full">
    <table><thead><tr><th>Date</th><th>Client</th><th>AUM ($M)</th><th>Old Fee</th><th>New Fee</th><th>Δ Revenue/yr</th><th>Trigger</th></tr></thead>
    <tbody>{reprice_rows_html}</tbody></table>
  </div>
</div>

<div class="sec"><span class="sec-n">03</span><span class="sec-t">Client Health & Churn Risk</span></div>
<div class="grid">
  <div class="panel"><div class="chart-box"><canvas id="c3"></canvas></div></div>
  <div class="panel">
    <table><thead><tr><th>Client</th><th>AUM</th><th>Revenue</th><th>Escalations</th><th>Errors</th><th>NPS</th><th>Risk</th></tr></thead>
    <tbody>{attrition_rows_html}</tbody></table>
  </div>
</div>

<div class="sec"><span class="sec-n">04</span><span class="sec-t">AI Insights</span></div>
<div class="grid"><div class="panel panel-full">{insights_html}</div></div>

<div class="footer">FA P&L Intelligence Report · v1.0 · {now}</div>

<script>
Chart.defaults.color='#8494b2'; Chart.defaults.borderColor='rgba(36,51,82,.5)';
Chart.defaults.font.family="'IBM Plex Sans',sans-serif"; Chart.defaults.font.size=11;

new Chart(document.getElementById('c1'),{{
  type:'bar',
  data:{{ labels:{month_labels}, datasets:[{{ label:'Payout ($K)', data:{month_values}, backgroundColor:'rgba(240,72,72,.65)', borderRadius:5 }}] }},
  options:{{ responsive:true, maintainAspectRatio:false, plugins:{{legend:{{display:false}}}},
    scales:{{ x:{{grid:{{display:false}}}}, y:{{beginAtZero:true, grid:{{color:'rgba(36,51,82,.3)'}}, ticks:{{callback:v=>'$'+v+'K'}}}} }} }}
}});

new Chart(document.getElementById('c2'),{{
  type:'doughnut',
  data:{{ labels:{cause_labels}, datasets:[{{ data:{cause_values}, backgroundColor:['rgba(240,72,72,.8)','rgba(237,160,37,.8)','rgba(155,109,255,.8)','rgba(58,123,253,.8)','rgba(18,196,122,.6)','rgba(90,109,142,.5)'], borderWidth:0 }}] }},
  options:{{ responsive:true, maintainAspectRatio:false, cutout:'60%', plugins:{{legend:{{position:'right',labels:{{boxWidth:10,padding:8,font:{{size:10}}}}}}}} }}
}});

const churnData = {churn_data};
new Chart(document.getElementById('c3'),{{
  type:'bubble',
  data:{{ datasets:[{{ data:churnData.map(c=>({{x:c.risk,y:c.rev/1000,r:Math.max(5,c.aum/600)}})),
    backgroundColor:churnData.map(c=>c.risk>60?'rgba(240,72,72,.5)':c.risk>35?'rgba(237,160,37,.5)':'rgba(18,196,122,.4)'),
    borderColor:churnData.map(c=>c.risk>60?'rgba(240,72,72,.9)':c.risk>35?'rgba(237,160,37,.9)':'rgba(18,196,122,.8)'), borderWidth:1.5 }}] }},
  options:{{ responsive:true, maintainAspectRatio:false, plugins:{{legend:{{display:false}},
    tooltip:{{callbacks:{{label:ctx=>churnData[ctx.dataIndex].name+' · Risk:'+churnData[ctx.dataIndex].risk+'%'}}}}}},
    scales:{{ x:{{title:{{display:true,text:'Risk (%)'}},min:0,max:100,grid:{{color:'rgba(36,51,82,.3)'}}}},
      y:{{title:{{display:true,text:'Revenue ($K)'}},grid:{{color:'rgba(36,51,82,.3)'}},ticks:{{callback:v=>'$'+v+'K'}}}} }} }}
}});
</script>
</body></html>"""
    return html


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return

    cmd = sys.argv[1].lower()

    if cmd == "templates":
        cmd_templates(with_sample=False)
    elif cmd == "templates-sample":
        cmd_templates(with_sample=True)
    elif cmd == "validate":
        if len(sys.argv) < 3:
            print_err("Provide CSV files: python pnl_cli.py validate *.csv")
            return
        cmd_validate(sys.argv[2:])
    elif cmd == "report":
        if len(sys.argv) < 3:
            print_err("Provide CSV files: python pnl_cli.py report *.csv")
            return
        cmd_report(sys.argv[2:])
    elif cmd == "analyse" or cmd == "analyze":
        if len(sys.argv) < 3:
            print_err("Provide CSV files: python pnl_cli.py analyse *.csv")
            return
        cmd_analyse(sys.argv[2:])
    else:
        print_err(f'Unknown command: "{cmd}"')
        print(__doc__)


if __name__ == "__main__":
    main()
