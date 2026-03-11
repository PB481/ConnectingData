"""
FA Deal Pricing Engine — Standalone Python CLI
===============================================
Zero external dependencies. Runs on Python 3.8+.

Usage:
    python deal_pricing_cli.py                           Interactive mode
    python deal_pricing_cli.py --quick                   Quick calc with defaults
    python deal_pricing_cli.py --aum 5000 --type ucits   Specify parameters
    python deal_pricing_cli.py --export report.html      Generate HTML deal sheet

All Parameters:
    --name TEXT          Client/deal name (default: "Prospective Fund Co.")
    --type TEXT          Fund type: ucits, aif, etf (default: ucits)
    --domicile TEXT      ireland, luxembourg, cayman (default: ireland)
    --strategy TEXT      equity, fixed_income, multi_asset, alternatives, real_assets, money_market
    --complexity TEXT    standard, moderate, complex, highly_complex
    --aum INT            Expected AUM in $M (default: 2000)
    --classes INT        Share classes (default: 5)
    --subfunds INT       Sub-funds (default: 1)
    --nav TEXT           daily, weekly, monthly (default: daily)
    --txns INT           Monthly transactions (default: 500)
    --margin INT         Target margin % (default: 25)
    --competitive TEXT   sole_bid, competitive, highly_competitive, incumbent_defense
    --win INT            Win probability % (default: 40)
    --export FILENAME    Export HTML deal sheet
    --quick              Run with defaults, no prompts
"""

import sys
import argparse
import json
from datetime import datetime
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
# COST MODEL
# ═══════════════════════════════════════════════════════════════
COST_MODEL = {
    "base_cost": {"ucits": 85000, "aif": 110000, "etf": 95000},
    "complexity_mult": {"standard": 1.0, "moderate": 1.35, "complex": 1.8, "highly_complex": 2.5},
    "domicile_mult": {"ireland": 1.0, "luxembourg": 1.12, "cayman": 0.9},
    "nav_freq_mult": {"daily": 1.0, "weekly": 0.55, "monthly": 0.35},
    "strategy_mult": {"equity": 1.0, "fixed_income": 1.15, "multi_asset": 1.25, "alternatives": 1.6, "real_assets": 1.8, "money_market": 0.75},
    "share_class_cost": 4500,
    "sub_fund_cost": 40000,
    "txn_cost_per": 1.2,
    "comp_adj": {"sole_bid": 1.15, "competitive": 1.0, "highly_competitive": 0.88, "incumbent_defense": 0.92},
}

SERVICES = {
    "Transfer Agency": 35000,
    "Custody": 25000,
    "FX Execution": 12000,
    "CBI Regulatory Reporting": 28000,
    "Performance & Attribution": 22000,
    "Investor Reporting": 18000,
    "Tax Services": 32000,
}

DEFAULT_SERVICES = ["Transfer Agency", "FX Execution", "CBI Regulatory Reporting", "Investor Reporting"]


def fmt(val):
    if abs(val) >= 1_000_000: return f"${val/1_000_000:.1f}M"
    if abs(val) >= 1_000: return f"${val/1_000:.0f}K"
    return f"${val:.0f}"


def hr(): print(f"{'─'*60}")


def header(text):
    print(f"\n{'═'*60}")
    print(f"  {text}")
    print(f"{'═'*60}")


def compute(args, services=None):
    if services is None:
        services = DEFAULT_SERVICES

    base = COST_MODEL["base_cost"].get(args.type, 85000)
    c_m = COST_MODEL["complexity_mult"].get(args.complexity, 1.0)
    d_m = COST_MODEL["domicile_mult"].get(args.domicile, 1.0)
    n_m = COST_MODEL["nav_freq_mult"].get(args.nav, 1.0)
    s_m = COST_MODEL["strategy_mult"].get(args.strategy, 1.0)

    core = base * c_m * d_m * n_m * s_m
    core += (args.classes - 1) * COST_MODEL["share_class_cost"]
    core += (args.subfunds - 1) * COST_MODEL["sub_fund_cost"]
    core += args.txns * 12 * COST_MODEL["txn_cost_per"]

    svc_cost = 0
    svc_items = []
    for name in services:
        cost = SERVICES.get(name, 0) * c_m
        svc_cost += cost
        svc_items.append((name, cost))

    total = core + svc_cost
    aum_usd = args.aum * 1_000_000
    margin = args.margin / 100
    target_rev = total / (1 - margin) if margin < 1 else total * 2
    target_fee = target_rev / aum_usd * 10000
    adj = COST_MODEL["comp_adj"].get(args.competitive, 1.0)

    scenarios = {}
    for label, mult in [("Aggressive", 0.82), ("Recommended", 1.0), ("Premium", 1.18)]:
        fee = round(target_fee * mult * adj, 1)
        rev = fee / 10000 * aum_usd
        mg = (rev - total) / rev * 100 if rev > 0 else 0
        be = total / (fee / 10000) / 1_000_000 if fee > 0 else 0
        scenarios[label] = {"fee": fee, "revenue": rev, "margin": mg, "breakeven": be}

    # Sensitivity
    fee_levels = [1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0]
    aum_levels = [int(args.aum * m) for m in [0.5, 0.75, 1.0, 1.5, 2.0]]
    sensitivity = []
    for a in aum_levels:
        row = {"aum": a}
        for f in fee_levels:
            rev = f / 10000 * a * 1_000_000
            mg = (rev - total) / rev * 100 if rev > 0 else -100
            row[f] = round(mg)
        sensitivity.append(row)

    return {
        "core_cost": core, "svc_cost": svc_cost, "total_cost": total,
        "svc_items": svc_items, "scenarios": scenarios,
        "sensitivity": sensitivity, "fee_levels": fee_levels, "aum_levels": aum_levels,
        "prob_weighted": scenarios["Recommended"]["revenue"] * (args.win / 100),
    }


def print_results(args, result):
    rec = result["scenarios"]["Recommended"]

    header("DEAL PRICING RESULTS")
    print(f"  Client:     {args.name}")
    print(f"  Fund:       {args.type.upper()} · {args.strategy.replace('_',' ')} · {args.complexity.replace('_',' ')}")
    print(f"  Domicile:   {args.domicile.capitalize()} · {args.nav.capitalize()} NAV")
    print(f"  AUM:        ${args.aum:,}M · {args.classes} classes · {args.subfunds} sub-funds")
    print(f"  Context:    {args.competitive.replace('_',' ')} · {args.win}% win prob")

    header("COST-TO-SERVE")
    print(f"  Core FA Cost:      {fmt(result['core_cost']):>12}")
    for name, cost in result["svc_items"]:
        print(f"  + {name:<20} {fmt(cost):>12}")
    hr()
    print(f"  TOTAL COST:        {fmt(result['total_cost']):>12} /yr")

    header("PRICING SCENARIOS")
    for label, data in result["scenarios"].items():
        marker = " ★" if label == "Recommended" else "  "
        mc = "✓" if data["margin"] >= 20 else "~" if data["margin"] >= 10 else "✗"
        print(f"{marker} {label:<14} {data['fee']:>5} bps │ Rev: {fmt(data['revenue']):>8}/yr │ Margin: {mc} {data['margin']:.1f}% │ B/E: ${data['breakeven']:,.0f}M")

    print(f"\n  Probability-weighted revenue: {fmt(result['prob_weighted'])}/yr")

    header("MARGIN SENSITIVITY (Fee bps × AUM $M)")
    # Header row
    print(f"  {'AUM':>10}", end="")
    for f in result["fee_levels"]:
        label = f"{f}bps"
        if abs(f - rec["fee"]) < 0.3:
            label += "★"
        print(f" {label:>7}", end="")
    print()
    hr()
    for row in result["sensitivity"]:
        print(f"  ${row['aum']:>8,}", end="")
        for f in result["fee_levels"]:
            m = row[f]
            indicator = "+" if m >= 20 else "~" if m >= 10 else "-"
            print(f"  {indicator}{m:>4}%", end="")
        print()
    print(f"\n  Legend: + ≥20% margin   ~ 10-20%   - <10%")


def export_html(args, result, filename):
    rec = result["scenarios"]["Recommended"]
    now = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    scenarios_html = ""
    for label, data in result["scenarios"].items():
        mc = "#0fc882" if data["margin"] >= 20 else "#e8a317" if data["margin"] >= 10 else "#f0463c"
        border = "border:2px solid #0fc882;" if label == "Recommended" else ""
        tag = "<div style='font-size:9px;color:#0fc882;margin-bottom:4px'>★ RECOMMENDED</div>" if label == "Recommended" else ""
        scenarios_html += f"""<div style="background:#0b1018;border:1px solid #1e3048;border-radius:10px;padding:22px;text-align:center;flex:1;{border}">
            {tag}<div style="font-size:10px;color:#4e6380;text-transform:uppercase;letter-spacing:.8px">{label}</div>
            <div style="font-family:monospace;font-size:28px;font-weight:600;margin:8px 0">{data['fee']}</div>
            <div style="font-size:11px;color:#7a8faa">basis points</div>
            <div style="font-size:11px;color:#7a8faa;margin-top:10px">Revenue: <b>{fmt(data['revenue'])}/yr</b></div>
            <div style="font-size:11px;color:{mc}">Margin: {data['margin']:.1f}%</div>
            <div style="font-size:11px;color:#7a8faa">Break-even: ${data['breakeven']:,.0f}M</div>
        </div>"""

    cost_rows = f"<tr><td>Core FA</td><td style='text-align:right;font-family:monospace'>{fmt(result['core_cost'])}</td></tr>"
    for name, cost in result["svc_items"]:
        cost_rows += f"<tr><td>{name}</td><td style='text-align:right;font-family:monospace'>{fmt(cost)}</td></tr>"
    cost_rows += f"<tr style='font-weight:700;border-top:2px solid #1e3048'><td>Total</td><td style='text-align:right;font-family:monospace'>{fmt(result['total_cost'])}/yr</td></tr>"

    sens_header = "<th>AUM ($M)</th>"
    for f in result["fee_levels"]:
        star = " ★" if abs(f - rec["fee"]) < 0.3 else ""
        sens_header += f"<th>{f} bps{star}</th>"

    sens_rows = ""
    for row in result["sensitivity"]:
        sens_rows += f"<tr><td style='font-weight:600'>${row['aum']:,}</td>"
        for f in result["fee_levels"]:
            m = row[f]
            c = "#0fc882" if m >= 20 else "#e8a317" if m >= 10 else "#f0463c"
            sens_rows += f"<td style='color:{c};text-align:center'>{m}%</td>"
        sens_rows += "</tr>"

    summary_items = [
        ("Client", args.name), ("Fund Type", args.type.upper()), ("Domicile", args.domicile.capitalize()),
        ("Strategy", args.strategy.replace("_", " ")), ("Complexity", args.complexity.replace("_", " ")),
        ("AUM", f"${args.aum:,}M"), ("Share Classes", str(args.classes)), ("Sub-Funds", str(args.subfunds)),
        ("NAV Frequency", args.nav.capitalize()), ("Monthly Txns", f"{args.txns:,}"),
        ("Cost-to-Serve", f"{fmt(result['total_cost'])}/yr"), ("Recommended Fee", f"{rec['fee']} bps"),
        ("Revenue", f"{fmt(rec['revenue'])}/yr"), ("Margin", f"{rec['margin']:.1f}%"),
        ("Break-Even AUM", f"${rec['breakeven']:,.0f}M"), ("Win Probability", f"{args.win}%"),
        ("Prob-Weighted Rev", f"{fmt(result['prob_weighted'])}/yr"),
    ]
    summary_html = ""
    for label, val in summary_items:
        summary_html += f"<div style='display:flex;justify-content:space-between;padding:8px 14px;background:#0b1018;border-radius:6px;margin-bottom:5px'><span style='color:#7a8faa;font-size:11px'>{label}</span><span style='font-family:monospace;font-size:12px'>{val}</span></div>"

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Deal Sheet — {args.name}</title>
<style>
body {{ font-family:system-ui,sans-serif; background:#04080d; color:#eef2f9; padding:40px; max-width:1000px; margin:0 auto; }}
h1 {{ font-size:24px; margin-bottom:4px; }} .meta {{ color:#4e6380; font-size:12px; margin-bottom:28px; }}
h2 {{ font-size:16px; margin:28px 0 12px; padding-bottom:8px; border-bottom:1px solid #1e3048; }}
table {{ width:100%; border-collapse:collapse; }} th,td {{ padding:8px 12px; border-bottom:1px solid #1e3048; font-size:12px; text-align:left; }}
th {{ color:#4e6380; font-size:10px; text-transform:uppercase; }}
.scenarios {{ display:flex; gap:14px; }} .kpis {{ display:flex; gap:14px; margin-bottom:24px; }}
.kpi {{ flex:1; background:#111a28; border:1px solid #1e3048; border-radius:9px; padding:16px; }}
.kpi-l {{ font-size:10px; color:#4e6380; text-transform:uppercase; }} .kpi-v {{ font-family:monospace; font-size:20px; margin:6px 0; }}
@media print {{ body {{ background:white; color:black; }} .kpi,.scenarios>div {{ border-color:#ddd; background:#f9f9f9; }} }}
</style></head><body>
<h1>Deal Pricing Sheet — {args.name}</h1>
<div class="meta">Generated {now} · FA Deal Pricing Engine v1.0</div>

<div class="kpis">
  <div class="kpi"><div class="kpi-l">Recommended Fee</div><div class="kpi-v" style="color:#2d8cf0">{rec['fee']} bps</div></div>
  <div class="kpi"><div class="kpi-l">Annual Revenue</div><div class="kpi-v" style="color:#0fc882">{fmt(rec['revenue'])}</div></div>
  <div class="kpi"><div class="kpi-l">Margin</div><div class="kpi-v">{rec['margin']:.1f}%</div></div>
  <div class="kpi"><div class="kpi-l">Prob-Weighted Rev</div><div class="kpi-v" style="color:#1ac7c7">{fmt(result['prob_weighted'])}</div></div>
</div>

<h2>Pricing Scenarios</h2>
<div class="scenarios">{scenarios_html}</div>

<h2>Cost-to-Serve</h2>
<table>{cost_rows}</table>

<h2>Margin Sensitivity</h2>
<table><thead><tr>{sens_header}</tr></thead><tbody>{sens_rows}</tbody></table>

<h2>Deal Summary</h2>
{summary_html}

<div style="margin-top:32px;text-align:center;font-size:10px;color:#4e6380">FA Deal Pricing Engine v1.0 · {now}</div>
</body></html>"""

    Path(filename).write_text(html, encoding="utf-8")
    print(f"\n  ✓ Deal sheet exported to {filename}")
    print(f"    Open in browser: file://{Path(filename).resolve()}")


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="FA Deal Pricing Engine CLI")
    parser.add_argument("--name", default="Prospective Fund Co.")
    parser.add_argument("--type", default="ucits", choices=["ucits", "aif", "etf"])
    parser.add_argument("--domicile", default="ireland", choices=["ireland", "luxembourg", "cayman"])
    parser.add_argument("--strategy", default="equity", choices=["equity", "fixed_income", "multi_asset", "alternatives", "real_assets", "money_market"])
    parser.add_argument("--complexity", default="standard", choices=["standard", "moderate", "complex", "highly_complex"])
    parser.add_argument("--aum", type=int, default=2000)
    parser.add_argument("--classes", type=int, default=5)
    parser.add_argument("--subfunds", type=int, default=1)
    parser.add_argument("--nav", default="daily", choices=["daily", "weekly", "monthly"])
    parser.add_argument("--txns", type=int, default=500)
    parser.add_argument("--margin", type=int, default=25)
    parser.add_argument("--competitive", default="competitive", choices=["sole_bid", "competitive", "highly_competitive", "incumbent_defense"])
    parser.add_argument("--win", type=int, default=40)
    parser.add_argument("--export", default=None, help="Export HTML deal sheet to file")
    parser.add_argument("--quick", action="store_true", help="Run with defaults")
    args = parser.parse_args()

    result = compute(args)
    print_results(args, result)

    if args.export:
        export_html(args, result, args.export)
    elif not args.quick:
        print(f"\n  Tip: Add --export deal_sheet.html to generate an HTML deal sheet")
        print(f"  Tip: Add --aum 5000 --type aif --complexity complex to customise")


if __name__ == "__main__":
    main()
