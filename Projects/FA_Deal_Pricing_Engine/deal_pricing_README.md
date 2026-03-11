# FA Deal Pricing Engine

Automated fund administration deal pricing with hyper-flexible scenario testing, cost-to-serve modelling, lifecycle schematics, and deal summaries ready for senior review.

## The Problem This Solves

> "The repricing and pricing work is manual, slow, and ends up with people working all hours. The details need to be transparent and flexible when being reviewed. This shouldn't be a regular fire drill."

Traditional FA deal pricing is a painful cycle: sales brings a deal, someone builds a spreadsheet, it goes up the chain, a senior leader questions an assumption, it bounces back for rework, goes up again, another view, more rework. People work late, clients wait, and the process feels adversarial rather than collaborative.

This tool **replaces that entire cycle** with an interactive engine where:

- Cost-to-serve is computed automatically from deal parameters
- Three pricing scenarios are generated instantly (Aggressive / Recommended / Premium)
- A full **margin sensitivity matrix** (Fee × AUM) lets reviewers see the impact of any change in seconds
- The **operational lifecycle schematic** shows how the fund will actually run day-to-day
- A **deal summary** is generated ready for sign-off — no spreadsheet required

When a senior leader says *"what if we drop the fee by 20 basis points?"* — the answer is on screen in under a second, not in someone's inbox three days later.

---

## Quick Start

### Option 1: Streamlit App (Interactive)

```bash
pip install -r requirements.txt
streamlit run deal_pricing_app.py
```

Open `http://localhost:8501`. Configure deal parameters in the sidebar, click Calculate.

### Option 2: Python CLI (Zero Dependencies)

```bash
# Quick calculation with defaults
python deal_pricing_cli.py --quick

# Custom deal
python deal_pricing_cli.py --name "ABC Capital" --type aif --aum 5000 --strategy alternatives --complexity complex --margin 30

# Export HTML deal sheet
python deal_pricing_cli.py --name "ABC Capital" --aum 5000 --export deal_sheet.html

# Full help
python deal_pricing_cli.py --help
```

---

## Project Structure

```
deal_pricing_engine/
├── deal_pricing_app.py     # Streamlit interactive application
├── deal_pricing_cli.py     # Standalone CLI (zero dependencies)
├── requirements.txt        # Python dependencies (Streamlit only)
└── README.md               # This file
```

---

## Deal Input Parameters

| Parameter | Options | Description |
|-----------|---------|-------------|
| Fund Type | UCITS, AIF, ETF | Determines base cost structure |
| Domicile | Ireland, Luxembourg, Cayman | Jurisdiction cost multiplier |
| Strategy | Equity, Fixed Income, Multi-Asset, Alternatives, Real Assets, Money Market | Complexity driver |
| Complexity | Standard, Moderate, Complex, Highly Complex | Cost multiplier (1.0x → 2.5x) |
| AUM ($M) | 100 – 20,000 | Scale of the mandate |
| Share Classes | 1 – 50 | Each adds incremental cost |
| Sub-Funds | 1 – 20 | Each adds significant cost |
| NAV Frequency | Daily, Weekly, Monthly | Operational intensity |
| Monthly Txns | 0 – 50,000 | Transaction volume |
| Target Margin | 5% – 50% | Desired profit margin |
| Competitive Context | Sole Bid, Competitive, Highly Competitive, Incumbent Defense | Adjusts pricing |
| Win Probability | 1% – 100% | For probability-weighted revenue |

### Optional Services

Each toggleable service adds to cost-to-serve and appears in the lifecycle schematic:

- Transfer Agency ($35K base)
- Custody ($25K base)
- FX Execution ($12K base)
- CBI Regulatory Reporting ($28K base)
- Performance & Attribution ($22K base)
- Investor Reporting ($18K base)
- Tax Services ($32K base)

Service costs are adjusted by the complexity multiplier.

---

## Output Sections

### 1. Pricing Scenarios
Three scenarios adjusted for competitive context:
- **Aggressive** (82% of target) — win the deal, accept lower margin
- **Recommended** (100% of target) — balanced price
- **Premium** (118% of target) — if differentiation supports it

### 2. Cost-to-Serve Breakdown
Visual breakdown of core FA costs vs service costs. Fully transparent — every component visible.

### 3. Margin Sensitivity Matrix
Fee (bps) × AUM ($M) grid showing margin at every intersection. Colour-coded: green ≥20%, amber 10-20%, red <10%. This is the key tool for senior review — no rework needed, just look at the grid.

### 4. Operational Lifecycle Schematic
Visual flow of how the fund will operate day-to-day: trade capture → pricing → NAV → services → sign-off. Includes timezone information. This grounds the pricing in operational reality.

### 5. Deal Summary
All parameters and outputs in a structured format, exportable as CSV or printable HTML.

---

## Cost Model

The cost model uses multiplicative factors:

```
Total Cost = (Base Cost × Complexity × Domicile × NAV Freq × Strategy)
           + (Share Classes - 1) × $4,500
           + (Sub-Funds - 1) × $40,000
           + Monthly Txns × 12 × $1.20
           + Sum(Service Costs × Complexity)
```

Base costs: UCITS $85K, AIF $110K, ETF $95K

**Important:** These are placeholder cost assumptions. Replace with your actual cost data for production use. The model structure is designed to be calibrated against real P&L data from the P&L Intelligence Platform.

---

## Roadmap

### Phase 1 (Current)
- ✅ Automated cost-to-serve calculation
- ✅ Three pricing scenarios with competitive adjustment
- ✅ Margin sensitivity matrix
- ✅ Operational lifecycle schematic
- ✅ Deal summary with export
- ✅ Streamlit + CLI versions

### Phase 2 (Next — After Testing)
- [ ] Integration with P&L Intelligence Platform (pipeline revenue feed)
- [ ] Historical deal benchmarking (how did similar deals perform?)
- [ ] Cost model calibration from actual operational data
- [ ] Approval workflow tracking
- [ ] Multi-fund umbrella pricing

### Phase 3 (Future)
- [ ] AI-powered pricing recommendations using competitive intelligence
- [ ] Automated deal sheet generation (PDF)
- [ ] Sales pipeline probability model with FA revenue estimation
- [ ] Real-time cost model updates from operational metrics

---

## License

Internal use — JP Morgan Fund Administration Product Team.
