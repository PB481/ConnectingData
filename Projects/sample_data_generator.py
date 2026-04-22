"""
Sample data generator for the Structured Credit Specialist Toolkit.
Produces synthetic syndicated loan data with no reference to specific firms.
"""
import pandas as pd
import random
from datetime import datetime, timedelta
from io import BytesIO

random.seed(42)

SECTORS = ["Healthcare", "Technology", "Industrials", "Consumer Goods", "Energy",
           "Telecoms", "Financials", "Real Estate", "Utilities", "Materials"]
RATINGS = ["BB+", "BB", "BB-", "B+", "B", "B-", "CCC+"]
COUNTRIES = ["DE", "FR", "NL", "IT", "ES", "IE", "LU", "BE", "AT", "SE"]
NACE = ["Q86", "J62", "C29", "G47", "D35", "J61", "K64", "L68", "D35", "C24"]
AGENT_BANKS = ["Agent A", "Agent B", "Agent C", "Agent D", "Agent E"]


def generate_loan_portfolio(num_loans=50):
    """Generate a synthetic syndicated loan portfolio."""
    rows = []
    for i in range(num_loans):
        par = round(random.uniform(500_000, 3_000_000) / 10_000) * 10_000
        price = round(random.uniform(92.0, 102.5), 3)
        spread = random.choice([275, 300, 325, 350, 375, 400, 425, 450, 475, 500])
        floor = random.choice([0.0, 0.0, 0.0, 0.5, 1.0])
        maturity_year = 2027 + random.randint(0, 5)
        days_since_price_change = random.choice([0, 0, 0, 1, 1, 2, 3, 3, 4, 6, 8, 12])
        sector_idx = i % 10
        rows.append({
            "Loan_ID": f"SL{100001 + i}",
            "Borrower": f"Company {chr(65 + (i // 26))}{chr(65 + (i % 26))}",
            "Sector": SECTORS[sector_idx],
            "NACE_Code": NACE[sector_idx],
            "Country": COUNTRIES[i % 10],
            "Par_Value_EUR": par,
            "Spread_bps": spread,
            "EURIBOR_Floor_Pct": floor,
            "Day_Count": "Actual/360",
            "Maturity": f"{maturity_year}-{(i % 12)+1:02d}-15",
            "Markit_Price": price,
            "Days_Since_Price_Change": days_since_price_change,
            "Rating": RATINGS[i % 7],
            "Cost_Basis_EUR": round(par * random.uniform(0.95, 1.02) / 10_000) * 10_000,
            "Agent_Bank": AGENT_BANKS[i % 5],
            "PIK_Eligible": random.choice([False, False, False, True]),
            "Status": random.choice(["Performing", "Performing", "Performing", "Performing", "Watchlist", "Performing", "Performing"]),
        })
    return pd.DataFrame(rows)


def generate_shadow_book(portfolio_df, bias_pct=0.5):
    """Generate a synthetic IM shadow book with small deviations from FA book."""
    rows = []
    for _, loan in portfolio_df.iterrows():
        par = loan["Par_Value_EUR"]
        spread = loan["Spread_bps"]
        euribor = 3.65  # assume current EURIBOR
        rate = max(euribor + spread/100, loan["EURIBOR_Floor_Pct"] + spread/100)
        fa_accrued = round(par * rate / 100 * 30 / 360)
        # Bias the shadow book slightly
        bias = random.uniform(-bias_pct/100, bias_pct/100)
        im_accrued = round(fa_accrued * (1 + bias))
        rows.append({
            "Loan_ID": loan["Loan_ID"],
            "Borrower": loan["Borrower"],
            "IM_Accrued_Interest_EUR": im_accrued,
            "IM_Cash_Received_EUR": round(im_accrued * 0.95) if random.random() > 0.15 else 0,
            "IM_Status": "Active" if loan["Status"] != "Watchlist" else "Monitored",
            "IM_Note": "" if abs(bias) < 0.003 else random.choice(["Rate reset timing diff", "PIK accrual", "Day count diff", "Period cutoff"]),
        })
    return pd.DataFrame(rows)


def generate_expense_schedule():
    """Generate a sample expense accrual schedule."""
    return pd.DataFrame([
        {"Expense_Category": "Admin Fee", "Annual_Amount_EUR": 100000, "VAT_Rate": "Exempt", "Annual_Cap_EUR": 100000},
        {"Expense_Category": "ManCo Fee", "Annual_Amount_EUR": 140000, "VAT_Rate": "Exempt", "Annual_Cap_EUR": 140000},
        {"Expense_Category": "IM Fee", "Annual_Amount_EUR": 500000, "VAT_Rate": "Exempt", "Annual_Cap_EUR": 500000},
        {"Expense_Category": "Trustee Fee", "Annual_Amount_EUR": 50000, "VAT_Rate": "Exempt", "Annual_Cap_EUR": 50000},
        {"Expense_Category": "Audit Fee", "Annual_Amount_EUR": 50000, "VAT_Rate": "23%", "Annual_Cap_EUR": 80000},
        {"Expense_Category": "Legal Fee", "Annual_Amount_EUR": 30000, "VAT_Rate": "23%", "Annual_Cap_EUR": 80000},
        {"Expense_Category": "Paying Agent", "Annual_Amount_EUR": 12000, "VAT_Rate": "Exempt", "Annual_Cap_EUR": 15000},
        {"Expense_Category": "Listing Fee", "Annual_Amount_EUR": 10000, "VAT_Rate": "Exempt", "Annual_Cap_EUR": 15000},
        {"Expense_Category": "Other", "Annual_Amount_EUR": 20000, "VAT_Rate": "Mixed", "Annual_Cap_EUR": 25000},
    ])


def generate_cash_inflows():
    """Generate sample quarterly cash inflows — separated by type."""
    return pd.DataFrame([
        # Interest sources
        {"Source": "Loan Interest Received", "Type": "Interest", "Q1_EUR": 825000, "Q2_EUR": 850000, "Q3_EUR": 870000, "Q4_EUR": 880000},
        {"Source": "Commitment Fees", "Type": "Interest", "Q1_EUR": 12000, "Q2_EUR": 8000, "Q3_EUR": 15000, "Q4_EUR": 10000},
        {"Source": "Amendment Fees", "Type": "Interest", "Q1_EUR": 5000, "Q2_EUR": 25000, "Q3_EUR": 0, "Q4_EUR": 18000},
        # Principal sources
        {"Source": "Scheduled Principal Repayments", "Type": "Principal", "Q1_EUR": 80000, "Q2_EUR": 100000, "Q3_EUR": 90000, "Q4_EUR": 110000},
        {"Source": "Prepayments", "Type": "Principal", "Q1_EUR": 40000, "Q2_EUR": 60000, "Q3_EUR": 45000, "Q4_EUR": 75000},
        {"Source": "Loan Sale Proceeds", "Type": "Principal", "Q1_EUR": 0, "Q2_EUR": 500000, "Q3_EUR": 0, "Q4_EUR": 0},
        {"Source": "Recovery Proceeds", "Type": "Principal", "Q1_EUR": 0, "Q2_EUR": 0, "Q3_EUR": 0, "Q4_EUR": 35000},
    ])


def generate_note_register():
    """Generate the PPN note register."""
    return pd.DataFrame([
        {"Event_Date": "2024-07-01", "Event_Type": "Inception", "Amount_EUR": 20_000_000,
         "PPN_Face_Value_After_EUR": 20_000_000, "Investor_ID": "INV-001", "Notes": "Initial in-specie subscription"},
        {"Event_Date": "2024-08-15", "Event_Type": "Drawdown", "Amount_EUR": 10_000_000,
         "PPN_Face_Value_After_EUR": 30_000_000, "Investor_ID": "INV-001", "Notes": "Additional cash drawdown"},
        {"Event_Date": "2024-10-01", "Event_Type": "Drawdown", "Amount_EUR": 5_000_000,
         "PPN_Face_Value_After_EUR": 35_000_000, "Investor_ID": "INV-001", "Notes": "Third tranche"},
    ])


def generate_credit_events_log():
    """Generate a log of sample credit events."""
    return pd.DataFrame([
        {"Event_Date": "2024-09-15", "Loan_ID": "SL100005", "Event_Type": "PIK Toggle",
         "Amount_EUR": 125000, "Description": "Borrower elected PIK for Q4 interest period"},
        {"Event_Date": "2024-10-20", "Loan_ID": "SL100012", "Event_Type": "Amend & Extend",
         "Amount_EUR": 0, "Description": "Maturity extended 2 years, spread +50bps"},
        {"Event_Date": "2024-11-05", "Loan_ID": "SL100023", "Event_Type": "Partial Paydown",
         "Amount_EUR": 500000, "Description": "Voluntary prepayment"},
        {"Event_Date": "2024-11-28", "Loan_ID": "SL100031", "Event_Type": "Covenant Waiver",
         "Amount_EUR": 0, "Description": "Financial covenant waived, 10bps consent fee paid"},
    ])


def to_excel_bytes(dfs_dict):
    """Convert a dict of {sheet_name: dataframe} to downloadable Excel bytes."""
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        for sheet_name, df in dfs_dict.items():
            df.to_excel(writer, sheet_name=sheet_name[:31], index=False)
    return output.getvalue()


def to_csv_bytes(df):
    return df.to_csv(index=False).encode("utf-8")
