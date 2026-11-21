"""Transaction data: synthetic generator, loader, alert rule and answer key.

The columns follow the PaySim dataset (Kaggle), so the real file can replace
the synthetic one without code changes:

    step, type, amount, nameOrig, oldbalanceOrg, newbalanceOrig,
    nameDest, oldbalanceDest, newbalanceDest, isFraud, isFlaggedFraud

`step` is hours since the start of the simulation.
"""
from __future__ import annotations

import random
from pathlib import Path

import pandas as pd

LABEL_COLUMNS = ["isFraud", "isFlaggedFraud"]

# The simple rule a bank's alerting system would use before an analyst looks.
ALERT_AMOUNT = 200_000


def generate_synthetic(n_customers: int = 400, hours: int = 72, seed: int = 7) -> pd.DataFrame:
    """Make a small PaySim-shaped dataset with planted fraud and false alarms.

    Planted patterns:
    - Fraud (account takeover): a victim's whole balance is TRANSFERred to a
      fresh "mule" account that receives from several victims, then the mule
      CASH_OUTs it. Both rows are labelled fraud, as in PaySim.
    - False alarms: customers who move most of their balance to an account
      they have paid many times before (savings, rent, family).
    """
    rng = random.Random(seed)
    rows: list[dict] = []
    balances = {f"C{100000 + i}": rng.uniform(5_000, 900_000) for i in range(n_customers)}
    customers = list(balances)
    merchants = [f"M{200000 + i}" for i in range(60)]
    dest_balance: dict[str, float] = {}

    def add(step, kind, amount, orig, dest, fraud=0):
        old_o = balances.get(orig, 0.0)
        new_o = max(old_o - amount, 0.0) if kind in ("PAYMENT", "TRANSFER", "CASH_OUT", "DEBIT") else old_o + amount
        balances[orig] = new_o
        old_d = dest_balance.get(dest, rng.uniform(0, 50_000) if dest.startswith("C") else 0.0)
        new_d = old_d + amount if dest.startswith("C") and kind == "TRANSFER" else old_d
        dest_balance[dest] = new_d
        rows.append({
            "step": step, "type": kind, "amount": round(amount, 2),
            "nameOrig": orig, "oldbalanceOrg": round(old_o, 2), "newbalanceOrig": round(new_o, 2),
            "nameDest": dest, "oldbalanceDest": round(old_d, 2), "newbalanceDest": round(new_d, 2),
            "isFraud": fraud, "isFlaggedFraud": 0,
        })

    # Habitual recipients make the false alarms: same sender -> same recipient, often.
    habits = {c: rng.choice(customers) for c in rng.sample(customers, 40)}

    mules = [f"C{900000 + i}" for i in range(6)]
    fraud_plan = {rng.randrange(6, hours): [] for _ in range(14)}
    victims = rng.sample(customers, 14)
    for (step, _), victim in zip(fraud_plan.items(), victims):
        fraud_plan[step].append(victim)

    for step in range(1, hours + 1):
        # Everyday activity. Normal customers never move more than a third of their balance.
        for _ in range(rng.randint(25, 45)):
            c = rng.choice(customers)
            cap = max(balances[c] / 3, 10.0)
            r = rng.random()
            if r < 0.6:
                add(step, "PAYMENT", min(rng.uniform(5, 2_500), cap), c, rng.choice(merchants))
            elif r < 0.85:
                add(step, "TRANSFER", min(rng.uniform(100, 30_000), cap), c, rng.choice(customers))
            else:
                add(step, "CASH_OUT", min(rng.uniform(50, 8_000), cap), c, rng.choice(merchants))

        # Habitual payers send regular amounts to the same account (rent, savings, family).
        for c, dest in habits.items():
            if rng.random() < 0.15:
                add(step, "TRANSFER", min(rng.uniform(1_000, 25_000), max(balances[c] / 3, 10.0)), c, dest)

        # False alarm: a habitual payer moves most of the balance to the usual account.
        # Starts after a day so the customer has a visible payment history.
        if step >= 24 and step % 2 == 0:
            rich = [c for c in habits if balances[c] > ALERT_AMOUNT * 1.2]
            if rich:
                c = rng.choice(rich)
                add(step, "TRANSFER", balances[c] * rng.uniform(0.6, 0.95), c, habits[c])

        for victim in fraud_plan.get(step, []):
            mule = rng.choice(mules)
            amount = balances[victim]
            if amount < 1_000:
                continue
            add(step, "TRANSFER", amount, victim, mule, fraud=1)
            balances[mule] = dest_balance[mule]
            add(step, "CASH_OUT", amount, mule, rng.choice(merchants), fraud=1)

    return pd.DataFrame(rows)


def load_transactions(path: str | Path) -> pd.DataFrame:
    """Load a PaySim-format CSV and give every row a stable transaction id.

    For the real PaySim file (6.3M rows) this keeps only TRANSFER and
    CASH_OUT, the only types that contain fraud, plus a sample of the rest.
    """
    df = pd.read_csv(path)
    if len(df) > 200_000:
        risky = df[df["type"].isin(["TRANSFER", "CASH_OUT"])]
        fraud = risky[risky["isFraud"] == 1]
        legit = risky[risky["isFraud"] == 0].sample(min(100_000, len(risky)), random_state=42)
        df = pd.concat([fraud, legit]).sort_values("step", kind="stable")
    df = df.reset_index(drop=True)
    df.insert(0, "txn_id", [f"T{i:07d}" for i in range(len(df))])
    return df


def build_alerts(df: pd.DataFrame) -> pd.DataFrame:
    """Flag transactions with the kind of simple rule banks use before review.

    Large transfers or cash-outs, or any transfer that empties the account.
    Most flags are false alarms; the agent's job is to tell them apart.
    """
    risky = df["type"].isin(["TRANSFER", "CASH_OUT"])
    large = df["amount"] >= ALERT_AMOUNT
    drained = (df["oldbalanceOrg"] > 0) & (df["newbalanceOrig"] <= 0.01)
    return df[risky & (large | drained)]


def split_answer_key(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Return (data the agent may see, answer key used only for scoring)."""
    answer_key = df[["txn_id", "isFraud"]].copy()
    visible = df.drop(columns=[c for c in LABEL_COLUMNS if c in df.columns])
    return visible, answer_key
