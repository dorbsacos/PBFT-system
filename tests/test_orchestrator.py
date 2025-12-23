"""
Test orchestrator for Linear-PBFT project
Parses CSV input describing transaction sets and drives execution.
"""

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional

from src.constants import TXN_TRANSFER, TXN_BALANCE


@dataclass
class Transaction:
    client_id: str
    txn_type: str
    sender: str
    receiver: Optional[str] = None
    amount: Optional[int] = None


@dataclass
class AttackConfig:
    sign: bool = False
    crash: bool = False
    time: bool = False
    time_delay_ms: Optional[int] = None
    dark_destinations: List[str] = field(default_factory=list)
    equivocation_destinations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sign": self.sign,
            "crash": self.crash,
            "time": self.time,
            "time_delay_ms": self.time_delay_ms,
            "dark_destinations": list(self.dark_destinations),
            "equivocation_destinations": list(self.equivocation_destinations),
        }


@dataclass
class TestCase:
    set_number: int
    transactions: List[Transaction]
    live_nodes: List[str]
    byzantine_nodes: List[str]
    attacks: AttackConfig


class TestOrchestrator:
    """
    Loads test cases from CSV and coordinates execution.
    Actual driving of nodes/clients is expected to be implemented by callers.
    """

    def __init__(self, logger=None):
        self.logger = logger
        self.test_cases: List[TestCase] = []

    def load_csv(self, csv_path: str) -> List[TestCase]:
        path = Path(csv_path)
        if not path.exists():
            raise FileNotFoundError(csv_path)

        self.test_cases.clear()
        current_case: Optional[TestCase] = None

        with path.open(newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                set_field = row.get("Set Number") or row.get("Set") or ""
                set_field = set_field.strip() if set_field else ""
                txn_entry = row.get("Transactions", "").strip()

                if set_field:
                    if current_case:
                        self.test_cases.append(current_case)

                    set_number = int(set_field)
                    live_nodes = self._parse_list_field(row.get("Live", ""))
                    byzantine_nodes = self._parse_list_field(row.get("Byzantine", ""))
                    attacks = self._parse_attacks(row.get("Attack", ""))
                    transactions: List[Transaction] = []

                    txn = self._parse_transaction_entry(txn_entry)
                    if txn:
                        transactions.append(txn)

                    current_case = TestCase(
                        set_number=set_number,
                        transactions=transactions,
                        live_nodes=live_nodes,
                        byzantine_nodes=byzantine_nodes,
                        attacks=attacks,
                    )
                else:
                    if not current_case:
                        continue
                    txn = self._parse_transaction_entry(txn_entry)
                    if txn:
                        current_case.transactions.append(txn)

        if current_case:
            self.test_cases.append(current_case)
        return self.test_cases

    def _parse_transaction_entry(self, entry: str) -> Optional[Transaction]:
        if not entry:
            return None

        entry = entry.strip()
        if not (entry.startswith("(") and entry.endswith(")")):
            return None

        parts = [p.strip() for p in entry[1:-1].split(",") if p.strip()]
        if len(parts) == 3:
            sender, receiver, amount = parts
            return Transaction(
                client_id=sender,
                txn_type=TXN_TRANSFER,
                sender=sender,
                receiver=receiver,
                amount=int(amount),
            )
        if len(parts) == 1:
            sender = parts[0]
            return Transaction(
                client_id=sender,
                txn_type=TXN_BALANCE,
                sender=sender,
            )
        return None

    def _parse_list_field(self, field: str) -> List[str]:
        if not field:
            return []
        field = field.strip()
        if field.startswith("[") and field.endswith("]"):
            field = field[1:-1]
        return [item.strip() for item in field.split(",") if item.strip()]

    def _parse_attacks(self, field: str) -> AttackConfig:
        config = AttackConfig()
        if not field:
            return config

        field = field.strip()
        if field.startswith("[") and field.endswith("]"):
            field = field[1:-1]

        tokens = [token.strip() for token in field.split(";") if token.strip()]
        for token in tokens:
            if token == "sign":
                config.sign = True
            elif token == "crash":
                config.crash = True
            elif token.startswith("time"):
                config.time = True
                if "(" in token and token.endswith(")"):
                    inside = token[token.find("(") + 1:-1]
                    try:
                        config.time_delay_ms = int(inside)
                    except ValueError:
                        config.time_delay_ms = None
            elif token.startswith("dark(") and token.endswith(")"):
                inside = token[5:-1]
                destinations = [p.strip() for p in inside.split(",") if p.strip()]
                config.dark_destinations.extend(destinations)
            elif token.startswith("equivocation(") and token.endswith(")"):
                inside = token[len("equivocation("):-1]
                destinations = [p.strip() for p in inside.split(",") if p.strip()]
                config.equivocation_destinations.extend(destinations)
        return config

    def run_all(self):
        if self.logger:
            self.logger.info("TestOrchestrator: run_all called, implement execution logic")
