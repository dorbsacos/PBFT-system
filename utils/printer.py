"""
Printing utilities for required project commands
"""

import json
from typing import Dict, Any

from src.constants import NODE_IDS


def print_db(node_balances: Dict[str, Dict[str, int]]) -> None:
    """
    Print balances for each node's datastore.

    Args:
        node_balances: Mapping of node_id -> {client_id: balance}
    """
    print("=== PrintDB ===")
    for node_id in sorted(node_balances.keys()):
        print(f"Node {node_id} balances:")
        balances = node_balances[node_id]
        for client_id in sorted(balances.keys()):
            print(f"  {client_id}: {balances[client_id]}")
    print("================")


def print_status(sequence: int, status_map: Dict[str, str]) -> None:
    """
    Print PP/P/C/E/X status for the requested nodes at the given sequence.

    Args:
        sequence: Sequence number to report
        status_map: Mapping of node_id -> status string
    """
    print("=== PrintStatus ===")
    for node_id in sorted(status_map.keys()):
        status = status_map.get(node_id, "X") or "X"
        print(f"Node {node_id} seq={sequence}: {status}")
    print("===================")


def print_view(view_info: Dict[str, Any]) -> None:
    """Print all VIEWCHANGE and NEWVIEW messages observed during the run."""
    print("=== PrintView ===")
    vc_map = view_info.get("viewchange_messages", {})
    aggregated_details = view_info.get("aggregated_newview_details", {})
    config_details = view_info.get("newview_configs", {})
    ordered_views = sorted(set(vc_map.keys()) | set(int(v) for v in aggregated_details.keys()))

    if not ordered_views:
        print("No view-change or new-view messages recorded")
        print("=================")
        return

    print("New-View Messages:")
    for view in ordered_views:
        print(f"  View {view}:")
        detail = aggregated_details.get(str(view)) or aggregated_details.get(view, {})
        configs = config_details.get(str(view)) or config_details.get(view, {})

        if detail:
            for signer_id, payload in sorted(detail.items()):
                print(f"    NEWVIEW from {signer_id}")
                payload_str = json.dumps(payload.get("payload", {}), indent=8)
                for line in payload_str.splitlines():
                    print("        " + line)
        elif configs:
            for nid, meta in sorted(configs.items()):
                config = meta.get("config", {})
                if config:
                    config_str = json.dumps(config, sort_keys=True)
                    print(f"    {nid}: attack config {config_str}")
                else:
                    print(f"    {nid}: no NEWVIEW (config only)")
        else:
            print("    NEWVIEW signer -> none")
    print("=================")


def print_log(log_entries: Dict[str, Dict[str, Any]]) -> None:
    """Print log metadata for each node and sequence."""
    print("=== PrintLog ===")
    for node_id in sorted(log_entries.keys()):
        node_data = log_entries.get(node_id) or {}
        entries = node_data.get("entries", {})
        meta = node_data.get("meta", {})
        print(f"Node {node_id}:")
        low = meta.get("low_water_mark")
        high = meta.get("high_water_mark")
        if low is not None and high is not None:
            print(f"  Watermarks: low={low}, high={high}")
        cp_sequence = meta.get("stable_checkpoint_sequence")
        if cp_sequence is not None:
            cp_digest = meta.get("stable_checkpoint_digest") or "None"
            cp_signers = meta.get("stable_checkpoint_signers") or []
            signer_list = ", ".join(sorted(cp_signers)) if cp_signers else "none"
            print(f"  Stable checkpoint: seq={cp_sequence} digest={cp_digest}")
            print(f"  Checkpoint signers ({len(cp_signers)}): {signer_list}")
        if not entries:
            print("  (log empty)")
            continue
        for sequence in sorted(entries.keys()):
            entry = entries[sequence]
            digest = entry.get("digest")
            view = entry.get("view")
            status = entry.get("status")
            print(f"  seq={sequence} view={view} status={status} digest={digest}")

            request = entry.get("request") or {}
            if request:
                txn_type = request.get("txn_type")
                client_id = request.get("client_id")
                sender = request.get("sender")
                receiver = request.get("receiver")
                amount = request.get("amount")
                timestamp = request.get("timestamp")
                if txn_type == "TRANSFER":
                    print(
                        f"    Request: client={client_id} transfer {sender}->{receiver} amount={amount} ts={timestamp}"
                    )
                elif txn_type == "BALANCE":
                    print(
                        f"    Request: client={client_id} balance sender={sender} ts={timestamp}"
                    )
                else:
                    print(f"    Request: {request}")

            preprepare_sender = entry.get("preprepare_sender")
            if preprepare_sender:
                print(f"    Pre-prepare from: {preprepare_sender}")

            flags = []
            flags.append(f"PP={'Y' if entry.get('pprepared') else 'N'}")
            flags.append(f"P={'Y' if entry.get('prepared') else 'N'}")
            flags.append(f"C={'Y' if entry.get('committed') else 'N'}")
            flags.append(f"E={'Y' if entry.get('executed') else 'N'}")
            print("    Status flags: " + ", ".join(flags))

            prepare_signers = entry.get("prepare_signers") or []
            if prepare_signers:
                print(
                    f"    Prepare signers ({len(prepare_signers)}): "
                    + ", ".join(prepare_signers)
                )
            commit_signers = entry.get("commit_signers") or []
            if commit_signers:
                print(
                    f"    Commit signers ({len(commit_signers)}): "
                    + ", ".join(commit_signers)
                )

            execution_result = entry.get("execution_result")
            if execution_result is not None:
                if isinstance(execution_result, dict):
                    result_str = json.dumps(execution_result, sort_keys=True)
                else:
                    result_str = str(execution_result)
                print(f"    Execution result: {result_str}")
            events = entry.get("events") or []
            if events:
                print("    Events:")
                for ev in events:
                    print(f"      - {ev}")
    print("================")
