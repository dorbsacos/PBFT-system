"""
Configuration loader for Linear-PBFT project
"""

import json
from pathlib import Path
from typing import Dict, Any

from src.constants import NODE_IDS, CLIENT_IDS


class ConfigError(Exception):
    pass


def load_config(path: str) -> Dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise ConfigError(f"Configuration file not found: {path}")

    with config_path.open("r", encoding="utf-8") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Invalid JSON in config: {exc}") from exc

    validate_config(config)
    return config


def validate_config(config: Dict[str, Any]) -> None:
    nodes = config.get("nodes")
    clients = config.get("clients")

    if not isinstance(nodes, list) or len(nodes) != len(NODE_IDS):
        raise ConfigError("Config must define nodes list matching expected size")
    if not isinstance(clients, list) or len(clients) != len(CLIENT_IDS):
        raise ConfigError("Config must define 10 clients")

    node_ids = set()
    for node in nodes:
        node_id = node.get("id")
        if node_id not in NODE_IDS:
            raise ConfigError(f"Unexpected node id {node_id}")
        if node_id in node_ids:
            raise ConfigError(f"Duplicate node id {node_id}")
        node_ids.add(node_id)
        if not node.get("host") or not node.get("port"):
            raise ConfigError(f"Node {node_id} missing host/port")

    client_ids = set()
    for client in clients:
        client_id = client.get("id")
        if client_id not in CLIENT_IDS:
            raise ConfigError(f"Unexpected client id {client_id}")
        if client_id in client_ids:
            raise ConfigError(f"Duplicate client id {client_id}")
        client_ids.add(client_id)
        if not client.get("port"):
            raise ConfigError(f"Client {client_id} missing port")

    if config.get("fault_tolerance") != 2:
        raise ConfigError("fault_tolerance must be 2 for 7-node deployment")

    if config.get("initial_balance") is None:
        raise ConfigError("initial_balance must be specified")
