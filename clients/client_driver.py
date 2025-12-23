"""
Client driver orchestrating all logical clients for Linear-PBFT
Handles request scheduling, reply routing, and timeout polling
"""

from typing import Dict, Callable, List, Optional, Any

from src.message import Message
from src.constants import TXN_TRANSFER, TXN_BALANCE, NODE_IDS
from src.crypto import CryptoManager, PublicKeyRegistry
from clients.client import Client


class ClientDriver:
    """
    Manages the fleet of logical clients (A..J). Each client runs closed-loop, but this
    driver coordinates request submission and timeout polling.
    """

    def __init__(
        self,
        client_ids: List[str],
        crypto_map: Dict[str, CryptoManager],
        public_keys: PublicKeyRegistry,
        send_to_primary: Callable[[str, Message], None],
        broadcast_to_all: Callable[[Message], None],
        logger=None,
    ):
        self.logger = logger
        self.public_keys = public_keys
        self.send_to_primary_fn = send_to_primary
        self.broadcast_to_all_fn = broadcast_to_all

        self._client_ids = list(client_ids)
        self._crypto_map = crypto_map
        self._public_keys = public_keys
        self._logger = logger

        self.clients: Dict[str, Client] = {}
        self._initialize_clients()

        self.current_view = 0

    def submit_transaction(self, txn: Dict[str, Any], timestamp: int) -> bool:
        """
        Submit a transaction dict. Expected format:
        {
            "client_id": "A",
            "type": "TRANSFER" | "BALANCE",
            "sender": "A",
            "receiver": "B",   # only for transfer
            "amount": 5          # only for transfer
        }
        """
        client_id = txn.get("client_id")
        if client_id not in self.clients:
            if self.logger:
                self.logger.error(f"ClientDriver: Unknown client {client_id}")
            return False

        client = self.clients[client_id]
        txn_type = txn.get("type")

        if txn_type == TXN_TRANSFER:
            sender = txn.get("sender")
            receiver = txn.get("receiver")
            amount = txn.get("amount", 0)
            result = client.submit_transfer(sender, receiver, amount, timestamp)
            return result is not None
        elif txn_type == TXN_BALANCE:
            sender = txn.get("sender")
            result = client.submit_balance(sender, timestamp)
            return result is not None
        else:
            if self.logger:
                self.logger.error(f"ClientDriver: Unsupported transaction type {txn_type}")
            return False

    def handle_reply(self, reply: Message) -> bool:
        client_id = reply.payload.get("client_id")
        if client_id not in self.clients:
            if self.logger:
                self.logger.warning(f"ClientDriver: Reply for unknown client {client_id}")
            return False
        return self.clients[client_id].handle_reply(reply)

    def check_timeouts(self):
        triggered = []
        for client_id, client in self.clients.items():
            if client.check_timeout():
                triggered.append(client_id)
        return triggered

    def update_view(self, new_view: int):
        if new_view > self.current_view:
            self.current_view = new_view
            primary_number = (self.current_view % len(NODE_IDS)) + 1
            print(f"Current Primary: Node {primary_number}")
            for client in self.clients.values():
                client.update_view(new_view)

    def reset(self):
        print("ClientDriver: Resetting all clients")
        self._initialize_clients()

    def _initialize_clients(self):
        self.clients = {}
        for cid in self._client_ids:
            crypto = self._crypto_map.get(cid)
            if not crypto:
                raise ValueError(f"Missing CryptoManager for client {cid}")
            client = Client(
                client_id=cid,
                crypto=crypto,
                public_keys=self._public_keys,
                send_to_primary=lambda msg, c=cid: self.send_to_primary_fn(c, msg),
                broadcast_to_all=self.broadcast_to_all_fn,
                logger=self._logger,
            )
            self.clients[cid] = client
