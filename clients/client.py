"""
Client logic for Linear-PBFT banking application
Each client runs in closed-loop mode with independent timers and retry logic
"""

import json
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Any, Set

from src.constants import (
    MSG_REQUEST,
    MSG_REPLY,
    TXN_BALANCE,
    TXN_TRANSFER,
    TIMER_CLIENT_RETRY,
    QUORUM_REPLY,
    CLIENT_MAX_RETRIES,
)
from src.message import Message, create_request
from src.crypto import CryptoManager, PublicKeyRegistry


@dataclass
class PendingRequest:
    txn: Dict[str, Any]
    timestamp: int
    retries: int = 0
    sent_to_all: bool = False
    last_send_time: float = field(default_factory=time.time)
    reply_votes: Dict[str, Set[str]] = field(default_factory=dict)
    signer_responses: Dict[str, str] = field(default_factory=dict)


class Client:
    """
    Represents a single logical client in the Linear-PBFT system
    """

    def __init__(
        self,
        client_id: str,
        crypto: CryptoManager,
        public_keys: PublicKeyRegistry,
        send_to_primary: Callable[[Message], None],
        broadcast_to_all: Callable[[Message], None],
        logger=None,
    ):
        self.client_id = client_id
        self.crypto = crypto
        self.public_keys = public_keys
        self.send_to_primary = send_to_primary
        self.broadcast_to_all = broadcast_to_all
        self.logger = logger

        self.current_view = 0
        self.pending: Optional[PendingRequest] = None
        self.timer_interval = TIMER_CLIENT_RETRY / 1000.0
        self.last_reply_view = 0
        self.last_request_failed = False
        self.last_result: Optional[Any] = None
        self.last_failure_reason: Optional[str] = None

    def submit_transfer(self, sender: str, receiver: str, amount: int, timestamp: int) -> Optional[Message]:
        if self.pending:
            if self.logger:
                self.logger.warning(f"Client {self.client_id}: Request already pending; cannot submit new transfer")
            return None

        txn = {
            "txn_type": TXN_TRANSFER,
            "client_id": self.client_id,
            "sender": sender,
            "receiver": receiver,
            "amount": amount,
            "timestamp": timestamp,
        }
        return self._send_request(txn)

    def submit_balance(self, sender: str, timestamp: int) -> Optional[Message]:
        if self.pending:
            if self.logger:
                self.logger.warning(f"Client {self.client_id}: Request already pending; cannot submit new balance check")
            return None

        txn = {
            "txn_type": TXN_BALANCE,
            "client_id": self.client_id,
            "sender": sender,
            "timestamp": timestamp,
        }
        return self._send_request(txn)

    def _send_request(self, txn: Dict[str, Any]) -> Message:
        message = create_request(
            client_id=self.client_id,
            txn_type=txn["txn_type"],
            sender=txn.get("sender", ""),
            receiver=txn.get("receiver", ""),
            amount=txn.get("amount", 0),
            timestamp=txn["timestamp"],
        )
        message.sign(self.crypto)

        pending = PendingRequest(txn=txn, timestamp=txn["timestamp"])
        self.pending = pending
        self.last_request_failed = False
        self.last_result = None
        self.last_failure_reason = None

        self.send_to_primary(message)
        pending.last_send_time = time.time()
        return message

    def handle_reply(self, reply: Message) -> bool:
        if reply.msg_type != MSG_REPLY:
            return False

        if not self.public_keys.verify_message(reply.get_data_to_sign(), reply.signature, reply.signer_id):
            if self.logger:
                self.logger.error(f"Client {self.client_id}: Invalid reply signature from {reply.signer_id}")
            return False

        payload = reply.payload
        if payload.get("client_id") != self.client_id:
            return False

        if not self.pending or payload.get("timestamp") != self.pending.timestamp:
            return False

        pending = self.pending
        view = payload.get("view", 0)
        self.last_reply_view = max(self.last_reply_view, view)
        if view > self.current_view:
            self.update_view(view)

        signer_id = reply.signer_id
        result_payload = payload.get("result")
        result_key = json.dumps(result_payload, sort_keys=True)

        previous_key = pending.signer_responses.get(signer_id)
        if previous_key == result_key:
            pass
        else:
            if previous_key and previous_key in pending.reply_votes:
                pending.reply_votes[previous_key].discard(signer_id)
            pending.signer_responses[signer_id] = result_key
            votes = pending.reply_votes.setdefault(result_key, set())
            votes.add(signer_id)

        votes = pending.reply_votes.get(result_key, set())
        if len(votes) >= QUORUM_REPLY:
            success_flag = True
            failure_reason: Optional[str] = None
            if isinstance(result_payload, dict):
                if result_payload.get("success") is False:
                    success_flag = False
                    failure_reason = result_payload.get("message") or "Operation failed"
            elif result_payload is False:
                success_flag = False
                failure_reason = "Operation failed"

            self.last_result = result_payload
            self.last_failure_reason = failure_reason
            self.pending = None
            self.last_request_failed = not success_flag
            return success_flag

        return False

    def check_timeout(self, current_time: Optional[float] = None) -> bool:
        if not self.pending:
            return False

        now = current_time or time.time()
        elapsed = now - self.pending.last_send_time
        if elapsed < self.timer_interval:
            return False

        self.pending.retries += 1
        self.pending.last_send_time = now

        if self.pending.retries >= CLIENT_MAX_RETRIES:
            self.last_request_failed = True
            self.last_failure_reason = "Maximum retries exceeded"
            self.pending = None
            return True

        if self.pending.sent_to_all:
            if self.logger:
                self.logger.warning(
                    f"Client {self.client_id}: Request timestamp={self.pending.timestamp} still pending after broadcast"
                )
            self._broadcast_pending()
        else:
            self.pending.sent_to_all = True
            if self.logger:
                self.logger.warning(
                    f"Client {self.client_id}: Timeout waiting for reply; broadcasting request timestamp={self.pending.timestamp}"
                )
            self._broadcast_pending()
        return True

    def _broadcast_pending(self):
        if not self.pending:
            return

        txn = self.pending.txn
        message = create_request(
            client_id=self.client_id,
            txn_type=txn["txn_type"],
            sender=txn.get("sender", ""),
            receiver=txn.get("receiver", ""),
            amount=txn.get("amount", 0),
            timestamp=txn["timestamp"],
        )
        message.sign(self.crypto)
        self.broadcast_to_all(message)

    def update_view(self, new_view: int):
        if new_view > self.current_view:
            self.current_view = new_view

    def reset(self):
        if self.logger:
            self.logger.info(f"Client {self.client_id}: Resetting state")
        self.pending = None
        self.current_view = 0
        self.last_reply_view = 0
        self.last_request_failed = False
        self.last_result = None
        self.last_failure_reason = None
