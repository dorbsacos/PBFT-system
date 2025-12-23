"""
Node orchestration for Linear-PBFT replicas. Handles message routing, protocol integration, and view-change management
"""

from typing import Callable, Dict, Optional, Set, Any

from src.message import Message
from src.constants import (
    MSG_REQUEST,
    MSG_PREPREPARE,
    MSG_PREPARE,
    MSG_COMMIT,
    MSG_REPLY,
    MSG_VIEWCHANGE,
    MSG_NEWVIEW,
    MSG_FLUSH,
    MSG_CHECKPOINT,
)
from nodes.replica import ReplicaState
from nodes.protocol_linear_pbft import LinearPBFTProtocol
from nodes.view_change import ViewChangeManager
from src.crypto import CryptoManager, PublicKeyRegistry


class Node:
    """
    Represents a single Linear-PBFT replica. This class ties together
    the replica state machine, Linear-PBFT protocol logic, and view-change manager.
    """

    def __init__(
        self,
        node_id: str,
        config: Dict[str, Any],
        crypto: CryptoManager,
        public_keys: PublicKeyRegistry,
        send_to_node: Callable[[str, Message], None],
        broadcast_to_nodes: Callable[[Message, Optional[Set[str]]], None],
        send_to_client: Callable[[str, Message], None],
        logger=None,
    ):
        self.node_id = node_id
        self.config = config
        self.crypto = crypto
        self.public_keys = public_keys
        self.logger = logger

        self.send_to_node_cb = send_to_node
        self.broadcast_to_nodes_cb = broadcast_to_nodes
        self.send_to_client_cb = send_to_client

        self.node_ids: Dict[str, Dict[str, Any]] = {
            entry["id"]: entry for entry in config.get("nodes", [])
        }
        self.node_order = [entry["id"] for entry in config.get("nodes", [])]
        self.peer_ids: Set[str] = {node for node in self.node_order if node != self.node_id}
        self.client_ids: Set[str] = {entry["id"] for entry in config.get("clients", [])}

        self.replica_state = ReplicaState(initial_balance=config.get("initial_balance", 10))

        self.protocol: Optional[LinearPBFTProtocol] = None
        self.view_change_manager: Optional[ViewChangeManager] = None

        self._initialize_protocol_components()

    def _initialize_protocol_components(self):
        def is_primary_for_view(view: int) -> bool:
            return self._get_primary_id(view) == self.node_id

        def get_primary_id(view: int) -> str:
            return self._get_primary_id(view)

        self.protocol = LinearPBFTProtocol(
            node_id=self.node_id,
            replica_state=self.replica_state,
            crypto=self.crypto,
            public_keys=self.public_keys,
            send_to_primary=self._send_to_primary,
            broadcast_to_replicas=self._broadcast_to_replicas,
            send_to_client=self._send_reply_to_client,
            is_primary_fn=is_primary_for_view,
            get_primary_id_fn=get_primary_id,
            valid_clients=self.client_ids,
            report_progress=self._report_progress,
            report_idle=self._report_idle,
            logger=self.logger,
        )

        self.view_change_manager = ViewChangeManager(
            node_id=self.node_id,
            replica_state=self.replica_state,
            protocol=self.protocol,
            crypto=self.crypto,
            public_keys=self.public_keys,
            broadcast_to_replicas=self._broadcast_to_replicas,
            send_to_primary=self._send_to_primary,
            on_view_change_start=self._on_view_change_start,
            on_view_change_complete=self._on_view_change_complete,
            get_primary_id_fn=get_primary_id,
            logger=self.logger,
        )

        # Synchronize initial view state
        self.protocol.update_view(0)
        self.view_change_manager.update_view(0)

    def _send_to_primary(self, message: Message):
        try:
            primary_id = self._get_primary_id(self.view_change_manager.current_view)
        except ValueError as exc:
            if self.logger:
                self.logger.error(f"{self.node_id}: Unable to determine primary: {exc}")
            return
        if primary_id == self.node_id:
            # Handle locally
            self.handle_incoming_message(message, self.node_id)
        else:
            self.send_to_node_cb(primary_id, message)

    def _broadcast_to_replicas(self, message: Message, exclude: Optional[Set[str]] = None):
        exclude = set(exclude or set())
        exclude.add(self.node_id)
        self.broadcast_to_nodes_cb(message, exclude)

    def _send_reply_to_client(self, message: Message, client_id: str):
        if not client_id:
            return
        self.send_to_client_cb(client_id, message)

    def _get_primary_id(self, view: int) -> str:
        if not self.node_order:
            raise ValueError("Node order not configured")
        index = view % len(self.node_order)
        return self.node_order[index]

    def handle_incoming_message(self, msg: Message, sender_id: str, is_client: bool = False):
        """Entry point for all inbound protocol messages"""
        if msg.msg_type == MSG_REQUEST:
            self._handle_client_request(msg, sender_id, is_client)
            return

        if msg.msg_type == MSG_PREPREPARE:
            success = self.protocol.handle_preprepare(msg)
            if success:
                self._report_progress()
            return

        if msg.msg_type == MSG_PREPARE:
            success = self.protocol.handle_prepare(msg)
            if success:
                self._report_progress()
            return

        if msg.msg_type == MSG_COMMIT:
            success = self.protocol.handle_commit(msg)
            if success:
                self._report_progress()
            return

        if msg.msg_type == MSG_CHECKPOINT:
            success = self.protocol.handle_checkpoint(msg)
            if success:
                self._report_progress()
            return

        if msg.msg_type == MSG_REPLY:
            if self.logger:
                self.logger.warning(f"{self.node_id}: Unexpected REPLY received from {sender_id}")
            return

        if msg.msg_type == MSG_VIEWCHANGE:
            self.view_change_manager.handle_view_change(msg)
            return

        if msg.msg_type == MSG_NEWVIEW:
            self.view_change_manager.handle_new_view(msg)
            return

        if msg.msg_type == MSG_FLUSH:
            self.handle_flush()
            return

        if self.logger:
            self.logger.warning(f"{self.node_id}: Unknown message type {msg.msg_type} from {sender_id}")

    def _handle_client_request(self, msg: Message, sender_id: str, is_client: bool):
        if not is_client:
            if self.logger:
                self.logger.warning(f"{self.node_id}: Ignoring REQUEST from non-client {sender_id}")
            return

        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, sender_id):
            if self.logger:
                self.logger.error(f"{self.node_id}: Invalid client signature from {sender_id}")
            return

        if msg.payload.get("client_id") != sender_id:
            if self.logger:
                self.logger.error(
                    f"{self.node_id}: Client ID mismatch in request (claimed={msg.payload.get('client_id')} actual={sender_id})"
                )
            return

        if self.protocol.is_primary():
            self.protocol.handle_client_request(msg)
        else:
            primary_id = self._get_primary_id(self.view_change_manager.current_view)
            if self.protocol:
                self.protocol.cache_client_request(msg.payload)
            if self.view_change_manager and not self.view_change_manager.started:
                self.view_change_manager.record_progress()
            self.send_to_node_cb(primary_id, msg)

    def _on_view_change_start(self, target_view: int):
        if self.logger:
            self.logger.warning(f"{self.node_id}: View change starting for view {target_view}")

    def _on_view_change_complete(self, new_view: int):
        if self.logger:
            self.logger.info(f"{self.node_id}: View change complete for view {new_view}")

    def _report_progress(self):
        if self.view_change_manager:
            self.view_change_manager.record_progress()

    def _report_idle(self):
        if self.view_change_manager:
            self.view_change_manager.record_idle()

    def check_timeouts(self):
        if self.view_change_manager:
            return self.view_change_manager.check_timeout()
        return None

    def handle_flush(self):
        if self.logger:
            self.logger.info(f"{self.node_id}: Handling FLUSH (system reset)")

        self.replica_state.clear_state()
        if self.protocol:
            self.protocol.reset_collections(clear_client_state=True)
            self.protocol.update_view(0)
        if self.view_change_manager:
            self.view_change_manager.reset()
            self.view_change_manager.update_view(0)
            self.view_change_manager.started = False

    def get_status(self, sequence: int) -> str:
        return self.replica_state.get_request_status(sequence)

    def get_balances(self) -> Dict[str, int]:
        return self.replica_state.get_all_balances()

    def get_view_state(self) -> Dict[str, Any]:
        if not self.view_change_manager:
            return {}
        return self.view_change_manager.get_view_snapshot()

    def pause_timers(self):
        if self.view_change_manager:
            self.view_change_manager.record_idle()
