"""
Linear-PBFT normal-case protocol logic
Implements pre-prepare, prepare, commit phases using collector pattern (O(n))
"""

import copy
from collections import defaultdict
from typing import Callable, Dict, Optional, Any, Set, Tuple

from src.constants import (
    QUORUM_PREPARE,
    QUORUM_COMMIT,
    MSG_PREPREPARE,
    MSG_PREPARE,
    MSG_COMMIT,
    MSG_REPLY,
    MSG_CHECKPOINT,
)
from src.message import (
    Message,
    create_preprepare,
    create_prepare,
    create_commit,
    create_reply,
    create_checkpoint,
    compute_request_digest,
)
from nodes.replica import ReplicaState, RequestLogEntry
from src.crypto import CryptoManager, PublicKeyRegistry


class LinearPBFTProtocol:
    """
    Implements the Linear-PBFT normal-case protocol for a single replica

    The protocol uses the collector pattern:
    - Prepare phase: replicas -> primary -> all replicas
    - Commit phase: replicas -> primary -> all replicas
    """

    def __init__(
        self,
        node_id: str,
        replica_state: ReplicaState,
        crypto: CryptoManager,
        public_keys: PublicKeyRegistry,
        send_to_primary: Callable[[Message], None],
        broadcast_to_replicas: Callable[[Message], None],
        send_to_client: Callable[[Message, str], None],
        is_primary_fn: Callable[[int], bool],
        get_primary_id_fn: Callable[[int], str],
        valid_clients: Optional[Set[str]] = None,
        report_progress: Optional[Callable[[], None]] = None,
        report_idle: Optional[Callable[[], None]] = None,
        logger=None,
    ):
        self.node_id = node_id
        self.replica_state = replica_state
        self.crypto = crypto
        self.public_keys = public_keys
        self.send_to_primary = send_to_primary
        self.broadcast_to_replicas = broadcast_to_replicas
        self.send_to_client = send_to_client
        self.is_primary_fn = is_primary_fn
        self.get_primary_id_fn = get_primary_id_fn
        self.logger = logger
        self.valid_clients: Set[str] = valid_clients or set()
        self.report_progress = report_progress
        self.report_idle = report_idle

        self.current_view = 0
        self.next_sequence_number = 1

        self.client_request_info: Dict[int, Dict[str, Any]] = {}
        self.pending_requests: Dict[tuple, Dict[str, Any]] = {}
        self.completed_requests: Dict[tuple, Dict[str, Any]] = {}
        self.request_cache: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.forged_digests_by_request: Dict[Tuple[str, int], Set[str]] = defaultdict(set)

        self.prepare_collections: Dict[int, Dict[str, bytes]] = defaultdict(dict)
        self.commit_collections: Dict[int, Dict[str, bytes]] = defaultdict(dict)
        self.prepare_certificates_sent: Dict[int, bool] = defaultdict(bool)
        self.commit_certificates_sent: Dict[int, bool] = defaultdict(bool)
        self.commit_sent: Dict[int, bool] = defaultdict(bool)

    def _log_event(self, sequence: Optional[int], message: str):
        if sequence is None:
            return
        self.replica_state.record_event(sequence, f"{self.node_id}: {message}")

    def _drop_sequence(
        self,
        sequence: int,
        request_key: Optional[Tuple[str, int]] = None,
        *,
        preserve_request: bool = True,
    ) -> None:
        """
        Remove bookkeeping for a forged sequence so the canonical sequence can replace it.
        """
        self.prepare_collections.pop(sequence, None)
        self.commit_collections.pop(sequence, None)
        self.prepare_certificates_sent.pop(sequence, None)
        self.commit_certificates_sent.pop(sequence, None)
        self.commit_sent.pop(sequence, None)
        self.client_request_info.pop(sequence, None)

        if request_key:
            if preserve_request:
                pending = self.pending_requests.get(request_key)
                if pending and pending.get("sequence") == sequence:
                    pending["sequence"] = None
                completed = self.completed_requests.get(request_key)
                if completed and completed.get("sequence") == sequence:
                    self.completed_requests.pop(request_key, None)
                cache_entry = self.request_cache.get(request_key)
                if cache_entry and cache_entry.get("active_sequence") == sequence:
                    cache_entry["active_sequence"] = None
                cache_entry = self.request_cache.get(request_key)
                if cache_entry:
                    cache_entry.setdefault("dropped_sequences", set()).add(sequence)
            else:
                self.pending_requests.pop(request_key, None)
                completed = self.completed_requests.get(request_key)
                if completed and completed.get("sequence") == sequence:
                    self.completed_requests.pop(request_key, None)
                self.request_cache.pop(request_key, None)

        self.replica_state.remove_sequence(sequence)
        self.sync_sequence_cursor()

    def _ensure_client_tracking(
        self,
        sequence: int,
        request_payload: Dict[str, Any],
        entry: Optional[RequestLogEntry] = None,
    ) -> Optional[Tuple[Dict[str, Any], Tuple[str, int]]]:
        if entry is None:
            entry = self.replica_state.get_request_log_entry(sequence)
        if not entry:
            return None

        client_id = request_payload.get("client_id")
        timestamp = request_payload.get("timestamp")
        if client_id is None or timestamp is None:
            return None

        client_info = self.client_request_info.get(sequence)
        if not client_info:
            client_info = {
                "client_id": client_id,
                "timestamp": timestamp,
                "request": copy.deepcopy(request_payload),
            }
            self.client_request_info[sequence] = client_info
        else:
            client_info.setdefault("request", copy.deepcopy(request_payload))

        request_key = (client_id, timestamp)

        if entry.status_executed:
            self.pending_requests.pop(request_key, None)
            self.completed_requests[request_key] = {
                "sequence": sequence,
                "digest": entry.digest,
                "client_info": client_info,
                "result": entry.execution_result,
            }
        else:
            pending_entry = self.pending_requests.setdefault(
                request_key,
                {
                    "sequence": sequence,
                    "digest": entry.digest,
                    "client_info": client_info,
                },
            )
            pending_entry["sequence"] = sequence
            pending_entry["digest"] = entry.digest
            pending_entry["client_info"] = client_info

        return client_info, request_key

    def _allocate_sequence(self, cache_entry: Optional[Dict[str, Any]] = None) -> Optional[int]:
        candidate: Optional[int] = None

        if cache_entry:
            dropped = cache_entry.get("dropped_sequences") or set()
            while dropped:
                seq = min(dropped)
                dropped.remove(seq)
                if seq > self.replica_state.last_executed_sequence and self.replica_state.is_within_watermarks(seq):
                    candidate = seq
                    break
            cache_entry["dropped_sequences"] = dropped

        if candidate is None:
            candidate = self.next_sequence_number
            if candidate > self.replica_state.high_water_mark:
                if self.logger:
                    self.logger.warning(
                        "%s: Cannot assign new sequence; high-water mark reached (low=%s high=%s)",
                        self.node_id,
                        self.replica_state.low_water_mark,
                        self.replica_state.high_water_mark,
                    )
                return None
            self.next_sequence_number += 1
        else:
            self.next_sequence_number = max(self.next_sequence_number, candidate + 1)

        return candidate

    def _validate_and_cache_request(
        self,
        request_key: Tuple[str, int],
        request_payload: Dict[str, Any],
        digest: str,
        sequence: Optional[int],
        view: int,
    ) -> Optional[Dict[str, Any]]:
        """
        Ensure the request cache retains the canonical digest and payload for a
        client request, rejecting conflicting digests.
        """
        cache_entry = self.request_cache.get(request_key)
        if cache_entry:
            cache_entry.setdefault("dropped_sequences", set())
            canonical_digest = cache_entry.get("canonical_digest")
            if canonical_digest and canonical_digest != digest:
                self.forged_digests_by_request[request_key].add(digest)
                if self.logger:
                    client_id, timestamp = request_key
                    self.logger.warning(
                        "%s: Rejecting forged request digest for client=%s ts=%s",
                        self.node_id,
                        client_id,
                        timestamp,
                    )
                return None
            if not canonical_digest:
                cache_entry["canonical_digest"] = digest
            cache_entry["request"] = copy.deepcopy(request_payload)
        else:
            cache_entry = {
                "request": copy.deepcopy(request_payload),
                "canonical_digest": digest,
                "active_sequence": None,
                "last_view": view,
                "executed": False,
                "dropped_sequences": set(),
            }
            self.request_cache[request_key] = cache_entry

        if sequence is not None:
            cache_entry["active_sequence"] = sequence
            cache_entry["last_view"] = view
        else:
            cache_entry.setdefault("request", copy.deepcopy(request_payload))
        return cache_entry

    def cache_client_request(self, request_payload: Dict[str, Any]) -> None:
        """
        Cache a client request received while acting as a backup. If we later
        become primary we can immediately issue a PRE-PREPARE without waiting
        for the client retry.
        """
        client_id = request_payload.get("client_id")
        timestamp = request_payload.get("timestamp")
        if client_id is None or timestamp is None:
            return

        digest = compute_request_digest(request_payload)
        request_key = (client_id, timestamp)
        self._validate_and_cache_request(
            request_key,
            request_payload,
            digest,
            sequence=None,
            view=self.current_view,
        )

    def _send_reply_from_entry(
        self,
        sequence: int,
        entry: RequestLogEntry,
        client_info: Dict[str, Any],
    ) -> None:
        client_id = client_info.get("client_id")
        if not client_id:
            return
        result = entry.execution_result
        if result is None:
            return

        reply_msg = create_reply(
            replica_id=self.node_id,
            client_id=client_id,
            view=self.current_view,
            timestamp=client_info.get("timestamp", 0),
            result=result,
        )
        reply_msg.sign(self.crypto)

        self.send_to_client(reply_msg, client_id)
        request_key = (client_id, client_info.get("timestamp"))
        self.completed_requests[request_key] = {
            "sequence": sequence,
            "digest": entry.digest,
            "client_info": client_info,
            "result": result,
        }
        self.pending_requests.pop(request_key, None)
        self._log_event(sequence, f"sent REPLY to client {client_id} result={result}")
        if self.report_progress:
            self.report_progress()
        self._maybe_report_idle()

    def update_view(self, view: int):
        """Update the current view and reset per-view state if needed"""
        if self.logger:
            self.logger.debug(f"{self.node_id}: Updating view to {view}")

        self.current_view = view
        self.sync_sequence_cursor()

    def is_primary(self) -> bool:
        return self.is_primary_fn(self.current_view)

    def get_primary_id(self) -> str:
        return self.get_primary_id_fn(self.current_view)

    def sync_sequence_cursor(self):
        """Ensure the next sequence assigned will be monotonic with replica log."""
        highest_seq = self.replica_state.get_highest_sequence()
        low_mark = self.replica_state.low_water_mark
        self.next_sequence_number = max(highest_seq + 1, low_mark + 1)

    def handle_client_request(self, request_msg: Message) -> Optional[int]:
        """Primary handles a client REQUEST and initiates PRE-PREPARE"""
        if not self.is_primary():
            if self.logger:
                self.logger.warning(
                    f"{self.node_id}: Received client request but not primary in view {self.current_view}"
                )
            return None

        request_payload = request_msg.payload
        client_id = request_payload.get("client_id")
        if self.valid_clients and client_id not in self.valid_clients:
            if self.logger:
                self.logger.error(
                    f"{self.node_id}: Rejecting request from unknown client {client_id}"
                )
            return None

        digest = compute_request_digest(request_payload)
        request_key = (client_id, request_payload.get("timestamp"))

        cache_entry: Optional[Dict[str, Any]] = None
        if client_id is not None and request_payload.get("timestamp") is not None:
            cache_entry = self._validate_and_cache_request(
                request_key,
                request_payload,
                digest,
                sequence=None,
                view=self.current_view,
            )
            if cache_entry is None:
                return None

        if client_id is not None and request_payload.get("timestamp") is not None:
            existing = self.replica_state.find_sequence_by_client(client_id, request_payload.get("timestamp"))
            if existing:
                existing_sequence, existing_entry = existing
                self._ensure_client_tracking(existing_sequence, request_payload, existing_entry)

        completed = self.completed_requests.get(request_key)
        if completed:
            sequence = completed["sequence"]
            client_info = completed.get("client_info")
            result = completed.get("result")
            if client_info and result is not None:
                entry = self.replica_state.get_request_log_entry(sequence)
                if entry and entry.execution_result is None:
                    entry.execution_result = result
                if entry and entry.execution_result is not None:
                    self._send_reply_from_entry(sequence, entry, client_info)
                else:
                    reply_msg = create_reply(
                        replica_id=self.node_id,
                        client_id=client_info.get("client_id"),
                        view=self.current_view,
                        timestamp=client_info.get("timestamp", 0),
                        result=result,
                    )
                    reply_msg.sign(self.crypto)
                    self.send_to_client(reply_msg, client_info.get("client_id"))
            else:
                self._maybe_report_idle()
            return sequence

        pending = self.pending_requests.get(request_key)
        if pending:
            stale_sequence = pending.get("sequence")
            entry = (
                self.replica_state.get_request_log_entry(stale_sequence)
                if stale_sequence is not None
                else None
            )
            entry_view = entry.view if entry else -1
            should_reissue = (
                self.is_primary()
                and (
                    entry is None
                    or (
                        not entry.status_prepared
                        and not entry.status_committed
                        and not entry.status_executed
                        and entry_view < self.current_view
                    )
                )
            )

            if should_reissue:
                if stale_sequence is not None:
                    self._drop_sequence(stale_sequence, request_key, preserve_request=True)
                    self.sync_sequence_cursor()
                else:
                    self.pending_requests.pop(request_key, None)
                    self.sync_sequence_cursor()
            else:
                self._maybe_report_idle()
                return pending["sequence"]

        sequence = self._allocate_sequence(cache_entry)
        if sequence is None:
            return None

        if cache_entry is None and client_id is not None and request_payload.get("timestamp") is not None:
            cache_entry = self._validate_and_cache_request(
                request_key,
                request_payload,
                digest,
                sequence=None,
                view=self.current_view,
            )
            if cache_entry is None:
                return None

        if cache_entry is not None:
            cache_entry["active_sequence"] = sequence
            cache_entry["last_view"] = self.current_view
            cache_entry.setdefault("dropped_sequences", set()).discard(sequence)

        self.client_request_info[sequence] = {
            "client_id": request_payload.get("client_id"),
            "timestamp": request_payload.get("timestamp", 0),
            "request": copy.deepcopy(request_payload),
        }
        self.replica_state.add_request_log_entry(
            sequence,
            self.current_view,
            digest,
            request_payload,
            origin=self.node_id,
        )
        self.replica_state.mark_preprepared(sequence)
        self._log_event(
            sequence,
            f"accepted REQUEST from client {client_id} ts={request_payload.get('timestamp')}",
        )

        self.pending_requests[request_key] = {
            "sequence": sequence,
            "digest": digest,
            "client_info": self.client_request_info[sequence],
        }

        preprepare_msg = create_preprepare(
            primary_id=self.node_id,
            view=self.current_view,
            sequence=sequence,
            request_digest=digest,
            request=copy.deepcopy(request_payload),
        )
        preprepare_msg.sign(self.crypto)

        if self.logger:
            self.logger.info(
                f"{self.node_id}: Broadcasting PRE-PREPARE seq={sequence} view={self.current_view}"
            )

        self._log_event(sequence, "broadcast PRE-PREPARE to replicas")
        self.broadcast_to_replicas(preprepare_msg)

        self._send_prepare(sequence, digest)
        return sequence

    def handle_preprepare(self, msg: Message) -> bool:
        """Handle PRE-PREPARE message at backups"""
        if msg.msg_type != MSG_PREPREPARE:
            return False

        if msg.signer_id != self.get_primary_id():
            if self.logger:
                self.logger.warning(
                    f"{self.node_id}: PRE-PREPARE signer {msg.signer_id} != primary {self.get_primary_id()}"
                )
            return False

        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, msg.signer_id):
            if self.logger:
                self.logger.error(f"{self.node_id}: Invalid PRE-PREPARE signature from {msg.signer_id}")
            return False

        payload = msg.payload
        view = payload.get("view")
        sequence = payload.get("sequence")
        digest = payload.get("digest")
        request = payload.get("request", {})

        if sequence is None or sequence <= self.replica_state.last_executed_sequence:
            if self.logger:
                self.logger.debug(
                    f"{self.node_id}: Ignoring PRE-PREPARE for old/executed seq={sequence}"
                )
            return False

        if view != self.current_view:
            if self.logger:
                self.logger.warning(
                    f"{self.node_id}: PRE-PREPARE view {view} != current view {self.current_view}"
                )
            return False

        computed_digest = compute_request_digest(request)
        if computed_digest != digest:
            if self.logger:
                self.logger.error(
                    f"{self.node_id}: PRE-PREPARE digest mismatch seq={sequence}"
                )
            return False

        client_id = request.get("client_id")
        if self.valid_clients and client_id not in self.valid_clients:
            if self.logger:
                self.logger.error(
                    f"{self.node_id}: PRE-PREPARE with unknown client {client_id}"
                )
            return False

        if not self.replica_state.is_within_watermarks(sequence):
            if self.logger:
                self.logger.warning(
                    "%s: PRE-PREPARE seq=%s outside watermarks (low=%s high=%s)",
                    self.node_id,
                    sequence,
                    self.replica_state.low_water_mark,
                    self.replica_state.high_water_mark,
                )
            return False

        timestamp = request.get("timestamp")
        request_key: Optional[Tuple[str, int]] = None
        cache_entry: Optional[Dict[str, Any]] = None
        if client_id is not None and timestamp is not None:
            request_key = (client_id, timestamp)
            cache_entry = self._validate_and_cache_request(
                request_key,
                request,
                digest,
                sequence=None,
                view=view,
            )
            if cache_entry is None:
                return False

            existing = self.replica_state.find_sequence_by_client(client_id, timestamp)
            if existing:
                existing_seq, existing_entry = existing
                if existing_seq != sequence:
                    if (
                        existing_entry.view >= view
                        or existing_entry.status_prepared
                        or existing_entry.status_committed
                        or existing_entry.status_executed
                    ):
                        if self.logger:
                            self.logger.warning(
                                "%s: Ignoring conflicting PRE-PREPARE seq=%s view=%s (existing seq=%s view=%s for client %s ts=%s)",
                                self.node_id,
                                sequence,
                                view,
                                existing_seq,
                                existing_entry.view,
                                client_id,
                                timestamp,
                            )
                        self._ensure_client_tracking(existing_seq, existing_entry.request or request, existing_entry)
                        return False
                    self._log_event(
                        existing_seq,
                        f"discarding conflicting sequence (replaced by seq={sequence})",
                    )
                    self._drop_sequence(existing_seq, request_key, preserve_request=True)
                else:
                    cache_entry["active_sequence"] = sequence
                    cache_entry["last_view"] = view
                    self._ensure_client_tracking(existing_seq, existing_entry.request or request, existing_entry)

        if request_key and cache_entry:
            previous_sequence = cache_entry.get("active_sequence")
            if previous_sequence and previous_sequence != sequence:
                previous_entry = self.replica_state.get_request_log_entry(previous_sequence)
                if previous_entry and (
                    previous_entry.status_committed or previous_entry.status_executed
                ):
                    return False
                self._drop_sequence(previous_sequence, request_key, preserve_request=True)
                cache_entry["active_sequence"] = sequence
            else:
                cache_entry["active_sequence"] = sequence
            cache_entry["last_view"] = view
            cache_entry.setdefault("dropped_sequences", set()).discard(sequence)

        entry = self.replica_state.add_request_log_entry(
            sequence,
            view,
            digest,
            request,
            origin=msg.signer_id,
        )
        self.replica_state.mark_preprepared(sequence)
        self._log_event(sequence, f"received PRE-PREPARE from {msg.signer_id}")
        self._ensure_client_tracking(sequence, request, entry)

        self.client_request_info[sequence] = {
            "client_id": request.get("client_id"),
            "timestamp": request.get("timestamp", 0),
            "request": request,
        }
        self._send_prepare(sequence, digest)
        return True

    def _send_prepare(self, sequence: int, digest: str):
        """Replica (or primary) sends PREPARE to collector (primary)"""
        prepare_msg = create_prepare(
            replica_id=self.node_id,
            view=self.current_view,
            sequence=sequence,
            request_digest=digest,
        )
        prepare_msg.sign(self.crypto)

        self.replica_state.mark_prepared(
            sequence,
            self.node_id,
            prepare_msg.signature,
            quorum_size=QUORUM_PREPARE,
        )
        self.prepare_collections[sequence][self.node_id] = prepare_msg.signature
        self._log_event(sequence, "sent PREPARE to primary")

        if self.is_primary():
            self._collect_prepare(prepare_msg)
        else:
            if self.logger:
                self.logger.debug(f"{self.node_id}: Sending PREPARE seq={sequence} to primary")
            self.send_to_primary(prepare_msg)

    def handle_prepare(self, msg: Message) -> bool:
        """Handle PREPARE messages (collector or aggregated broadcast)"""
        payload = msg.payload
        sequence = payload.get("sequence")
        digest = payload.get("digest")
        view = payload.get("view")

        if sequence is None:
            return False

        if view != self.current_view:
            return False

        if not self.replica_state.is_within_watermarks(sequence):
            if self.logger:
                self.logger.warning(
                    "%s: PREPARE seq=%s outside watermarks (low=%s high=%s)",
                    self.node_id,
                    sequence,
                    self.replica_state.low_water_mark,
                    self.replica_state.high_water_mark,
                )
            return False

        certificate = payload.get("certificate")
        if certificate:
            return self._handle_prepare_certificate(msg)
        else:
            if not self.is_primary():
                return False
            return self._collect_prepare(msg)

    def _collect_prepare(self, msg: Message) -> bool:
        """Primary collects PREPARE signatures from replicas"""
        payload = msg.payload
        sequence = payload.get("sequence")
        digest = payload.get("digest")
        signer = msg.signer_id

        if sequence is None or sequence <= self.replica_state.last_executed_sequence:
            if self.logger:
                self.logger.debug(
                    f"{self.node_id}: Ignoring PREPARE for old/executed seq={sequence}"
                )
            return False

        if not self.replica_state.is_within_watermarks(sequence):
            if self.logger:
                self.logger.warning(
                    "%s: PREPARE seq=%s outside watermarks (low=%s high=%s)",
                    self.node_id,
                    sequence,
                    self.replica_state.low_water_mark,
                    self.replica_state.high_water_mark,
                )
            return False

        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, signer):
            return False

        entry = self.replica_state.get_request_log_entry(sequence)
        if not entry or entry.digest != digest:
            if self.logger:
                self.logger.warning(
                    f"{self.node_id}: PREPARE for unknown or mismatched request seq={sequence}"
                )
            return False

        existing_signature = self.prepare_collections[sequence].get(signer)
        if existing_signature is not None:
            if existing_signature != msg.signature:
                if self.logger:
                    self.logger.warning(
                        f"{self.node_id}: Conflicting PREPARE from {signer} for seq={sequence}"
                    )
                return False
        else:
            self.prepare_collections[sequence][signer] = msg.signature
            self.replica_state.mark_prepared(
                sequence,
                signer,
                msg.signature,
                quorum_size=QUORUM_PREPARE,
            )
            self._log_event(sequence, f"collected PREPARE from {signer}")

        if self.logger:
            self.logger.debug(
                f"{self.node_id}: Collected PREPARE from {signer} (total={len(self.prepare_collections[sequence])})"
            )

        if (
            len(self.prepare_collections[sequence]) >= QUORUM_PREPARE
            and not self.prepare_certificates_sent[sequence]
        ):
            self.prepare_certificates_sent[sequence] = True
            self._broadcast_prepare_certificate(sequence, entry.view, entry.digest)
        return True

    def _broadcast_prepare_certificate(self, sequence: int, view: int, digest: str):
        """Primary broadcasts aggregated PREPARE certificate to all replicas"""
        signatures_hex = {
            node: sig.hex() for node, sig in self.prepare_collections[sequence].items()
        }
        prepare_msg = create_prepare(
            replica_id=self.node_id,
            view=view,
            sequence=sequence,
            request_digest=digest,
        )
        prepare_msg.payload["certificate"] = {
            "phase": "prepare",
            "signatures": signatures_hex,
        }
        prepare_msg.sign(self.crypto)

        if self.logger:
            self.logger.info(
                f"{self.node_id}: Broadcasting PREPARE certificate seq={sequence}"
            )

        self.broadcast_to_replicas(prepare_msg)
        self._log_event(sequence, "broadcast PREPARE certificate to replicas")

        if self.report_progress:
            self.report_progress()

        if not self.commit_sent[sequence]:
            self._send_commit(sequence, digest)

    def _handle_prepare_certificate(self, msg: Message) -> bool:
        """Replicas process aggregated PREPARE certificates"""
        payload = msg.payload
        sequence = payload.get("sequence")
        digest = payload.get("digest")
        certificate = payload.get("certificate", {})
        signatures_hex = certificate.get("signatures", {})

        if sequence is None or sequence <= self.replica_state.last_executed_sequence:
            if self.logger:
                self.logger.debug(
                    f"{self.node_id}: Ignoring PREPARE certificate for old/executed seq={sequence}"
                )
            return False

        if not self.replica_state.is_within_watermarks(sequence):
            if self.logger:
                self.logger.warning(
                    "%s: PREPARE certificate seq=%s outside watermarks (low=%s high=%s)",
                    self.node_id,
                    sequence,
                    self.replica_state.low_water_mark,
                    self.replica_state.high_water_mark,
                )
            return False

        if msg.signer_id != self.get_primary_id():
            return False
        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, msg.signer_id):
            return False

        if not self._verify_certificate_signatures(
            phase_type=MSG_PREPARE,
            view=self.current_view,
            sequence=sequence,
            digest=digest,
            signatures_hex=signatures_hex,
            quorum=QUORUM_PREPARE,
        ):
            if self.logger:
                self.logger.error(f"{self.node_id}: Invalid PREPARE certificate seq={sequence}")
            return False

        entry = self.replica_state.get_request_log_entry(sequence)
        if not entry or entry.digest != digest:
            if self.logger:
                self.logger.warning(
                    f"{self.node_id}: PREPARE certificate mismatch seq={sequence} digest={digest}"
                )
            return False

        for node_id, sig_hex in signatures_hex.items():
            try:
                signature = bytes.fromhex(sig_hex)
            except (ValueError, TypeError):
                if self.logger:
                    self.logger.error(
                        "%s: Invalid hex in PREPARE certificate for seq=%s signer=%s",
                        self.node_id,
                        sequence,
                        node_id,
                    )
                return False
            self.replica_state.mark_prepared(
                sequence,
                node_id,
                signature,
                quorum_size=QUORUM_PREPARE,
            )
            self.prepare_collections[sequence][node_id] = signature

        self._log_event(sequence, f"processed PREPARE certificate from {msg.signer_id}")

        self._send_commit(sequence, digest)
        return True

    def _send_commit(self, sequence: int, digest: str, force: bool = False):
        """Replica sends COMMIT to primary collector"""
        if not force:
            if sequence <= self.replica_state.last_executed_sequence:
                if self.logger:
                    self.logger.debug(
                        f"{self.node_id}: Not sending COMMIT for already executed seq={sequence}"
                    )
                return
            if self.commit_sent[sequence]:
                return

        commit_msg = create_commit(
            replica_id=self.node_id,
            view=self.current_view,
            sequence=sequence,
            request_digest=digest,
        )
        commit_msg.sign(self.crypto)

        self.replica_state.mark_committed(sequence, self.node_id, commit_msg.signature)
        self.commit_collections[sequence][self.node_id] = commit_msg.signature
        self.commit_sent[sequence] = True

        if self.is_primary():
            self._collect_commit(commit_msg)
        else:
            self.send_to_primary(commit_msg)
            self._log_event(sequence, "sent COMMIT to primary")

    def reaffirm_entry(self, sequence: int, expected_digest: Optional[str] = None):
        """
        Re-send PREPARE/COMMIT messages for a sequence we already know,
        helping lagging replicas finish the protocol during a view change.
        """
        entry = self.replica_state.get_request_log_entry(sequence)
        if not entry:
            return

        digest = entry.digest
        if expected_digest and digest != expected_digest:
            return

        if entry.status_prepared and not self.is_primary():
            self._send_prepare(sequence, digest)

        if (entry.status_committed or entry.status_executed) and not self.is_primary():
            self._send_commit(sequence, digest, force=True)

    def handle_commit(self, msg: Message) -> bool:
        payload = msg.payload
        sequence = payload.get("sequence")
        view = payload.get("view")
        digest = payload.get("digest")

        if sequence is None:
            return False

        if view != self.current_view:
            return False

        if not self.replica_state.is_within_watermarks(sequence):
            if self.logger:
                self.logger.warning(
                    "%s: COMMIT seq=%s outside watermarks (low=%s high=%s)",
                    self.node_id,
                    sequence,
                    self.replica_state.low_water_mark,
                    self.replica_state.high_water_mark,
                )
            return False

        certificate = payload.get("certificate")
        if certificate:
            return self._handle_commit_certificate(msg)
        else:
            if not self.is_primary():
                return False
            return self._collect_commit(msg)

    def _collect_commit(self, msg: Message) -> bool:
        payload = msg.payload
        sequence = payload.get("sequence")
        digest = payload.get("digest")
        signer = msg.signer_id

        if sequence is None or sequence <= self.replica_state.last_executed_sequence:
            if self.logger:
                self.logger.debug(
                    f"{self.node_id}: Ignoring COMMIT for old/executed seq={sequence}"
                )
            return False

        if not self.replica_state.is_within_watermarks(sequence):
            if self.logger:
                self.logger.warning(
                    "%s: COMMIT seq=%s outside watermarks (low=%s high=%s)",
                    self.node_id,
                    sequence,
                    self.replica_state.low_water_mark,
                    self.replica_state.high_water_mark,
                )
            return False

        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, signer):
            if self.logger:
                self.logger.error(f"{self.node_id}: Invalid COMMIT signature from {signer}")
            return False

        entry = self.replica_state.get_request_log_entry(sequence)
        if not entry or entry.digest != digest:
            if self.logger:
                self.logger.warning(
                    f"{self.node_id}: COMMIT for unknown/mismatched seq={sequence}"
                )
            return False

        existing_signature = self.commit_collections[sequence].get(signer)
        if existing_signature is not None:
            if existing_signature != msg.signature:
                if self.logger:
                    self.logger.warning(
                        f"{self.node_id}: Conflicting COMMIT from {signer} for seq={sequence}"
                    )
                return False
        else:
            self.commit_collections[sequence][signer] = msg.signature
            self.replica_state.mark_committed(sequence, signer, msg.signature)
            self._log_event(sequence, f"collected COMMIT from {signer}")

        if self.logger:
            self.logger.debug(
                f"{self.node_id}: Collected COMMIT from {signer} (total={len(self.commit_collections[sequence])})"
            )

        if (
            len(self.commit_collections[sequence]) >= QUORUM_COMMIT
            and not self.commit_certificates_sent[sequence]
        ):
            self.commit_certificates_sent[sequence] = True
            self._broadcast_commit_certificate(sequence, entry.view, entry.digest)
            self.try_execute_requests()
        return True

    def _broadcast_commit_certificate(self, sequence: int, view: int, digest: str):
        signatures_hex = {
            node: sig.hex() for node, sig in self.commit_collections[sequence].items()
        }
        commit_msg = create_commit(
            replica_id=self.node_id,
            view=view,
            sequence=sequence,
            request_digest=digest,
        )
        commit_msg.payload["certificate"] = {
            "phase": "commit",
            "signatures": signatures_hex,
        }
        commit_msg.sign(self.crypto)

        if self.logger:
            self.logger.info(
                f"{self.node_id}: Broadcasting COMMIT certificate seq={sequence}"
            )

        self.broadcast_to_replicas(commit_msg)
        self._log_event(sequence, "broadcast COMMIT certificate to replicas")

        if self.report_progress:
            self.report_progress()

    def _handle_commit_certificate(self, msg: Message) -> bool:
        payload = msg.payload
        sequence = payload.get("sequence")
        digest = payload.get("digest")
        certificate = payload.get("certificate", {})
        signatures_hex = certificate.get("signatures", {})

        if sequence is None or sequence <= self.replica_state.last_executed_sequence:
            if self.logger:
                self.logger.debug(
                    f"{self.node_id}: Ignoring COMMIT certificate for old/executed seq={sequence}"
                )
            return False

        if not self.replica_state.is_within_watermarks(sequence):
            if self.logger:
                self.logger.warning(
                    "%s: COMMIT certificate seq=%s outside watermarks (low=%s high=%s)",
                    self.node_id,
                    sequence,
                    self.replica_state.low_water_mark,
                    self.replica_state.high_water_mark,
                )
            return False

        if msg.signer_id != self.get_primary_id():
            return False
        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, msg.signer_id):
            return False

        if not self._verify_certificate_signatures(
            phase_type=MSG_COMMIT,
            view=self.current_view,
            sequence=sequence,
            digest=digest,
            signatures_hex=signatures_hex,
            quorum=QUORUM_COMMIT,
        ):
            if self.logger:
                self.logger.error(f"{self.node_id}: Invalid COMMIT certificate seq={sequence}")
            return False

        entry = self.replica_state.get_request_log_entry(sequence)
        if not entry or entry.digest != digest:
            if self.logger:
                self.logger.warning(
                    f"{self.node_id}: COMMIT certificate mismatch seq={sequence} digest={digest}"
                )
            return False

        for node_id, sig_hex in signatures_hex.items():
            try:
                signature = bytes.fromhex(sig_hex)
            except (ValueError, TypeError):
                if self.logger:
                    self.logger.error(
                        "%s: Invalid hex in COMMIT certificate for seq=%s signer=%s",
                        self.node_id,
                        sequence,
                        node_id,
                    )
                return False
            self.replica_state.mark_committed(sequence, node_id, signature)
            self.commit_collections[sequence][node_id] = signature

        self._log_event(sequence, f"processed COMMIT certificate from {msg.signer_id}")

        self.try_execute_requests()
        return True

    def handle_checkpoint(self, msg: Message) -> bool:
        if msg.msg_type != MSG_CHECKPOINT:
            return False

        payload = msg.payload
        sequence = payload.get("sequence")
        state_digest = payload.get("state_digest")
        signer = msg.signer_id

        if sequence is None or state_digest is None or not signer:
            return False

        if not msg.signature:
            return False

        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, signer):
            if self.logger:
                self.logger.error(f"{self.node_id}: Invalid CHECKPOINT signature from {signer}")
            return False

        if sequence > self.replica_state.last_executed_sequence:
            if self.logger:
                self.logger.debug(
                    "%s: Recording CHECKPOINT seq=%s before execution (last_executed=%s)",
                    self.node_id,
                    sequence,
                    self.replica_state.last_executed_sequence,
                )

        self._log_event(sequence, f"received CHECKPOINT from {signer} digest={state_digest}")

        became_stable = self.replica_state.record_checkpoint_vote(
            sequence,
            state_digest,
            signer,
            msg.signature,
        )

        if became_stable:
            self._on_stable_checkpoint(sequence, state_digest)

        return True

    def _maybe_emit_checkpoint(self, sequence: int):
        if not self.replica_state.should_emit_checkpoint(sequence):
            return

        state_digest = self.replica_state.compute_state_digest()
        checkpoint_msg = create_checkpoint(
            replica_id=self.node_id,
            sequence=sequence,
            state_digest=state_digest,
        )
        checkpoint_msg.sign(self.crypto)

        if self.logger:
            self.logger.info(
                f"{self.node_id}: Broadcasting CHECKPOINT seq={sequence}"
            )

        self.broadcast_to_replicas(checkpoint_msg)
        self._log_event(sequence, f"broadcast CHECKPOINT digest={state_digest}")
        self.handle_checkpoint(checkpoint_msg)

    def _on_stable_checkpoint(self, sequence: int, state_digest: str):
        if self.logger:
            self.logger.info(
                "%s: Stable checkpoint established at seq=%s digest=%s",
                self.node_id,
                sequence,
                state_digest,
            )

        self._prune_protocol_state(sequence)
        self.sync_sequence_cursor()
        if self.report_progress:
            self.report_progress()
        self._maybe_report_idle()

    def _prune_protocol_state(self, sequence: int):
        """
        Historically this cleared consensus caches below the checkpoint.
        We now retain them to keep full consensus history available after checkpoints.
        """
        return


    def try_execute_requests(self):
        """Execute all committed requests in order and send replies to clients"""
        while True:
            next_exec = self.replica_state.execute_next(QUORUM_COMMIT)
            if not next_exec:
                break

            sequence, result = next_exec
            client_info = self.client_request_info.get(sequence)
            entry = self.replica_state.get_request_log_entry(sequence)
            if not client_info and entry and entry.request:
                ensured = self._ensure_client_tracking(sequence, entry.request, entry)
                if ensured:
                    client_info = ensured[0]
            if not client_info:
                self._maybe_emit_checkpoint(sequence)
                continue
            self._log_event(sequence, f"executed request result={result}")

            reply_msg = create_reply(
                replica_id=self.node_id,
                client_id=client_info.get("client_id"),
                view=self.current_view,
                timestamp=client_info.get("timestamp", 0),
                result=result,
            )
            reply_msg.sign(self.crypto)

            if self.logger:
                self.logger.info(
                    f"{self.node_id}: Sending REPLY seq={sequence} to client {client_info.get('client_id')}"
                )

            self.send_to_client(reply_msg, client_info.get("client_id"))
            self._log_event(
                sequence,
                f"sent REPLY to client {client_info.get('client_id')} result={result}",
            )

            request_payload = client_info.get("request", {}) if client_info else {}
            request_key = (client_info.get("client_id"), client_info.get("timestamp"))
            if request_key in self.pending_requests:
                self.pending_requests.pop(request_key, None)
            self.completed_requests[request_key] = {
                "sequence": sequence,
                "digest": entry.digest if entry else self.replica_state.get_request_digest(sequence),
                "client_info": client_info,
                "request": request_payload,
                "result": result,
            }

            cache_entry = self.request_cache.get(request_key)
            if cache_entry:
                cache_entry["executed"] = True
                cache_entry["active_sequence"] = sequence
                cache_entry["last_view"] = self.current_view

            self._maybe_emit_checkpoint(sequence)

            if self.report_progress:
                self.report_progress()

        self._maybe_report_idle()

    def _verify_certificate_signatures(
        self,
        phase_type: str,
        view: int,
        sequence: int,
        digest: str,
        signatures_hex: Dict[str, str],
        quorum: int,
    ) -> bool:
        """Verify that a certificate contains >= quorum valid signatures"""
        if len(signatures_hex) < quorum:
            return False

        payload = {
            "view": view,
            "sequence": sequence,
            "digest": digest,
        }
        message_data = {
            "type": phase_type,
            "payload": payload,
        }

        for node_id, sig_hex in signatures_hex.items():
            try:
                signature = bytes.fromhex(sig_hex)
            except (ValueError, TypeError):
                return False
            if not self.public_keys.verify_message(message_data, signature, node_id):
                return False
        return True

    def get_prepare_signers(self, sequence: int) -> Dict[str, bytes]:
        return self.prepare_collections.get(sequence, {}).copy()

    def get_commit_signers(self, sequence: int) -> Dict[str, bytes]:
        return self.commit_collections.get(sequence, {}).copy()

    def reset_collections(self, *, clear_client_state: bool = False):
        """
        Clear collector state.

        Args:
            clear_client_state: When True, also clears client-facing caches.
                This should only be used during FLUSH (full system reset).
        """
        self.prepare_collections.clear()
        self.commit_collections.clear()
        self.prepare_certificates_sent.clear()
        self.commit_certificates_sent.clear()
        self.commit_sent.clear()

        if clear_client_state:
            self.client_request_info.clear()
            self.pending_requests.clear()
            self.completed_requests.clear()
            self.request_cache.clear()
            self.forged_digests_by_request.clear()
            self.next_sequence_number = 1
        if self.logger:
            self.logger.debug(f"{self.node_id}: Collector state reset")

    def _maybe_report_idle(self):
        if self.report_idle and not self.replica_state.has_pending_requests() and not self.pending_requests:
            self.report_idle()

    def reissue_cached_requests(self) -> None:
        """Primary replays cached requests that lack prepared state in the current view."""
        if not self.is_primary():
            return

        for request_key, cache_entry in list(self.request_cache.items()):
            if cache_entry.get("executed"):
                continue

            request = cache_entry.get("request")
            digest = cache_entry.get("canonical_digest")
            if not request or not digest:
                continue
            request = copy.deepcopy(request)

            sequence = cache_entry.get("active_sequence")
            entry = (
                self.replica_state.get_request_log_entry(sequence)
                if sequence is not None
                else None
            )

            need_new_sequence = False
            if sequence is None or entry is None:
                need_new_sequence = True
            elif entry.status_prepared or entry.status_committed or entry.status_executed:
                continue
            elif entry.view < self.current_view:
                self._drop_sequence(sequence, request_key, preserve_request=True)
                need_new_sequence = True
            else:
                continue

            if not need_new_sequence:
                continue

            new_sequence = self._allocate_sequence(cache_entry)
            if new_sequence is None:
                continue

            cache_entry["active_sequence"] = new_sequence
            cache_entry["last_view"] = self.current_view
            cache_entry.setdefault("dropped_sequences", set()).discard(new_sequence)

            client_id = request.get("client_id")
            timestamp = request.get("timestamp", 0)
            self.client_request_info[new_sequence] = {
                "client_id": client_id,
                "timestamp": timestamp,
                "request": copy.deepcopy(request),
            }

            self.replica_state.add_request_log_entry(
                new_sequence,
                self.current_view,
                digest,
                request,
                origin=self.node_id,
            )
            self.replica_state.mark_preprepared(new_sequence)

            self._log_event(
                new_sequence,
                f"reissued cached request for client {client_id} ts={timestamp}",
            )

            self.pending_requests[request_key] = {
                "sequence": new_sequence,
                "digest": digest,
                "client_info": self.client_request_info[new_sequence],
            }

            preprepare_msg = create_preprepare(
                primary_id=self.node_id,
                view=self.current_view,
                sequence=new_sequence,
                request_digest=digest,
                request=request,
            )
            preprepare_msg.sign(self.crypto)
            self._log_event(new_sequence, "broadcast PRE-PREPARE to replicas (reissue)")
            self.broadcast_to_replicas(preprepare_msg)
            self._send_prepare(new_sequence, digest)
