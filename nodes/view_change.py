"""
View change management for Linear-PBFT (PBFT-style view changes)
"""

import time
import copy
from collections import defaultdict
from typing import Callable, Dict, Optional, Set, Any, List, Tuple
import random

from src.constants import (
    MSG_VIEWCHANGE,
    MSG_NEWVIEW,
    MSG_CHECKPOINT,
    QUORUM_VIEWCHANGE,
    VIEWCHANGE_DELAY_BASE,
    VIEWCHANGE_DELAY_MULTIPLIER,
    VIEWCHANGE_DELAY_JITTER,
    F,
)
from src.message import (
    Message,
    create_viewchange,
    create_newview,
    create_preprepare,
    compute_request_digest,
)
from nodes.replica import ReplicaState
from nodes.protocol_linear_pbft import LinearPBFTProtocol
from src.crypto import CryptoManager, PublicKeyRegistry


class ViewChangeManager:
    """
    Handles PBFT view-change protocol (same as original PBFT) for Linear-PBFT system
    """

    def __init__(
        self,
        node_id: str,
        replica_state: ReplicaState,
        protocol: LinearPBFTProtocol,
        crypto: CryptoManager,
        public_keys: PublicKeyRegistry,
        broadcast_to_replicas: Callable[[Message], None],
        send_to_primary: Callable[[Message], None],
        on_view_change_start: Callable[[int], None],
        on_view_change_complete: Callable[[int], None],
        get_primary_id_fn: Callable[[int], str],
        logger=None,
    ):
        self.node_id = node_id
        self.replica_state = replica_state
        self.protocol = protocol
        self.crypto = crypto
        self.public_keys = public_keys
        self.broadcast_to_replicas = broadcast_to_replicas
        self.send_to_primary = send_to_primary
        self.on_view_change_start = on_view_change_start
        self.on_view_change_complete = on_view_change_complete
        self.get_primary_id_fn = get_primary_id_fn
        self.logger = logger

        self.current_view = 0
        self.highest_view = 0
        self.in_view_change = False
        self.pending_view = 0
        self.viewchange_messages: Dict[int, Dict[str, Message]] = defaultdict(dict)
        self.newview_messages: Dict[int, Message] = {}

        self.viewchange_timeout_ms = self._randomized_timeout()
        self.last_progress_time = time.time()
        self.started = False
        self.viewchange_trigger = F + 1

    def update_view(self, new_view: int):
        if new_view > self.current_view:
            self.current_view = new_view
            self.highest_view = max(self.highest_view, new_view)
            self.protocol.update_view(new_view)
            if self.logger:
                self.logger.info(f"{self.node_id}: View updated to {new_view}")

    def record_progress(self):
        """Call when normal-case progress is made to reset timers"""
        self.viewchange_timeout_ms = self._randomized_timeout()
        self.last_progress_time = time.time()
        self.started = True
        self.pending_view = self.current_view

    def record_idle(self):
        """Disable timeout monitoring when no work is outstanding."""
        self.started = False

    def check_timeout(self) -> Optional[int]:
        if not self.started:
            return None

        now = time.time()
        elapsed = (now - self.last_progress_time) * 1000
        if elapsed >= self.viewchange_timeout_ms:
            if self.pending_view == self.current_view:
                next_view = self.current_view + 1
            else:
                next_view = max(self.highest_view, self.pending_view + 1)
            self.start_view_change(next_view)
            self.viewchange_timeout_ms = self._randomized_timeout(
                self.viewchange_timeout_ms * VIEWCHANGE_DELAY_MULTIPLIER
            )
            self.last_progress_time = time.time()
            return next_view
        return None
    def start_view_change(self, target_view: int):
        if target_view <= max(self.current_view, self.pending_view):
            return

        if self.logger:
            self.logger.warning(f"{self.node_id}: Initiating view change to {target_view}")

        self.in_view_change = True
        self.pending_view = target_view
        self.highest_view = max(self.highest_view, target_view)
        self.on_view_change_start(target_view)

        prepared_proofs = self._collect_prepared_proofs()
        checkpoint = self._collect_checkpoint_proof()

        viewchange_msg = create_viewchange(
            replica_id=self.node_id,
            new_view=target_view,
            prepared_proofs=prepared_proofs,
            checkpoint_proof=checkpoint,
        )
        viewchange_msg.sign(self.crypto)

        primary_id = self.get_primary_id_fn(target_view)
        if self.logger:
            self.logger.info(
                f"{self.node_id}: Sending VIEWCHANGE for view {target_view} to {primary_id}"
            )

        if primary_id == self.node_id:
            self.handle_view_change(viewchange_msg)
        else:
            self.send_to_primary(viewchange_msg)
        self.broadcast_to_replicas(viewchange_msg)
    def handle_view_change(self, msg: Message) -> bool:
        if msg.msg_type != MSG_VIEWCHANGE:
            return False

        view = msg.payload.get("new_view")
        signer = msg.signer_id

        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, signer):
            return False

        if view <= self.current_view:
            return False

        self.highest_view = max(self.highest_view, view)
        self.viewchange_messages[view][signer] = self._clone_message(msg)

        if self.logger:
            self.logger.debug(
                f"{self.node_id}: Collected VIEWCHANGE from {signer} for view {view} (total={len(self.viewchange_messages[view])})"
            )

        if view > self.pending_view:
            if len(self.viewchange_messages[view]) >= self.viewchange_trigger:
                self.start_view_change(view)

        if self.node_id == self.get_primary_id_fn(view):
            if len(self.viewchange_messages[view]) >= QUORUM_VIEWCHANGE:
                self._try_send_new_view(view)

        return True
    def handle_new_view(self, msg: Message) -> bool:
        if msg.msg_type != MSG_NEWVIEW:
            return False

        view = msg.payload.get("new_view")
        signer = msg.signer_id

        if signer != self.get_primary_id_fn(view):
            return False

        if not self.public_keys.verify_message(msg.get_data_to_sign(), msg.signature, signer):
            return False

        view_changes = msg.payload.get("view_changes", [])
        new_view_proofs_raw = msg.payload.get("new_view_proofs", {})
        new_view_proofs = self._normalize_new_view_proofs(new_view_proofs_raw)

        if len(view_changes) < QUORUM_VIEWCHANGE:
            if self.logger:
                self.logger.error(f"{self.node_id}: NEWVIEW missing enough view-changes")
            return False

        if view > self.pending_view:
            self.pending_view = view
        self.viewchange_timeout_ms = self._randomized_timeout()
        self.last_progress_time = time.time()
        self.started = True

        reconstructed_vc = {}
        for vc_dict in view_changes:
            inner_msg = Message(
                msg_type=MSG_VIEWCHANGE,
                payload=vc_dict.get("payload", {}),
                signer_id=vc_dict.get("signer_id", ""),
                signature=bytes.fromhex(vc_dict.get("signature", "")) if vc_dict.get("signature") else b"",
            )
            signer_id = inner_msg.signer_id
            if not signer_id:
                return False
            if not self.public_keys.verify_message(inner_msg.get_data_to_sign(), inner_msg.signature, signer_id):
                if self.logger:
                    self.logger.error(f"{self.node_id}: Invalid embedded VIEWCHANGE from {signer_id}")
                return False
            reconstructed_vc[signer_id] = inner_msg

        expected_checkpoint_raw, expected_checkpoint_verified = self._select_checkpoint_proof(
            reconstructed_vc, allow_local_fallback=False
        )
        provided_checkpoint_raw = msg.payload.get("checkpoint_proof")
        checkpoint_verified = None

        if expected_checkpoint_raw:
            checkpoint_verified = self._verify_checkpoint_proof(provided_checkpoint_raw)
            if not checkpoint_verified:
                if self.logger:
                    self.logger.error(
                        "%s: NEWVIEW missing valid checkpoint proof despite expectations for view %s",
                        self.node_id,
                        view,
                    )
                return False
            if (
                checkpoint_verified["sequence"] != expected_checkpoint_verified["sequence"]
                or checkpoint_verified["state_digest"] != expected_checkpoint_verified["state_digest"]
            ):
                if self.logger:
                    self.logger.error(
                        "%s: NEWVIEW checkpoint proof mismatch (expected seq=%s digest=%s)",
                        self.node_id,
                        expected_checkpoint_verified["sequence"],
                        expected_checkpoint_verified["state_digest"],
                    )
                return False
            expected_nodes = set(expected_checkpoint_verified["signatures"].keys())
            provided_nodes = set(checkpoint_verified["signatures"].keys())
            if not expected_nodes.issubset(provided_nodes):
                if self.logger:
                    self.logger.error(
                        "%s: NEWVIEW checkpoint proof missing required signer coverage",
                        self.node_id,
                    )
                return False
        elif provided_checkpoint_raw:
            checkpoint_verified = self._verify_checkpoint_proof(provided_checkpoint_raw)
            if not checkpoint_verified:
                if self.logger:
                    self.logger.error(
                        "%s: NEWVIEW included invalid checkpoint proof",
                        self.node_id,
                    )
                return False

        checkpoint_sequence = checkpoint_verified["sequence"] if checkpoint_verified else 0

        expected_o_set, valid = self._build_o_set(view, reconstructed_vc, checkpoint_sequence)
        if not valid:
            if self.logger:
                self.logger.error(
                    f"{self.node_id}: Conflicting proofs detected when validating NEWVIEW for view {view}"
                )
            return False

        for seq, expected in expected_o_set.items():
            proof = new_view_proofs.get(seq)
            if not proof or proof.get("digest") != expected.get("digest"):
                if self.logger:
                    self.logger.error(
                        f"{self.node_id}: NEWVIEW proof mismatch for seq={seq}"
                    )
                return False

        self.newview_messages[view] = self._clone_message(msg)

        self._adopt_new_view(view, reconstructed_vc, new_view_proofs, checkpoint_verified)
        return True
    def _collect_prepared_proofs(self) -> List[Dict[str, Any]]:
        proofs = []
        for sequence, entry in self.replica_state.log.items():
            if entry.status_prepared:
                proof = {
                    "sequence": sequence,
                    "view": entry.view,
                    "digest": entry.digest,
                    "request": copy.deepcopy(entry.request) if entry.request is not None else {},
                    "prepare_signers": [
                        {"node": node_id, "signature": sig.hex()}
                        for node_id, sig in entry.prepare_signatures.items()
                    ],
                }
                proofs.append(proof)
        return proofs

    def _collect_checkpoint_proof(self) -> Optional[Dict[str, Any]]:
        return self.replica_state.get_stable_checkpoint_proof()

    def _verify_checkpoint_proof(
        self, proof: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        if not proof:
            return None

        sequence = proof.get("sequence")
        state_digest = proof.get("state_digest")
        signers = proof.get("signers", [])

        if sequence is None or state_digest is None or not isinstance(signers, list):
            return None

        try:
            sequence = int(sequence)
        except (TypeError, ValueError):
            return None

        checkpoint_msg = Message(
            msg_type=MSG_CHECKPOINT,
            payload={"sequence": sequence, "state_digest": state_digest},
            signer_id="",
            signature=b"",
        )
        data_to_verify = checkpoint_msg.get_data_to_sign()

        signatures: Dict[str, bytes] = {}
        for signer_info in signers:
            if not isinstance(signer_info, dict):
                return None
            node_id = signer_info.get("node")
            signature_hex = signer_info.get("signature")
            if not node_id or not signature_hex:
                return None
            try:
                signature = bytes.fromhex(signature_hex)
            except (ValueError, TypeError):
                return None
            if not self.public_keys.verify_message(data_to_verify, signature, node_id):
                return None
            signatures[node_id] = signature

        if len(signatures) < QUORUM_VIEWCHANGE:
            return None

        return {
            "sequence": sequence,
            "state_digest": state_digest,
            "signatures": signatures,
        }

    def _select_checkpoint_proof(
        self,
        viewchange_msgs: Dict[str, Message],
        allow_local_fallback: bool,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        best_raw: Optional[Dict[str, Any]] = None
        best_verified: Optional[Dict[str, Any]] = None
        best_sequence = -1

        for msg in viewchange_msgs.values():
            proof = msg.payload.get("checkpoint_proof")
            verified = self._verify_checkpoint_proof(proof)
            if not verified:
                continue
            if verified["sequence"] > best_sequence:
                best_sequence = verified["sequence"]
                best_raw = proof
                best_verified = verified

        if best_raw is None and allow_local_fallback:
            local_proof = self.replica_state.get_stable_checkpoint_proof()
            verified_local = self._verify_checkpoint_proof(local_proof)
            if verified_local:
                best_raw = local_proof
                best_verified = verified_local

        return best_raw, best_verified

    def _try_send_new_view(self, target_view: int):
        viewchange_msgs = self.viewchange_messages.get(target_view, {})
        if len(viewchange_msgs) < QUORUM_VIEWCHANGE:
            return

        checkpoint_raw, checkpoint_verified = self._select_checkpoint_proof(
            viewchange_msgs, allow_local_fallback=True
        )
        checkpoint_sequence = checkpoint_verified["sequence"] if checkpoint_verified else 0

        o_set, valid = self._build_o_set(target_view, viewchange_msgs, checkpoint_sequence)
        if not valid:
            if self.logger:
                self.logger.error(
                    f"{self.node_id}: Aborting NEWVIEW construction due to conflicting prepared proofs"
                )
            return

        view_changes_payload = [
            {
                "payload": copy.deepcopy(msg.payload),
                "signer_id": signer,
                "signature": msg.signature.hex() if msg.signature else "",
            }
            for signer, msg in viewchange_msgs.items()
        ]

        new_view_msg = create_newview(
            primary_id=self.node_id,
            new_view=target_view,
            view_changes=view_changes_payload,
            new_view_proofs=o_set,
            checkpoint_proof=copy.deepcopy(checkpoint_raw) if checkpoint_raw else None,
        )
        new_view_msg.sign(self.crypto)

        if self.logger:
            self.logger.info(
                f"{self.node_id}: Broadcasting NEWVIEW for view {target_view}"
            )

        self.record_progress()
        if target_view > self.pending_view:
            self.pending_view = target_view

        self.broadcast_to_replicas(new_view_msg)
        self.handle_new_view(new_view_msg)

    def _build_o_set(
        self,
        target_view: int,
        viewchange_msgs: Dict[str, Message],
        checkpoint_sequence: int,
    ) -> Tuple[Dict[int, Dict[str, Any]], bool]:
        o_set: Dict[int, Dict[str, Any]] = {}
        valid = True

        for msg in viewchange_msgs.values():
            prepared_proofs = msg.payload.get("prepared_proofs", [])
            for proof in prepared_proofs:
                seq = proof.get("sequence")
                proof_view = proof.get("view")
                digest = proof.get("digest")
                request = proof.get("request")

                if seq is None or digest is None or seq <= checkpoint_sequence:
                    continue

                entry = o_set.get(seq)
                if entry is None:
                    o_set[seq] = {
                        "view": proof_view,
                        "sequence": seq,
                        "digest": digest,
                        "request": copy.deepcopy(request),
                        "prepare_signers": copy.deepcopy(proof.get("prepare_signers", [])),
                    }
                else:
                    existing_view = entry.get("view", -1)
                    existing_digest = entry.get("digest")
                    if proof_view > existing_view:
                        o_set[seq] = {
                            "view": proof_view,
                            "sequence": seq,
                            "digest": digest,
                            "request": copy.deepcopy(request),
                            "prepare_signers": copy.deepcopy(proof.get("prepare_signers", [])),
                        }
                    elif proof_view == existing_view and existing_digest != digest:
                        if self.logger:
                            self.logger.error(
                                f"{self.node_id}: Conflicting prepared proofs for seq={seq} view={proof_view}"
                            )
                        valid = False
                        break
            if not valid:
                break

        return o_set, valid

    def _adopt_new_view(
        self,
        target_view: int,
        viewchange_msgs: Dict[str, Message],
        o_set: Dict[int, Dict[str, Any]],
        checkpoint_info: Optional[Dict[str, Any]],
    ):
        if target_view <= self.current_view:
            return

        if self.logger:
            self.logger.info(f"{self.node_id}: Adopting new view {target_view}")

        if checkpoint_info:
            self.replica_state.apply_stable_checkpoint(
                checkpoint_info["sequence"],
                checkpoint_info["state_digest"],
                checkpoint_info["signatures"],
            )
            if hasattr(self.protocol, "_prune_protocol_state"):
                self.protocol._prune_protocol_state(checkpoint_info["sequence"])

        self.update_view(target_view)
        self.in_view_change = False
        self.pending_view = target_view
        self.viewchange_messages = defaultdict(
            dict,
            {k: v for k, v in self.viewchange_messages.items() if k > target_view},
        )
        self.protocol.reset_collections()

        primary_id = self.get_primary_id_fn(target_view)

        if self.node_id == primary_id:
            for seq, proof in o_set.items():
                request = proof.get("request")
                if not request:
                    continue
                digest = proof.get("digest")
                client_id = request.get("client_id")
                timestamp = request.get("timestamp")

                if client_id is not None and timestamp is not None:
                    existing = self.replica_state.find_sequence_by_client(client_id, timestamp)
                    if existing and existing[0] != seq:
                        if self.logger:
                            self.logger.warning(
                                "%s: Skipping O-set entry seq=%s (client %s ts=%s already tracked as seq=%s)",
                                self.node_id,
                                seq,
                                client_id,
                                timestamp,
                                existing[0],
                            )
                        continue

                self.replica_state.add_request_log_entry(
                    sequence=seq,
                    view=target_view,
                    digest=digest,
                    request=copy.deepcopy(request),
                    origin=primary_id,
                    preserve_existing_view=True,
                )
                entry = self.replica_state.get_request_log_entry(seq)
                if entry:
                    self.protocol._ensure_client_tracking(seq, entry.request or {}, entry)

                preprepare_msg = create_preprepare(
                    primary_id=primary_id,
                    view=target_view,
                    sequence=seq,
                    request_digest=digest,
                    request=request,
                )
                preprepare_msg.sign(self.crypto)

                self.broadcast_to_replicas(preprepare_msg)
                self.protocol.handle_preprepare(preprepare_msg)

        for seq, proof in o_set.items():
            digest = proof.get("digest")
            self.protocol.reaffirm_entry(seq, digest)

        if self.node_id == primary_id:
            self.protocol.reissue_cached_requests()

        self.protocol.sync_sequence_cursor()

        self.record_progress()

        self.on_view_change_complete(target_view)

    def _normalize_new_view_proofs(self, proofs: Dict[Any, Any]) -> Dict[int, Dict[str, Any]]:
        normalized: Dict[int, Dict[str, Any]] = {}
        for key, value in proofs.items():
            try:
                seq = int(key)
            except (ValueError, TypeError):
                seq = key
            normalized[seq] = copy.deepcopy(value)
        return normalized

    def _randomized_timeout(self, base: Optional[float] = None) -> float:
        reference = base if base is not None else VIEWCHANGE_DELAY_BASE
        jitter_range = VIEWCHANGE_DELAY_JITTER
        lower = 1.0 - jitter_range
        upper = 1.0 + jitter_range
        factor = random.uniform(lower, upper)
        return max(0.5 * VIEWCHANGE_DELAY_BASE, reference * factor)

    def reset(self):
        """Reset view-change state (called during FLUSH)"""
        self.in_view_change = False
        self.viewchange_messages.clear()
        self.newview_messages.clear()
        self.current_view = 0
        self.highest_view = 0
        self.pending_view = 0
        self.viewchange_timeout_ms = VIEWCHANGE_DELAY_BASE
        self.last_progress_time = time.time()
        self.started = False
        if self.logger:
            self.logger.debug(f"{self.node_id}: View-change state reset")

    def get_view_snapshot(self) -> Dict[str, Any]:
        viewchange_messages = {
            view: list(messages.keys())
            for view, messages in self.viewchange_messages.items()
        }
        newview_details = {
            view: msg.to_dict()
            for view, msg in self.newview_messages.items()
        }
        return {
            "current_view": self.current_view,
            "highest_view": self.highest_view,
            "in_view_change": self.in_view_change,
            "viewchange_messages": viewchange_messages,
            "newview_messages": list(newview_details.keys()),
            "newview_details": newview_details,
            "low_water_mark": self.replica_state.low_water_mark,
            "high_water_mark": self.replica_state.high_water_mark,
            "stable_checkpoint": {
                "sequence": self.replica_state.stable_checkpoint_sequence,
                "state_digest": self.replica_state.stable_checkpoint_digest,
                "signers": sorted(self.replica_state.stable_checkpoint_signatures.keys()),
            },
        }

    def _clone_message(self, msg: Message) -> Message:
        return Message(
            msg_type=msg.msg_type,
            payload=copy.deepcopy(msg.payload),
            signer_id=msg.signer_id,
            signature=bytes(msg.signature) if isinstance(msg.signature, (bytes, bytearray)) else msg.signature,
        )
