"""
Replica state management for Linear-PBFT
Handles datastore (balances), request log, and banking operations
"""

import hashlib
import copy
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any

from src.constants import (
    INITIAL_BALANCE,
    STATUS_PPREPARED,
    STATUS_PREPARED,
    STATUS_COMMITTED,
    STATUS_EXECUTED,
    STATUS_NONE,
    TXN_BALANCE,
    TXN_TRANSFER,
    LOG_HIGH_WATER_DELTA,
    CHECKPOINT_INTERVAL,
    QUORUM_VIEWCHANGE,
)


class RequestLogEntry:
    """
    Log entry for a single request/sequence number
    """

    def __init__(
        self,
        sequence: int,
        view: int,
        digest: str,
        request: Dict,
        preprepare_sender: str = "",
    ):
        self.sequence = sequence
        self.view = view
        self.digest = digest
        self.request = request
        self.preprepare_sender = preprepare_sender

        self.status_pprepared = False
        self.status_prepared = False
        self.status_committed = False
        self.status_executed = False
        self.prepare_signatures: Dict[str, bytes] = {}
        self.commit_signatures: Dict[str, bytes] = {}
        self.execution_result = None
        self.events: List[str] = []


class ReplicaState:
    """
    Manages replica state: datastore (balances) and request log
    """
    
    def __init__(self, initial_balance: int = INITIAL_BALANCE):
        self.balances: Dict[str, int] = {}
        self.initial_balance = initial_balance
        self.log: Dict[int, RequestLogEntry] = {}
        self.executed_sequences: Set[int] = set()
        self.last_executed_sequence = 0
        self.low_water_mark = 0
        self.high_water_mark = self.low_water_mark + LOG_HIGH_WATER_DELTA
        self.stable_checkpoint_sequence = 0
        self.stable_checkpoint_digest = ""
        self.stable_checkpoint_signatures: Dict[str, bytes] = {}
        self.checkpoint_votes: Dict[int, Dict[str, Dict[str, bytes]]] = defaultdict(
            lambda: defaultdict(dict)
        )
        
        self._initialize_balances()
        self.stable_checkpoint_digest = self.compute_state_digest()
    
    def _initialize_balances(self):
        """Initialize all client balances to initial_balance"""
        for i in range(10):
            client_id = chr(65 + i)
            self.balances[client_id] = self.initial_balance
    
    def get_balance(self, client_id: str) -> int:
        """
        Get balance for a client
        
        Args:
            client_id: Client ID (A-J)
            
        Returns:
            Current balance
        """
        return self.balances.get(client_id, 0)
    
    def execute_transfer(self, sender: str, receiver: str, amount: int) -> Tuple[bool, str]:
        """
        Execute a transfer transaction
        
        Args:
            sender: Sender client ID
            receiver: Receiver client ID
            amount: Transfer amount
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        if sender not in self.balances:
            return False, f"Sender {sender} does not exist"
        if receiver not in self.balances:
            return False, f"Receiver {receiver} does not exist"
        if self.balances[sender] < amount:
            return False, f"Insufficient balance: {sender} has {self.balances[sender]}, needs {amount}"
        self.balances[sender] -= amount
        self.balances[receiver] += amount
        return True, "Transfer successful"
    
    def execute_balance_check(self, client_id: str) -> int:
        """
        Execute a balance check (read-only operation)
        
        Args:
            client_id: Client ID to check balance for
            
        Returns:
            Current balance
        """
        return self.get_balance(client_id)
    
    def add_request_log_entry(
        self,
        sequence: int,
        view: int,
        digest: str,
        request: Dict,
        origin: Optional[str] = None,
        *,
        preserve_existing_view: bool = False,
    ) -> RequestLogEntry:
        """
        Add or update a request log entry
        
        Args:
            sequence: Sequence number
            view: View number
            digest: Request digest
            request: Request payload
            origin: Replica id that supplied the PRE-PREPARE
            
        Returns:
            RequestLogEntry object
        """
        if sequence not in self.log:
            self.log[sequence] = RequestLogEntry(
                sequence,
                view,
                digest,
                copy.deepcopy(request) if request is not None else {},
                preprepare_sender=origin or "",
            )
        else:
            entry = self.log[sequence]
            if not (
                preserve_existing_view
                and (
                    entry.status_prepared
                    or entry.status_committed
                    or entry.status_executed
                )
            ):
                entry.view = view
            entry.digest = digest
            entry.request = copy.deepcopy(request) if request is not None else {}
            if origin:
                entry.preprepare_sender = origin
        
        return self.log[sequence]

    def record_event(self, sequence: int, event: str):
        entry = self.log.get(sequence)
        if not entry:
            return
        entry.events.append(event)
    
    def get_request_log_entry(self, sequence: int) -> Optional[RequestLogEntry]:
        """Get request log entry for a sequence number"""
        return self.log.get(sequence)

    def find_sequence_by_client(self, client_id: str, timestamp: int) -> Optional[Tuple[int, RequestLogEntry]]:
        """
        Locate the sequence entry associated with a given client request.

        Args:
            client_id: Client identifier
            timestamp: Client request timestamp

        Returns:
            Tuple of (sequence, RequestLogEntry) if found, else None
        """
        for seq, entry in self.log.items():
            request = entry.request or {}
            if request.get("client_id") == client_id and request.get("timestamp") == timestamp:
                return seq, entry
        return None


    def remove_sequence(self, sequence: int) -> None:
        """
        Remove a request entry from the log (used when replacing forged sequences).
        """
        entry = self.log.pop(sequence, None)
        if entry and entry.status_executed:
            self.executed_sequences.discard(sequence)
            if sequence == self.last_executed_sequence:
                self.last_executed_sequence = max(self.executed_sequences) if self.executed_sequences else 0
    
    def mark_preprepared(self, sequence: int):
        """Mark request as pre-prepared"""
        if sequence in self.log:
            self.log[sequence].status_pprepared = True
    
    def mark_prepared(
        self,
        sequence: int,
        node_id: str,
        signature: bytes,
        quorum_size: Optional[int] = None,
    ):
        """
        Mark request as prepared and collect signature
        
        Args:
            sequence: Sequence number
            node_id: Node that sent the prepare
            signature: Prepare message signature
            quorum_size: Optional quorum threshold to set prepared status
        """
        if sequence in self.log:
            entry = self.log[sequence]
            entry.prepare_signatures[node_id] = signature
            if quorum_size is not None and len(entry.prepare_signatures) >= quorum_size:
                entry.status_prepared = True
    
    def mark_committed(self, sequence: int, node_id: str, signature: bytes):
        """
        Mark request as committed and collect signature
        
        Args:
            sequence: Sequence number
            node_id: Node that sent the commit
            signature: Commit message signature
        """
        if sequence in self.log:
            entry = self.log[sequence]
            entry.status_committed = True
            entry.commit_signatures[node_id] = signature
    
    def mark_executed(self, sequence: int, result: Any):
        """
        Mark request as executed with result
        
        Args:
            sequence: Sequence number
            result: Execution result
        """
        if sequence in self.log:
            entry = self.log[sequence]
            entry.status_executed = True
            entry.execution_result = result
            self.executed_sequences.add(sequence)
            
            if sequence > self.last_executed_sequence:
                self.last_executed_sequence = sequence
    
    def get_request_status(self, sequence: int) -> str:
        """
        Get status string for a request (for PrintStatus)
        
        Returns:
            Status string: "PP", "P", "C", "E", or "X"
        """
        if sequence not in self.log:
            return STATUS_NONE
        
        entry = self.log[sequence]
        
        if entry.status_executed:
            return STATUS_EXECUTED
        elif entry.status_committed:
            return STATUS_COMMITTED
        elif entry.status_prepared:
            return STATUS_PREPARED
        elif entry.status_pprepared:
            return STATUS_PPREPARED
        else:
            return STATUS_NONE

    def get_highest_sequence(self) -> int:
        """Return the highest sequence number present in the log."""
        if not self.log:
            return 0
        return max(self.log.keys())

    def has_pending_requests(self) -> bool:
        """Return True if any logged request is not yet executed."""
        return any(not entry.status_executed for entry in self.log.values())
    
    def is_prepared(self, sequence: int, quorum_size: int) -> bool:
        """
        Check if request has enough prepare signatures (quorum reached)
        
        Args:
            sequence: Sequence number
            quorum_size: Required number of prepare signatures (n-f)
            
        Returns:
            True if quorum reached
        """
        if sequence not in self.log:
            return False
        
        entry = self.log[sequence]
        return len(entry.prepare_signatures) >= quorum_size
    
    def is_committed(self, sequence: int, quorum_size: int) -> bool:
        """
        Check if request has enough commit signatures (quorum reached)
        
        Args:
            sequence: Sequence number
            quorum_size: Required number of commit signatures (n-f)
            
        Returns:
            True if quorum reached
        """
        if sequence not in self.log:
            return False
        
        entry = self.log[sequence]
        return len(entry.commit_signatures) >= quorum_size
    
    def can_execute(self, sequence: int, quorum_size: int) -> bool:
        """
        Check if a request can be executed (committed-local condition)
        
        In Linear-PBFT, a request can be executed when:
        1. It has reached committed status (n-f commit signatures)
        2. All previous sequences have been executed (ordered execution)
        
        Args:
            sequence: Sequence number
            quorum_size: Required number of commit signatures (n-f)
            
        Returns:
            True if request can be executed
        """
        if not self.is_committed(sequence, quorum_size):
            return False
        
        if sequence in self.executed_sequences:
            return False
        
        for seq in range(self.last_executed_sequence + 1, sequence):
            if seq not in self.executed_sequences:
                return False
        
        return True
    
    def get_executable_sequences(self, quorum_size: int) -> List[int]:
        """
        Get list of sequence numbers that are ready to execute
        (committed and all previous sequences executed)
        
        Args:
            quorum_size: Required number of commit signatures (n-f)
            
        Returns:
            List of executable sequence numbers in order
        """
        executable = []
        
        start_seq = self.last_executed_sequence + 1
        
        for seq in sorted(self.log.keys()):
            if seq < start_seq:
                continue
            if self.can_execute(seq, quorum_size):
                executable.append(seq)
        
        return sorted(executable)
    
    def execute_next(self, quorum_size: int) -> Optional[Tuple[int, Any]]:
        """
        Execute the next executable request in sequence order
        
        Args:
            quorum_size: Required number of commit signatures (n-f)
            
        Returns:
            Tuple of (sequence, result) if executed, None otherwise
        """
        executable = self.get_executable_sequences(quorum_size)
        
        if not executable:
            return None
        
        sequence = executable[0]
        entry = self.log[sequence]
        request = entry.request
        
        if request.get("txn_type") == TXN_TRANSFER:
            sender = request.get("sender")
            receiver = request.get("receiver")
            amount = request.get("amount", 0)
            success, msg = self.execute_transfer(sender, receiver, amount)
            result = {"success": success, "message": msg}
        elif request.get("txn_type") == TXN_BALANCE:
            client_id = request.get("sender")
            balance = self.execute_balance_check(client_id)
            result = {"balance": balance}
        else:
            result = {"error": "Unknown transaction type"}
        
        self.mark_executed(sequence, result)
        
        return (sequence, result)
    
    def get_prepare_signatures(self, sequence: int) -> Dict[str, bytes]:
        """Get all prepare signatures for a sequence"""
        if sequence not in self.log:
            return {}
        return self.log[sequence].prepare_signatures.copy()
    
    def get_commit_signatures(self, sequence: int) -> Dict[str, bytes]:
        """Get all commit signatures for a sequence"""
        if sequence not in self.log:
            return {}
        return self.log[sequence].commit_signatures.copy()
    
    def clear_state(self):
        """Clear all state (for FLUSH operation)"""
        self.balances.clear()
        self.log.clear()
        self.executed_sequences.clear()
        self.last_executed_sequence = 0
        self._initialize_balances()
        self.low_water_mark = 0
        self.high_water_mark = self.low_water_mark + LOG_HIGH_WATER_DELTA
        self.stable_checkpoint_sequence = 0
        self.stable_checkpoint_digest = self.compute_state_digest()
        self.stable_checkpoint_signatures.clear()
        self.checkpoint_votes.clear()
    
    def get_all_balances(self) -> Dict[str, int]:
        """Get all client balances (for PrintDB)"""
        return self.balances.copy()
    
    def get_request_digest(self, sequence: int) -> Optional[str]:
        """Get digest for a request sequence"""
        if sequence not in self.log:
            return None
        return self.log[sequence].digest
    
    def get_request(self, sequence: int) -> Optional[Dict]:
        """Get request payload for a sequence"""
        if sequence not in self.log:
            return None
        return self.log[sequence].request.copy()

    def compute_state_digest(self) -> str:
        """Compute a deterministic digest of the replica state for checkpoints."""
        parts = [f"seq:{self.last_executed_sequence}"]
        for client_id in sorted(self.balances.keys()):
            parts.append(f"{client_id}:{self.balances[client_id]}")
        state_str = "|".join(parts)
        return hashlib.sha256(state_str.encode("utf-8")).hexdigest()

    def get_stable_checkpoint_proof(self) -> Optional[Dict[str, Any]]:
        """Return the stable checkpoint proof, if any."""
        if (
            self.stable_checkpoint_sequence == 0
            and not self.stable_checkpoint_signatures
        ):
            return None
        return {
            "sequence": self.stable_checkpoint_sequence,
            "state_digest": self.stable_checkpoint_digest,
            "signers": [
                {"node": node_id, "signature": signature.hex()}
                for node_id, signature in self.stable_checkpoint_signatures.items()
            ],
        }

    def record_checkpoint_vote(
        self,
        sequence: int,
        state_digest: str,
        node_id: str,
        signature: bytes,
        quorum: int = QUORUM_VIEWCHANGE,
    ) -> bool:
        """
        Record a checkpoint vote. Returns True if a stable checkpoint is formed.
        """
        if sequence <= self.stable_checkpoint_sequence:
            return False

        votes_for_sequence = self.checkpoint_votes[sequence]
        signatures = votes_for_sequence[state_digest]

        if node_id not in signatures:
            signatures[node_id] = signature

        if (
            sequence <= self.last_executed_sequence
            and len(signatures) >= quorum
        ):
            self._mark_stable_checkpoint(sequence, state_digest, signatures)
            return True
        return False

    def _mark_stable_checkpoint(
        self,
        sequence: int,
        state_digest: str,
        signatures: Dict[str, bytes],
    ):
        """
        Mark a checkpoint as stable, advance watermarks, and prune old log entries.
        """
        self.stable_checkpoint_sequence = sequence
        self.stable_checkpoint_digest = state_digest
        self.stable_checkpoint_signatures = dict(signatures)
        self.low_water_mark = sequence
        self.high_water_mark = self.low_water_mark + LOG_HIGH_WATER_DELTA
        self.prune_below(sequence)

        obsolete = [seq for seq in self.checkpoint_votes if seq <= sequence]
        for seq in obsolete:
            self.checkpoint_votes.pop(seq, None)

    def apply_stable_checkpoint(
        self,
        sequence: int,
        state_digest: str,
        signatures: Dict[str, bytes],
    ):
        """
        Forcefully install a stable checkpoint (used during view change adoption).
        """
        if sequence < self.stable_checkpoint_sequence:
            return
        self._mark_stable_checkpoint(sequence, state_digest, signatures)

    def prune_below(self, sequence: int):
        """
        Adjust watermarks after a stable checkpoint without discarding historical data.
        PBFT checkpoints are advisory for catch-up; we retain completed consensus entries
        so inspection commands can still report their status.
        """
        if self.executed_sequences:
            self.last_executed_sequence = max(self.executed_sequences)
        else:
            self.last_executed_sequence = sequence

    def is_within_watermarks(self, sequence: int) -> bool:
        """Return True if the sequence lies within the active watermarks."""
        return self.low_water_mark < sequence <= self.high_water_mark

    def should_emit_checkpoint(self, sequence: int) -> bool:
        """Determine whether a checkpoint should be emitted after executing sequence."""
        if sequence == 0:
            return False
        return sequence % CHECKPOINT_INTERVAL == 0

