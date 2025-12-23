"""
Message definitions and serialization for Linear-PBFT
Handles message construction, serialization, and signature management
"""

import json
import struct
from typing import Dict, Any, Optional
from src.crypto import CryptoManager
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
    TXN_BALANCE,
    TXN_TRANSFER,
)


class Message:
    """
    Base message class for Linear-PBFT protocol messages
    """
    
    def __init__(self, msg_type: str, payload: Dict[str, Any], 
                 signer_id: str = "", signature: bytes = b""):
        self.msg_type = msg_type
        self.payload = payload
        self.signer_id = signer_id
        self.signature = signature
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for JSON serialization"""
        return {
            "type": self.msg_type,
            "payload": self.payload,
            "signer_id": self.signer_id,
            "signature": self.signature.hex() if isinstance(self.signature, bytes) else self.signature
        }
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes with length prefix"""
        json_str = json.dumps(self.to_dict(), sort_keys=True)
        json_bytes = json_str.encode('utf-8')
        
        length = struct.pack('>I', len(json_bytes))
        return length + json_bytes
    
    @staticmethod
    def from_bytes(data: bytes) -> 'Message':
        """Deserialize message from bytes with length prefix"""
        if len(data) < 4:
            raise ValueError("Message too short")
        
        length = struct.unpack('>I', data[:4])[0]
        
        if len(data) < 4 + length:
            raise ValueError(f"Message incomplete: expected {4 + length} bytes, got {len(data)}")
        
        json_bytes = data[4:4 + length]
        json_str = json_bytes.decode('utf-8')
        msg_dict = json.loads(json_str)
        
        signature_hex = msg_dict.get("signature", "")
        signature = bytes.fromhex(signature_hex) if signature_hex else b""
        
        return Message(
            msg_type=msg_dict["type"],
            payload=msg_dict["payload"],
            signer_id=msg_dict.get("signer_id", ""),
            signature=signature
        )
    
    def get_data_to_sign(self) -> Dict[str, Any]:
        """Get the data that should be signed (payload + type)"""
        return {
            "type": self.msg_type,
            "payload": self.payload
        }
    
    def sign(self, crypto: CryptoManager):
        """Sign this message using the provided CryptoManager"""
        data_to_sign = self.get_data_to_sign()
        self.signature = crypto.sign(data_to_sign)
        self.signer_id = crypto.node_id

def create_request(client_id: str, txn_type: str, sender: str = "", 
                   receiver: str = "", amount: int = 0, timestamp: int = 0) -> Message:
    """
    Create a REQUEST message
    
    Args:
        client_id: ID of the client making the request
        txn_type: TXN_BALANCE or TXN_TRANSFER
        sender: Sender client ID (for transfers)
        receiver: Receiver client ID (for transfers)
        amount: Transfer amount (for transfers)
        timestamp: Client timestamp
    """
    payload = {
        "client_id": client_id,
        "txn_type": txn_type,
        "timestamp": timestamp
    }
    
    if txn_type == TXN_TRANSFER:
        payload["sender"] = sender
        payload["receiver"] = receiver
        payload["amount"] = amount
    elif txn_type == TXN_BALANCE:
        payload["sender"] = sender
    
    return Message(MSG_REQUEST, payload)


def create_preprepare(primary_id: str, view: int, sequence: int, 
                      request_digest: str, request: Dict[str, Any]) -> Message:
    """
    Create a PREPREPARE message
    
    Args:
        primary_id: ID of the primary node
        view: Current view number
        sequence: Sequence number assigned to request
        request_digest: SHA-256 digest of the request
        request: Original REQUEST message payload
    """
    payload = {
        "view": view,
        "sequence": sequence,
        "digest": request_digest,
        "request": request
    }
    
    return Message(MSG_PREPREPARE, payload)


def create_prepare(replica_id: str, view: int, sequence: int, 
                   request_digest: str) -> Message:
    """
    Create a PREPARE message
    
    Args:
        replica_id: ID of the replica sending the prepare
        view: Current view number
        sequence: Sequence number
        request_digest: Request digest
    """
    payload = {
        "view": view,
        "sequence": sequence,
        "digest": request_digest
    }
    
    return Message(MSG_PREPARE, payload)


def create_commit(replica_id: str, view: int, sequence: int, 
                  request_digest: str) -> Message:
    """
    Create a COMMIT message
    
    Args:
        replica_id: ID of the replica sending the commit
        view: Current view number
        sequence: Sequence number
        request_digest: Request digest
    """
    payload = {
        "view": view,
        "sequence": sequence,
        "digest": request_digest
    }
    
    return Message(MSG_COMMIT, payload)


def create_reply(replica_id: str, client_id: str, view: int, 
                 timestamp: int, result: Any) -> Message:
    """
    Create a REPLY message
    
    Args:
        replica_id: ID of the replica sending the reply
        client_id: ID of the client to reply to
        view: Current view number
        timestamp: Client's original request timestamp
        result: Result of the transaction (balance amount or success/failure)
    """
    payload = {
        "client_id": client_id,
        "view": view,
        "timestamp": timestamp,
        "result": result
    }
    
    return Message(MSG_REPLY, payload)


def create_viewchange(replica_id: str, new_view: int, 
                     prepared_proofs: list, checkpoint_proof: Dict[str, Any] = None) -> Message:
    """
    Create a VIEWCHANGE message
    
    Args:
        replica_id: ID of the replica initiating view change
        new_view: New view number
        prepared_proofs: List of prepared request proofs (C, P sets)
        checkpoint_proof: Optional checkpoint proof
    """
    payload = {
        "new_view": new_view,
        "prepared_proofs": prepared_proofs
    }
    
    if checkpoint_proof:
        payload["checkpoint_proof"] = checkpoint_proof
    
    return Message(MSG_VIEWCHANGE, payload)


def create_newview(
    primary_id: str,
    new_view: int,
    view_changes: list,
    new_view_proofs: Dict[int, Dict[str, Any]],
    checkpoint_proof: Optional[Dict[str, Any]] = None,
) -> Message:
    """
    Create a NEWVIEW message
    
    Args:
        primary_id: ID of the new primary
        new_view: New view number
        view_changes: List of VIEWCHANGE messages (2f+1 signed)
        new_view_proofs: Dictionary mapping sequence to pre-prepare data (O set)
    """
    payload = {
        "new_view": new_view,
        "view_changes": view_changes,
        "new_view_proofs": new_view_proofs,
    }
    if checkpoint_proof:
        payload["checkpoint_proof"] = checkpoint_proof
    
    return Message(MSG_NEWVIEW, payload)


def create_flush() -> Message:
    """Create a FLUSH message to reset system state"""
    return Message(MSG_FLUSH, {})


def create_checkpoint(replica_id: str, sequence: int, state_digest: str) -> Message:
    """
    Create a CHECKPOINT message summarizing the replica state at a sequence.

    Args:
        replica_id: ID of the replica producing the checkpoint
        sequence: Sequence number (must be multiple of checkpoint interval)
        state_digest: Digest identifying the deterministic replica state
    """
    payload = {
        "sequence": sequence,
        "state_digest": state_digest,
    }
    return Message(MSG_CHECKPOINT, payload)


def compute_request_digest(request_payload: Dict[str, Any]) -> str:
    """
    Compute SHA-256 digest of a request for identification
    
    Args:
        request_payload: REQUEST message payload
        
    Returns:
        Hexadecimal digest string
    """
    parts = []
    for key in sorted(request_payload.keys()):
        value = request_payload[key]
        parts.append(f"{key}:{value}")
    
    request_str = "|".join(parts)
    
    import hashlib
    return hashlib.sha256(request_str.encode('utf-8')).hexdigest()


def validate_message_structure(msg: Message) -> bool:
    """
    Validate that a message has required fields based on its type
    
    Args:
        msg: Message to validate
        
    Returns:
        True if valid, False otherwise
    """
    if msg.msg_type == MSG_REQUEST:
        required = ["client_id", "txn_type", "timestamp"]
        if msg.payload.get("txn_type") == TXN_TRANSFER:
            required.extend(["sender", "receiver", "amount"])
        return all(key in msg.payload for key in required)
    
    elif msg.msg_type == MSG_PREPREPARE:
        required = ["view", "sequence", "digest", "request"]
        return all(key in msg.payload for key in required)
    
    elif msg.msg_type == MSG_PREPARE:
        required = ["view", "sequence", "digest"]
        return all(key in msg.payload for key in required)
    
    elif msg.msg_type == MSG_COMMIT:
        required = ["view", "sequence", "digest"]
        return all(key in msg.payload for key in required)
    
    elif msg.msg_type == MSG_REPLY:
        required = ["client_id", "view", "timestamp", "result"]
        return all(key in msg.payload for key in required)
    
    elif msg.msg_type == MSG_VIEWCHANGE:
        required = ["new_view", "prepared_proofs"]
        return all(key in msg.payload for key in required)
    
    elif msg.msg_type == MSG_NEWVIEW:
        required = ["new_view", "view_changes", "new_view_proofs"]
        if not all(key in msg.payload for key in required):
            return False
        checkpoint = msg.payload.get("checkpoint_proof")
        if checkpoint is not None:
            return "sequence" in checkpoint and "state_digest" in checkpoint and "signers" in checkpoint
        return True
    
    elif msg.msg_type == MSG_FLUSH:
        return True

    elif msg.msg_type == MSG_CHECKPOINT:
        required = ["sequence", "state_digest"]
        return all(key in msg.payload for key in required)
    
    return False


def extract_request_info(request_payload: Dict[str, Any]) -> tuple:
    """
    Extract readable information from a request payload
    
    Returns:
        Tuple of (client_id, txn_type, sender, receiver, amount)
    """
    client_id = request_payload.get("client_id", "")
    txn_type = request_payload.get("txn_type", "")
    sender = request_payload.get("sender", "")
    receiver = request_payload.get("receiver", "")
    amount = request_payload.get("amount", 0)
    
    return (client_id, txn_type, sender, receiver, amount)
