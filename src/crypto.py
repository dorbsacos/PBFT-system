"""
Cryptography utilities for Linear-PBFT
Handles Ed25519 signatures and SHA-256 hashing
"""

import hashlib
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.backends import default_backend


class CryptoManager:
    """
    Manages cryptographic operations for a single node/client
    """
    
    def __init__(self, node_id: str, private_key: Ed25519PrivateKey):
        self.node_id = node_id
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    @staticmethod
    def generate_keypair(node_id: str) -> 'CryptoManager':
        """Generate a new Ed25519 key pair for a node/client"""
        private_key = Ed25519PrivateKey.generate()
        return CryptoManager(node_id, private_key)
    
    def sign(self, message_data: Dict[str, Any]) -> bytes:
        """
        Sign a message and return the signature as bytes
        
        Args:
            message_data: Dictionary containing message fields to sign
            
        Returns:
            Signature bytes
        """
        # Create a canonical representation of the message for signing
        message_str = self._create_canonical_message(message_data)
        message_bytes = message_str.encode('utf-8')
        
        # Sign the message
        signature = self.private_key.sign(message_bytes)
        return signature
    
    def verify_signature(self, message_data: Dict[str, Any], signature: bytes, public_key: Ed25519PublicKey) -> bool:
        """
        Verify a message signature
        
        Args:
            message_data: Dictionary containing message fields
            signature: Signature bytes to verify
            public_key: Public key of the signer
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Create the same canonical representation used for signing
            message_str = self._create_canonical_message(message_data)
            message_bytes = message_str.encode('utf-8')
            
            # Verify the signature
            public_key.verify(signature, message_bytes)
            return True
        except Exception:
            # Signature verification failed
            return False
    
    def _create_canonical_message(self, message_data: Dict[str, Any]) -> str:
        """
        Create a canonical string representation of a message for signing
        Orders fields consistently to ensure deterministic signatures
        
        Args:
            message_data: Dictionary containing message fields
            
        Returns:
            Canonical string representation
        """
        return self._canonicalize(message_data)

    def _canonicalize(self, value: Any) -> str:
        if isinstance(value, dict):
            parts = []
            for key in sorted(value.keys()):
                parts.append(f"{key}:{self._canonicalize(value[key])}")
            return "{" + "|".join(parts) + "}"
        if isinstance(value, list):
            items = [self._canonicalize(item) for item in value]
            return "[" + ",".join(items) + "]"
        if isinstance(value, bytes):
            return value.hex()
        return str(value)
    
    def compute_digest(self, data: str) -> str:
        """
        Compute SHA-256 digest of data
        
        Args:
            data: String data to hash
            
        Returns:
            Hexadecimal digest string
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def get_public_key_bytes(self) -> bytes:
        """
        Serialize public key to bytes for storage/transmission
        
        Returns:
            Public key as bytes
        """
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_public_key_from_bytes(self, key_bytes: bytes) -> Ed25519PublicKey:
        """
        Deserialize public key from bytes
        
        Args:
            key_bytes: Public key as bytes
            
        Returns:
            Ed25519PublicKey object
        """
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    
    def serialize_private_key(self) -> bytes:
        """
        Serialize private key to bytes for storage
        
        Returns:
            Private key as bytes
        """
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @staticmethod
    def load_private_key_from_bytes(key_bytes: bytes, node_id: str) -> 'CryptoManager':
        """
        Load a private key from bytes and create a CryptoManager
        
        Args:
            key_bytes: Private key as bytes
            node_id: ID of the node/client
            
        Returns:
            CryptoManager instance
        """
        private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        return CryptoManager(node_id, private_key)


class PublicKeyRegistry:
    """
    Registry for storing and retrieving public keys of all nodes/clients
    """
    
    def __init__(self):
        self.public_keys: Dict[str, Ed25519PublicKey] = {}
    
    def register_public_key(self, node_id: str, public_key: Ed25519PublicKey):
        """Register a public key for a node/client"""
        self.public_keys[node_id] = public_key
    
    def register_public_key_from_bytes(self, node_id: str, key_bytes: bytes):
        """Register a public key from bytes"""
        public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
        self.public_keys[node_id] = public_key
    
    def get_public_key(self, node_id: str) -> Ed25519PublicKey:
        """
        Get public key for a node/client
        
        Args:
            node_id: ID of the node/client
            
        Returns:
            Public key
            
        Raises:
            KeyError: If node_id not found
        """
        if node_id not in self.public_keys:
            raise KeyError(f"Public key not found for {node_id}")
        return self.public_keys[node_id]
    
    def verify_message(self, message_data: Dict[str, Any], signature: bytes, signer_id: str) -> bool:
        """
        Verify a message using the signer's registered public key
        
        Args:
            message_data: Dictionary containing message fields
            signature: Signature bytes
            signer_id: ID of the signer
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key = self.get_public_key(signer_id)
            # Create a temporary CryptoManager for verification
            # (We only need the verification logic, not the signing)
            dummy_private = Ed25519PrivateKey.generate()
            temp_crypto = CryptoManager(signer_id, dummy_private)
            return temp_crypto.verify_signature(message_data, signature, public_key)
        except (KeyError, Exception):
            return False


def generate_all_keypairs(node_ids: list, client_ids: list) -> Dict[str, Tuple[CryptoManager, bytes]]:
    """
    Generate keypairs for all nodes and clients
    
    Args:
        node_ids: List of node IDs
        client_ids: List of client IDs
        
    Returns:
        Dictionary mapping IDs to (CryptoManager instance, public_key_bytes)
    """
    keypairs = {}
    
    # Generate for nodes
    for node_id in node_ids:
        crypto = CryptoManager.generate_keypair(node_id)
        keypairs[node_id] = (crypto, crypto.get_public_key_bytes())
    
    # Generate for clients
    for client_id in client_ids:
        crypto = CryptoManager.generate_keypair(client_id)
        keypairs[client_id] = (crypto, crypto.get_public_key_bytes())
    
    return keypairs


def create_byzantine_signature_wrapper(original_crypto: CryptoManager, 
                                       should_fail: bool) -> bytes:
    """
    Create a signature wrapper for Byzantine fault injection
    Returns either a valid signature or a corrupted signature
    
    Args:
        original_crypto: CryptoManager instance
        should_fail: If True, return invalid signature
        
    Returns:
        Signature bytes (valid or corrupted)
    """
    if should_fail:
        # Return invalid signature (all zeros or random garbage)
        return b'\x00' * 64  # Ed25519 signatures are 64 bytes
    else:
        # Return valid empty signature for comparison
        # In practice, this wouldn't be used in normal operation
        return b''

