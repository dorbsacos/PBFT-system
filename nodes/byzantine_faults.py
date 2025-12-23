"""
Byzantine fault injection helpers for Linear-PBFT
"""

from dataclasses import dataclass, field
from typing import Set, Optional, Dict

from src.message import Message
from src.constants import BYZANTINE_TIMING_DELAY, MSG_PREPREPARE
from src.crypto import CryptoManager


@dataclass
class ByzantineConfig:
    crash: bool = False
    invalid_signature: bool = False
    dark_targets: Set[str] = field(default_factory=set)
    delay_ms: Optional[int] = None
    equivocation_targets: Set[str] = field(default_factory=set)


class ByzantineFaultController:
    """
    Determines whether to drop, delay, or alter messages based on configured attacks.
    Each replica can hold its own controller instance configured per test set.
    """

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.config = ByzantineConfig()
        self.crypto: Optional[CryptoManager] = None
        self.equivocation_offsets: Dict[int, int] = {}

    def configure_from_attack(self, attack_config) -> None:
        """Configure based on AttackConfig from orchestrator."""
        if isinstance(attack_config, dict):
            self.configure_from_dict(attack_config)
            return
        self.configure_from_dict({
            "sign": getattr(attack_config, "sign", False),
            "crash": getattr(attack_config, "crash", False),
            "time": getattr(attack_config, "time", False),
            "time_delay_ms": getattr(attack_config, "time_delay_ms", None),
            "dark_destinations": list(getattr(attack_config, "dark_destinations", [])),
            "equivocation_destinations": list(getattr(attack_config, "equivocation_destinations", [])),
        })

    def configure_from_dict(self, data: Optional[dict]):
        self.reset()
        if not data:
            return

        self.config.crash = bool(data.get("crash", False))
        self.config.invalid_signature = bool(data.get("sign", False))
        if data.get("time"):
            delay = data.get("time_delay_ms")
            self.config.delay_ms = delay if delay is not None else BYZANTINE_TIMING_DELAY
        self.config.dark_targets.update(data.get("dark_destinations", []))
        self.config.equivocation_targets.update(data.get("equivocation_destinations", []))

    def reset(self):
        self.config = ByzantineConfig()
        self.equivocation_offsets = {}

    def attach_crypto(self, crypto: CryptoManager):
        self.crypto = crypto

    def should_drop(self, destination_id: str) -> bool:
        if self.config.crash:
            return True
        if destination_id in self.config.dark_targets:
            return True
        return False

    def get_delay_ms(self) -> Optional[int]:
        return self.config.delay_ms

    def should_corrupt_signature(self) -> bool:
        return self.config.invalid_signature

    def should_equivocate(self, destination_id: str) -> bool:
        return destination_id in self.config.equivocation_targets

    def mutate_message(self, message: Message, destination_id: str) -> Message:
        """Apply message-level faults based on configuration."""
        if self.config.crash:
            return message
        if not self.should_equivocate(destination_id):
            return message
        if message.msg_type == MSG_PREPREPARE:
            payload = message.payload
            original_sequence = payload.get("sequence", 0)
            forged_sequence = self.equivocation_offsets.get(original_sequence)
            if forged_sequence is None:
                forged_sequence = original_sequence + 1
                self.equivocation_offsets[original_sequence] = forged_sequence
            payload["sequence"] = forged_sequence
            if self.crypto:
                message.sign(self.crypto)
        return message
