"""
models.py
---------
Domain layer. Python port of:
    model/Account.java, model/Transaction.java,
    model/PaymentInstruction.java, model/MeshPacket.java,
    service/VirtualDevice.java

We use plain dataclasses + a tiny in-memory "repository" pattern instead of
JPA/Hibernate, since this is a single-process demo (H2 in-memory in the
original maps naturally onto Python dicts guarded by locks).
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


# --------------------------------------------------------------------------
# Account
# --------------------------------------------------------------------------

@dataclass
class Account:
    """
    Mirrors Account.java. The `version` field plays the role of JPA's
    @Version optimistic-locking column: SettlementService bumps it on every
    write and can detect a lost update if it ever runs multi-process.
    """
    account_id: str
    owner_name: str
    balance_paise: int  # store money as integer paise/cents to avoid float error
    version: int = 0

    def balance_rupees(self) -> float:
        return self.balance_paise / 100.0


class AccountRepository:
    """In-memory stand-in for Spring Data JPA's AccountRepository."""

    def __init__(self):
        self._accounts: dict[str, Account] = {}
        self._lock = threading.RLock()

    def seed(self, account_id: str, owner_name: str, balance_rupees: float) -> Account:
        with self._lock:
            acc = Account(
                account_id=account_id,
                owner_name=owner_name,
                balance_paise=int(round(balance_rupees * 100)),
            )
            self._accounts[account_id] = acc
            return acc

    def get(self, account_id: str) -> Optional[Account]:
        with self._lock:
            return self._accounts.get(account_id)

    def all(self) -> list[Account]:
        with self._lock:
            return list(self._accounts.values())

    def reset_to_seed(self, seed_data: list[tuple[str, str, float]]):
        with self._lock:
            self._accounts.clear()
        for account_id, owner_name, balance in seed_data:
            self.seed(account_id, owner_name, balance)


# --------------------------------------------------------------------------
# Transaction (settled-tx ledger)
# --------------------------------------------------------------------------

@dataclass
class Transaction:
    """Mirrors Transaction.java. `packet_hash` carries the unique index that
    acts as a defense-in-depth backstop if the idempotency cache is ever
    bypassed (e.g. after a cache restart in production with Redis)."""
    id: int
    sender_id: str
    receiver_id: str
    amount_paise: int
    packet_hash: str
    status: str  # "SETTLED" or "REJECTED"
    settled_at: float = field(default_factory=time.time)
    reason: Optional[str] = None


class TransactionRepository:
    """In-memory stand-in for Spring Data JPA's TransactionRepository."""

    def __init__(self):
        self._transactions: list[Transaction] = []
        self._by_hash: set[str] = set()
        self._next_id = 1
        self._lock = threading.RLock()

    def save(self, sender_id, receiver_id, amount_paise, packet_hash, status, reason=None) -> Transaction:
        with self._lock:
            if packet_hash in self._by_hash:
                # Mirrors the DB unique-index rejection in the Java version.
                raise ValueError(f"packet_hash {packet_hash} already settled (unique index violation)")
            tx = Transaction(
                id=self._next_id,
                sender_id=sender_id,
                receiver_id=receiver_id,
                amount_paise=amount_paise,
                packet_hash=packet_hash,
                status=status,
                reason=reason,
            )
            self._next_id += 1
            self._transactions.append(tx)
            self._by_hash.add(packet_hash)
            return tx

    def last(self, n: int = 20) -> list[Transaction]:
        with self._lock:
            return list(reversed(self._transactions[-n:]))

    def clear(self):
        with self._lock:
            self._transactions.clear()
            self._by_hash.clear()
            self._next_id = 1


# --------------------------------------------------------------------------
# PaymentInstruction (the decrypted payload)
# --------------------------------------------------------------------------

@dataclass
class PaymentInstruction:
    """Mirrors PaymentInstruction.java — the cleartext payload that only
    the backend (holder of the RSA private key) can ever see."""
    sender_id: str
    receiver_id: str
    amount_paise: int
    pin_hash: str
    nonce: str
    signed_at_epoch_ms: int

    def to_json_bytes(self) -> bytes:
        import json
        return json.dumps({
            "senderId": self.sender_id,
            "receiverId": self.receiver_id,
            "amountPaise": self.amount_paise,
            "pinHash": self.pin_hash,
            "nonce": self.nonce,
            "signedAt": self.signed_at_epoch_ms,
        }).encode("utf-8")

    @staticmethod
    def from_json_bytes(data: bytes) -> "PaymentInstruction":
        import json
        obj = json.loads(data.decode("utf-8"))
        return PaymentInstruction(
            sender_id=obj["senderId"],
            receiver_id=obj["receiverId"],
            amount_paise=obj["amountPaise"],
            pin_hash=obj["pinHash"],
            nonce=obj["nonce"],
            signed_at_epoch_ms=obj["signedAt"],
        )

    @staticmethod
    def new(sender_id: str, receiver_id: str, amount_rupees: float, pin: str) -> "PaymentInstruction":
        import hashlib
        return PaymentInstruction(
            sender_id=sender_id,
            receiver_id=receiver_id,
            amount_paise=int(round(amount_rupees * 100)),
            pin_hash=hashlib.sha256(pin.encode("utf-8")).hexdigest(),
            nonce=str(uuid.uuid4()),
            signed_at_epoch_ms=int(time.time() * 1000),
        )


# --------------------------------------------------------------------------
# MeshPacket (wire format hopping across the mesh)
# --------------------------------------------------------------------------

@dataclass
class MeshPacket:
    """Mirrors MeshPacket.java. Only packet_id/ttl/created_at are readable
    by intermediaries; `ciphertext` (bytes, base64 on the wire) is opaque."""
    packet_id: str
    ttl: int
    created_at_epoch_ms: int
    ciphertext: bytes

    def to_wire_dict(self) -> dict:
        import base64
        return {
            "packetId": self.packet_id,
            "ttl": self.ttl,
            "createdAt": self.created_at_epoch_ms,
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }

    @staticmethod
    def from_wire_dict(d: dict) -> "MeshPacket":
        import base64
        return MeshPacket(
            packet_id=d["packetId"],
            ttl=int(d["ttl"]),
            created_at_epoch_ms=int(d["createdAt"]),
            ciphertext=base64.b64decode(d["ciphertext"]),
        )

    @staticmethod
    def wrap(ciphertext: bytes, ttl: int = 5) -> "MeshPacket":
        return MeshPacket(
            packet_id=str(uuid.uuid4()),
            ttl=ttl,
            created_at_epoch_ms=int(time.time() * 1000),
            ciphertext=ciphertext,
        )


# --------------------------------------------------------------------------
# VirtualDevice (one simulated phone in the mesh)
# --------------------------------------------------------------------------

@dataclass
class VirtualDevice:
    """Mirrors VirtualDevice.java — a simulated phone holding a set of
    packets it has heard via 'Bluetooth' gossip."""
    device_id: str
    has_internet: bool = False
    packets: dict[str, MeshPacket] = field(default_factory=dict)

    def receive(self, packet: MeshPacket) -> bool:
        """Store the packet if we don't already have it and TTL > 0.
        Returns True if newly stored (a 'hop' actually happened)."""
        if packet.ttl <= 0:
            return False
        if packet.packet_id in self.packets:
            return False
        self.packets[packet.packet_id] = packet
        return True

    def clear(self):
        self.packets.clear()