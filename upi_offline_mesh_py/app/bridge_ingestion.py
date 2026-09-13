"""
bridge_ingestion.py
--------------------
Python port of BridgeIngestionService.java — THE pipeline.

Order matters and mirrors the original exactly:
  1. hash ciphertext (SHA-256)
  2. try to atomically claim the hash (IdempotencyService)
  3. if claimed: decrypt (RSA-OAEP unwrap AES key, AES-GCM decrypt+verify)
  4. freshness check (signedAt within 24h)
  5. settle (debit/credit/ledger, in one "transaction")
"""

import time
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidTag

from .crypto_utils import HybridCryptoService
from .idempotency import IdempotencyService
from .models import MeshPacket, PaymentInstruction
from .settlement import SettlementService, InsufficientFundsError, UnknownAccountError

FRESHNESS_WINDOW_MS = 24 * 60 * 60 * 1000  # 24 hours


@dataclass
class IngestResult:
    outcome: str  # "SETTLED" | "DUPLICATE_DROPPED" | "INVALID"
    packet_hash: str
    reason: Optional[str] = None
    transaction_id: Optional[int] = None

    def to_dict(self):
        return {
            "outcome": self.outcome,
            "packetHash": self.packet_hash,
            "reason": self.reason,
            "transactionId": self.transaction_id,
        }


class BridgeIngestionService:
    def __init__(
        self,
        crypto: HybridCryptoService,
        idempotency: IdempotencyService,
        settlement: SettlementService,
    ):
        self._crypto = crypto
        self._idempotency = idempotency
        self._settlement = settlement

    def ingest(self, packet: MeshPacket) -> IngestResult:
        # [1] Hash the ciphertext before doing any real work.
        packet_hash = self._crypto.hash_ciphertext(packet.ciphertext)

        # [2] Atomic claim. This is the linchpin of the whole demo: if N
        # threads/bridges call ingest() with byte-identical ciphertext at
        # the exact same instant, exactly one gets True here.
        first_claimer = self._idempotency.claim(packet_hash)
        if not first_claimer:
            return IngestResult(outcome="DUPLICATE_DROPPED", packet_hash=packet_hash)

        # [3] Decrypt. Any tampering (bit-flip anywhere in the ciphertext)
        # makes the GCM tag fail to verify -> InvalidTag -> INVALID.
        try:
            plaintext = self._crypto.decrypt(packet.ciphertext)
            instruction = PaymentInstruction.from_json_bytes(plaintext)
        except (InvalidTag, ValueError, Exception) as exc:
            return IngestResult(
                outcome="INVALID",
                packet_hash=packet_hash,
                reason=f"DECRYPTION_FAILED: {exc}",
            )

        # [4] Freshness check — reject anything older than 24h. The
        # attacker can't forge a newer signedAt without breaking the tag,
        # since signedAt lives inside the authenticated plaintext.
        now_ms = int(time.time() * 1000)
        age_ms = now_ms - instruction.signed_at_epoch_ms
        if age_ms > FRESHNESS_WINDOW_MS or age_ms < -60_000:  # small clock-skew allowance
            return IngestResult(
                outcome="INVALID",
                packet_hash=packet_hash,
                reason="STALE_OR_FUTURE_SIGNATURE",
            )

        # [5] Settle: debit sender, credit receiver, write the ledger.
        try:
            tx = self._settlement.settle(
                instruction.sender_id,
                instruction.receiver_id,
                instruction.amount_paise,
                packet_hash,
            )
            return IngestResult(
                outcome="SETTLED",
                packet_hash=packet_hash,
                transaction_id=tx.id,
            )
        except (InsufficientFundsError, UnknownAccountError) as exc:
            return IngestResult(
                outcome="INVALID",
                packet_hash=packet_hash,
                reason=str(exc),
            )