"""
test_idempotency_concurrency.py
---------------------------------
Python port of IdempotencyConcurrencyTest.java — the headline test.

Run with:  pytest tests/ -v
"""

import concurrent.futures
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography.exceptions import InvalidTag

from app.bridge_ingestion import BridgeIngestionService
from app.crypto_utils import HybridCryptoService, ServerKeyHolder
from app.demo_service import DemoService
from app.idempotency import IdempotencyService
from app.models import AccountRepository, MeshPacket, PaymentInstruction, TransactionRepository
from app.settlement import SettlementService


@pytest.fixture
def system():
    key_holder = ServerKeyHolder()
    crypto = HybridCryptoService(key_holder)
    accounts = AccountRepository()
    transactions = TransactionRepository()
    demo = DemoService(accounts, transactions, crypto)
    idempotency = IdempotencyService()
    settlement = SettlementService(accounts, transactions)
    ingestion = BridgeIngestionService(crypto, idempotency, settlement)
    return {
        "crypto": crypto,
        "accounts": accounts,
        "transactions": transactions,
        "demo": demo,
        "idempotency": idempotency,
        "settlement": settlement,
        "ingestion": ingestion,
    }


def test_encrypt_decrypt_round_trip(system):
    """encryptDecryptRoundTrip — sanity-check hybrid encryption is symmetric."""
    crypto = system["crypto"]
    instruction = PaymentInstruction.new("alice", "bob", 500.0, "1234")
    ciphertext = crypto.encrypt(instruction.to_json_bytes())
    plaintext = crypto.decrypt(ciphertext)
    round_tripped = PaymentInstruction.from_json_bytes(plaintext)

    assert round_tripped.sender_id == "alice"
    assert round_tripped.receiver_id == "bob"
    assert round_tripped.amount_paise == 50000
    assert round_tripped.nonce == instruction.nonce


def test_tampered_ciphertext_is_rejected(system):
    """tamperedCiphertextIsRejected — flip a byte, expect INVALID, not a crash or settlement."""
    demo = system["demo"]
    ingestion = system["ingestion"]

    packet = demo.create_packet("alice", "bob", 500.0, "1234")

    tampered_bytes = bytearray(packet.ciphertext)
    tampered_bytes[-1] ^= 0xFF  # flip the last byte (inside the GCM tag)
    import dataclasses
    tampered_packet = dataclasses.replace(packet, ciphertext=bytes(tampered_bytes))

    result = ingestion.ingest(tampered_packet)

    assert result.outcome == "INVALID"
    assert result.transaction_id is None


def test_single_packet_delivered_by_three_bridges_settles_exactly_once(system):
    """
    singlePacketDeliveredByThreeBridgesSettlesExactlyOnce — the headline test.
    Three threads, one packet, simultaneous delivery via ingest(). Assert
    exactly one SETTLED, two DUPLICATE_DROPPED, and the sender's balance
    changed by exactly the amount once.
    """
    demo = system["demo"]
    ingestion = system["ingestion"]
    accounts = system["accounts"]

    alice_before = accounts.get("alice").balance_paise
    packet = demo.create_packet("alice", "bob", 500.0, "1234")

    barrier = __import__("threading").Barrier(3)

    def deliver():
        barrier.wait()  # maximize the chance all three hit ingest() at once
        return ingestion.ingest(packet)

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(deliver) for _ in range(3)]
        results = [f.result() for f in futures]

    outcomes = [r.outcome for r in results]
    assert outcomes.count("SETTLED") == 1
    assert outcomes.count("DUPLICATE_DROPPED") == 2

    alice_after = accounts.get("alice").balance_paise
    assert alice_before - alice_after == 50000  # debited exactly once, ₹500 = 50000 paise


def test_stale_packet_is_rejected(system):
    """A packet signed more than 24h ago should be rejected as INVALID."""
    demo = system["demo"]
    ingestion = system["ingestion"]
    crypto = system["crypto"]

    instruction = PaymentInstruction.new("alice", "bob", 100.0, "1234")
    import dataclasses
    stale_instruction = dataclasses.replace(
        instruction, signed_at_epoch_ms=instruction.signed_at_epoch_ms - (25 * 60 * 60 * 1000)
    )
    ciphertext = crypto.encrypt(stale_instruction.to_json_bytes())
    packet = MeshPacket.wrap(ciphertext)

    result = ingestion.ingest(packet)
    assert result.outcome == "INVALID"
    assert result.reason == "STALE_OR_FUTURE_SIGNATURE"


def test_insufficient_funds_is_rejected(system):
    """Sending more than the sender has should reject, not silently overdraw."""
    demo = system["demo"]
    ingestion = system["ingestion"]

    packet = demo.create_packet("dave", "bob", 999999.0, "1234")  # dave starts at ₹0
    result = ingestion.ingest(packet)

    assert result.outcome == "INVALID"
    assert "insufficient funds" in (result.reason or "").lower()