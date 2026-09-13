"""
settlement.py
--------------
Python port of SettlementService.java.

Spring's @Transactional + JPA @Version becomes: a single global lock around
the debit/credit/ledger-write (playing the role of the DB transaction), plus
an explicit version bump on each Account (playing the role of optimistic
locking). For a single-process demo this is equivalent in spirit; in
production this maps onto a real DB transaction with `SELECT ... FOR UPDATE`
or an actual `@Version` column, same as the Java original.
"""

import threading

from .models import Account, AccountRepository, TransactionRepository


class InsufficientFundsError(Exception):
    pass


class UnknownAccountError(Exception):
    pass


class SettlementService:
    def __init__(self, accounts: AccountRepository, transactions: TransactionRepository):
        self._accounts = accounts
        self._transactions = transactions
        self._lock = threading.RLock()  # stands in for the DB transaction boundary

    def settle(self, sender_id: str, receiver_id: str, amount_paise: int, packet_hash: str):
        """
        Debit sender, credit receiver, write a ledger row — atomically.
        Raises UnknownAccountError / InsufficientFundsError on failure, in
        which case the caller (BridgeIngestionService) records a REJECTED
        transaction instead of SETTLED, exactly like the Java version's
        SettlementException handling.
        """
        with self._lock:
            sender: Account | None = self._accounts.get(sender_id)
            receiver: Account | None = self._accounts.get(receiver_id)

            if sender is None or receiver is None:
                tx = self._transactions.save(
                    sender_id, receiver_id, amount_paise, packet_hash,
                    status="REJECTED", reason="UNKNOWN_ACCOUNT",
                )
                raise UnknownAccountError(f"Unknown account: {sender_id if sender is None else receiver_id}")

            if sender.balance_paise < amount_paise:
                tx = self._transactions.save(
                    sender_id, receiver_id, amount_paise, packet_hash,
                    status="REJECTED", reason="INSUFFICIENT_FUNDS",
                )
                raise InsufficientFundsError(
                    f"{sender_id} has insufficient funds for {amount_paise} paise"
                )

            # The actual debit/credit — this whole block is the "transaction".
            sender.balance_paise -= amount_paise
            sender.version += 1
            receiver.balance_paise += amount_paise
            receiver.version += 1

            tx = self._transactions.save(
                sender_id, receiver_id, amount_paise, packet_hash,
                status="SETTLED",
            )
            return tx