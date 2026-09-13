"""
demo_service.py
-----------------
Python port of DemoService.java — seeds demo accounts and plays the role of
"the sender's phone" building + encrypting a PaymentInstruction into a
MeshPacket.
"""

from .crypto_utils import HybridCryptoService
from .models import Account, AccountRepository, MeshPacket, PaymentInstruction, TransactionRepository

SEED_ACCOUNTS = [
    # (account_id, owner_name, starting_balance_in_rupees)
    ("alice", "Alice", 2000.00),
    ("bob", "Bob", 500.00),
    ("carol", "Carol", 1200.00),
    ("dave", "Dave", 0.00),
]


class DemoService:
    def __init__(self, accounts: AccountRepository, transactions: TransactionRepository, crypto: HybridCryptoService):
        self._accounts = accounts
        self._transactions = transactions
        self._crypto = crypto
        self.seed_accounts()

    def seed_accounts(self):
        self._accounts.reset_to_seed(SEED_ACCOUNTS)
        self._transactions.clear()

    def create_packet(self, sender_id: str, receiver_id: str, amount_rupees: float, pin: str, ttl: int = 5) -> MeshPacket:
        """
        Simulates the sender's offline phone:
          1. build a PaymentInstruction with a fresh nonce + timestamp
          2. encrypt it with the server's RSA public key (hybrid scheme)
          3. wrap it in a MeshPacket with the given TTL
        """
        instruction = PaymentInstruction.new(sender_id, receiver_id, amount_rupees, pin)
        ciphertext = self._crypto.encrypt(instruction.to_json_bytes())
        return MeshPacket.wrap(ciphertext, ttl=ttl)