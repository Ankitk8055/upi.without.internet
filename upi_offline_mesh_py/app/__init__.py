"""
app/__init__.py
-----------------
Flask application factory. Python port of UpiMeshApplication.java +
AppConfig.java — this is where all the services get instantiated and
wired together (the equivalent of Spring's dependency injection, done
explicitly since we don't have a DI container).
"""

import atexit
import threading

from flask import Flask

from .bridge_ingestion import BridgeIngestionService
from .crypto_utils import HybridCryptoService, ServerKeyHolder
from .demo_service import DemoService
from .idempotency import IdempotencyService
from .mesh_simulator import MeshSimulatorService
from .models import AccountRepository, TransactionRepository
from .settlement import SettlementService


class ServiceRegistry:
    """A plain object holding every singleton service, attached to the Flask
    app so route handlers can reach them via `current_app.services`."""

    def __init__(self):
        self.key_holder = ServerKeyHolder()
        self.crypto = HybridCryptoService(self.key_holder)

        self.accounts = AccountRepository()
        self.transactions = TransactionRepository()

        self.idempotency = IdempotencyService()
        self.settlement = SettlementService(self.accounts, self.transactions)
        self.bridge_ingestion = BridgeIngestionService(self.crypto, self.idempotency, self.settlement)

        self.demo = DemoService(self.accounts, self.transactions, self.crypto)
        self.mesh = MeshSimulatorService()

    def full_reset(self):
        self.demo.seed_accounts()
        self.mesh.reset()
        self.idempotency.reset()


def _start_eviction_scheduler(services: ServiceRegistry, interval_seconds: int = 3600):
    """Mirrors AppConfig's @EnableScheduling cache-eviction job — a
    background thread that periodically clears expired idempotency
    entries. Runs as a daemon thread so it doesn't block process exit."""

    def _loop():
        while True:
            threading.Event().wait(interval_seconds)
            services.idempotency.evict_expired()

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


def create_app() -> Flask:
    app = Flask(__name__)
    app.services = ServiceRegistry()

    _start_eviction_scheduler(app.services)

    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    return app