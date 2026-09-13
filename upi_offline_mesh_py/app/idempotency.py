"""
idempotency.py
---------------
Python port of IdempotencyService.java.

Java used ConcurrentHashMap.putIfAbsent, which is atomic even under heavy
concurrent access. Python's GIL makes a plain dict "mostly" safe for simple
operations, but we still use an explicit lock to make the atomicity
guarantee explicit and correct even without relying on CPython's GIL
implementation detail (and so this code stays correct under PyPy or if
threads are swapped for multiprocessing later).

In production this becomes Redis: `SET key NX EX 86400` — same semantics,
distributed across replicas instead of JVM-local / process-local memory.
"""

import threading
import time


class IdempotencyService:
    TTL_SECONDS = 24 * 60 * 60  # 24h, matches the freshness window

    def __init__(self):
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def claim(self, packet_hash: str) -> bool:
        """
        Atomically try to claim `packet_hash`.
        Returns True if this call is the first claimer (proceed to settle),
        False if someone already claimed it (drop as duplicate).
        """
        now = time.time()
        with self._lock:
            if packet_hash in self._seen:
                return False
            self._seen[packet_hash] = now
            return True

    def evict_expired(self):
        """Scheduled cleanup — mirrors AppConfig's @EnableScheduling eviction."""
        cutoff = time.time() - self.TTL_SECONDS
        with self._lock:
            expired = [h for h, t in self._seen.items() if t < cutoff]
            for h in expired:
                del self._seen[h]
        return len(expired)

    def reset(self):
        with self._lock:
            self._seen.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._seen)
            