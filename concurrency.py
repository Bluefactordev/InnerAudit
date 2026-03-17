"""
Controllo concorrenza per InnerAudit.

Limita il numero massimo di chiamate LLM simultanee durante gli audit,
evitando che un audit grosso saturi tutti i worker gunicorn dell'app.

Uso:
    from concurrency import AuditConcurrencyLimiter
    limiter = AuditConcurrencyLimiter.get_instance()

    with limiter.acquire():
        # chiamata LLM per un file
        result = llm.run_analysis(...)
"""

import threading
import time
import logging
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger("AuditConcurrency")

# Numero massimo di chiamate LLM simultanee per tutti gli audit attivi
MAX_CONCURRENT_LLM_CALLS = 8


class AuditConcurrencyLimiter:
    """
    Semaforo globale (process-wide) per limitare le chiamate LLM simultanee.
    Singleton thread-safe.
    """

    _instance: Optional["AuditConcurrencyLimiter"] = None
    _lock = threading.Lock()

    def __init__(self, max_slots: int = MAX_CONCURRENT_LLM_CALLS):
        self._semaphore = threading.Semaphore(max_slots)
        self._max_slots = max_slots
        self._active = 0
        self._total = 0
        self._counter_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "AuditConcurrencyLimiter":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(MAX_CONCURRENT_LLM_CALLS)
                    logger.info(
                        "AuditConcurrencyLimiter inizializzato: max %d slot LLM simultanei",
                        MAX_CONCURRENT_LLM_CALLS,
                    )
        return cls._instance

    @contextmanager
    def acquire(self, timeout: Optional[float] = None):
        """
        Context manager che acquisisce uno slot LLM.
        Blocca finché uno slot è disponibile (o fino a timeout se specificato).
        """
        acquired = self._semaphore.acquire(timeout=timeout) if timeout else True
        if not timeout:
            self._semaphore.acquire()

        if not acquired:
            raise TimeoutError(
                f"Nessuno slot LLM disponibile dopo {timeout}s "
                f"(max {self._max_slots} slot simultanei)"
            )

        with self._counter_lock:
            self._active += 1
            self._total += 1
            active_now = self._active

        logger.debug("Slot LLM acquisito: %d/%d attivi", active_now, self._max_slots)

        try:
            yield
        finally:
            self._semaphore.release()
            with self._counter_lock:
                self._active -= 1
                active_now = self._active
            logger.debug("Slot LLM rilasciato: %d/%d attivi", active_now, self._max_slots)

    @property
    def active_slots(self) -> int:
        with self._counter_lock:
            return self._active

    @property
    def available_slots(self) -> int:
        return self._max_slots - self.active_slots

    @property
    def max_slots(self) -> int:
        return self._max_slots

    def status(self) -> dict:
        with self._counter_lock:
            return {
                "active": self._active,
                "available": self._max_slots - self._active,
                "max": self._max_slots,
                "total_processed": self._total,
            }
