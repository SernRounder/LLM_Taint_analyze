"""
src/db.py – MongoDB operations for storing/retrieving taint-analysis results.

Collection schema (one document per function):
{
    "uid":             str,   # FACT UID of the parent binary
    "function_name":   str,   # symbol name as reported by Ghidra
    "address":         str,   # hex address string, e.g. "0x00401000"
    "decompiled_code": str,   # pseudo-C produced by Ghidra's decompiler
    "callees":         list[str],  # list of callee address strings
    "llm_result":      str | None, # raw LLM JSON response (or None)
    "is_source":       bool,  # True if LLM identified this as a taint source
    "is_sink":         bool,  # True if LLM identified this as a taint sink
}

A compound unique index on (uid, address) prevents duplicate entries.
"""

from __future__ import annotations

import os
from typing import Any

_DEFAULT_MONGO_URI = 'mongodb://localhost:27017'
_DEFAULT_DB_NAME = 'external_llm_analyze'
_ANALYSIS_COLLECTION = 'function_analysis'
_MONGO_TIMEOUT_MS = 10_000


def _get_mongo_uri(override: str | None = None) -> str:
    return override or os.environ.get('EXTERNAL_LLM_PRIMARY_MONGO_URI', _DEFAULT_MONGO_URI)


def _get_db_name(override: str | None = None) -> str:
    return override or os.environ.get('EXTERNAL_LLM_PRIMARY_DB_NAME', _DEFAULT_DB_NAME)


class AnalysisDB:
    """Thin wrapper around the MongoDB ``function_analysis`` collection."""

    def __init__(
        self,
        mongo_uri: str | None = None,
        db_name: str | None = None,
    ) -> None:
        try:
            import pymongo  # noqa: PLC0415
        except ImportError as exc:
            raise SystemExit(
                'pymongo is not installed.  Run: pip install pymongo'
            ) from exc

        uri = _get_mongo_uri(mongo_uri)
        name = _get_db_name(db_name)

        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=_MONGO_TIMEOUT_MS)
        client.admin.command('ping')  # fail fast on bad connection
        db = client[name]
        self._col = db[_ANALYSIS_COLLECTION]
        # Ensure uniqueness per (uid, address) pair
        self._col.create_index(
            [('uid', pymongo.ASCENDING), ('address', pymongo.ASCENDING)],
            unique=True,
        )

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def upsert_function(self, record: dict[str, Any]) -> None:
        """Insert or replace a function record.

        *record* must contain at least ``'uid'`` and ``'address'`` keys.
        """
        import pymongo  # noqa: PLC0415

        self._col.update_one(
            {'uid': record['uid'], 'address': record['address']},
            {'$set': record},
            upsert=True,
        )

    def upsert_functions(self, records: list[dict[str, Any]]) -> None:
        """Bulk-upsert a list of function records."""
        for rec in records:
            self.upsert_function(rec)

    def update_llm_result(
        self,
        uid: str,
        address: str,
        llm_result: str,
        is_source: bool,
        is_sink: bool,
    ) -> None:
        """Persist the LLM analysis for a single function."""
        self._col.update_one(
            {'uid': uid, 'address': address},
            {
                '$set': {
                    'llm_result': llm_result,
                    'is_source': is_source,
                    'is_sink': is_sink,
                }
            },
        )

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_function(self, uid: str, address: str) -> dict[str, Any] | None:
        """Return the record for *address* in binary *uid*, or ``None``."""
        return self._col.find_one({'uid': uid, 'address': address}, {'_id': 0})

    def get_all_functions(self, uid: str) -> list[dict[str, Any]]:
        """Return all function records for binary *uid*."""
        return list(self._col.find({'uid': uid}, {'_id': 0}))

    def get_unanalyzed_functions(self, uid: str) -> list[dict[str, Any]]:
        """Return function records for *uid* that have not yet been analyzed by the LLM."""
        return list(
            self._col.find(
                {'uid': uid, 'llm_result': None},
                {'_id': 0},
            )
        )

    def count_functions(self, uid: str) -> int:
        """Return the number of function records stored for *uid*."""
        return self._col.count_documents({'uid': uid})

    def delete_uid(self, uid: str) -> int:
        """Delete all records for *uid*.  Returns the number of deleted documents."""
        result = self._col.delete_many({'uid': uid})
        return result.deleted_count
