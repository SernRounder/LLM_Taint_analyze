"""
src/flow_db.py – MongoDB operations for storing taint-flow path records.

Each binary gets its **own database** whose name is derived from the FACT UID
(MongoDB identifiers cannot contain certain characters, so the UID is sanitised).
Inside that database, a single collection – also named after the binary – holds
one document per taint-flow path.

Path document schema
--------------------
{
    "uid":               str,          # FACT UID of the binary
    "source_address":    str,          # address of the source function
    "sink_address":      str,          # address of the sink function
    "taint_flow":        list[str],    # ordered address list, source → sink
    "functions":         list[dict],   # per-function records (name, address,
                                       #   decompiled_code, llm_result, …)
    "sink_decompiled":   str,          # decompiled code of the sink function
    "flow_llm_result":   str | None,   # LLM summary of the whole path
}
"""

from __future__ import annotations

import os
import re
from typing import Any

_DEFAULT_MONGO_URI = 'mongodb://localhost:27017'
_DEFAULT_FLOW_DB_PREFIX = 'taint_flow'
_MONGO_TIMEOUT_MS = 10_000


def _get_mongo_uri(override: str | None = None) -> str:
    return override or os.environ.get('EXTERNAL_LLM_PRIMARY_MONGO_URI', _DEFAULT_MONGO_URI)


def _sanitize_name(name: str) -> str:
    """Convert *name* into a valid MongoDB database/collection identifier.

    MongoDB database names must not contain: ``/\\. "$*<>:|?``
    and must be non-empty.  We replace any prohibited characters with ``_``
    and truncate to 38 characters (well within the 64-byte limit).
    """
    sanitized = re.sub(r'[/\\. "$*<>:|?]', '_', name)
    return sanitized[:38] or 'unknown'


class FlowDB:
    """Stores and retrieves taint-flow path records for a single binary.

    Each call to the constructor opens (or creates) a MongoDB database whose
    name is ``<flow_db_prefix>_<sanitised_uid>``.  The collection inside that
    database is named after the sanitised UID as well.
    """

    def __init__(
        self,
        uid: str,
        mongo_uri: str | None = None,
        flow_db_prefix: str | None = None,
    ) -> None:
        try:
            import pymongo  # noqa: PLC0415
        except ImportError as exc:
            raise SystemExit(
                'pymongo is not installed.  Run: pip install pymongo'
            ) from exc

        uri = _get_mongo_uri(mongo_uri)
        prefix = flow_db_prefix or _DEFAULT_FLOW_DB_PREFIX
        safe_uid = _sanitize_name(uid)
        db_name = f'{prefix}_{safe_uid}'

        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=_MONGO_TIMEOUT_MS)
        client.admin.command('ping')
        db = client[db_name]
        self._col = db[safe_uid]
        self._uid = uid
        # Index to speed up lookups by source/sink pair
        self._col.create_index(
            [
                ('uid', pymongo.ASCENDING),
                ('source_address', pymongo.ASCENDING),
                ('sink_address', pymongo.ASCENDING),
            ],
        )

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def insert_path(self, path_record: dict[str, Any]) -> None:
        """Insert a single taint-flow path record.

        Duplicate paths (same uid + taint_flow list) are silently ignored.
        """
        import pymongo  # noqa: PLC0415

        try:
            self._col.insert_one(dict(path_record))
        except pymongo.errors.DuplicateKeyError:
            pass

    def insert_paths(self, path_records: list[dict[str, Any]]) -> int:
        """Insert multiple path records.  Returns the number actually inserted."""
        inserted = 0
        for rec in path_records:
            try:
                self.insert_path(rec)
                inserted += 1
            except Exception:  # noqa: BLE001
                pass
        return inserted

    def update_flow_llm_result(
        self,
        source_address: str,
        sink_address: str,
        taint_flow: list[str],
        flow_llm_result: str,
    ) -> None:
        """Store the LLM summary for the path identified by *taint_flow*."""
        self._col.update_one(
            {
                'uid': self._uid,
                'source_address': source_address,
                'sink_address': sink_address,
                'taint_flow': taint_flow,
            },
            {'$set': {'flow_llm_result': flow_llm_result}},
        )

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def get_all_paths(self) -> list[dict[str, Any]]:
        """Return all path records for this binary."""
        return list(self._col.find({'uid': self._uid}, {'_id': 0}))

    def get_paths_from_source(self, source_address: str) -> list[dict[str, Any]]:
        """Return all paths that start at *source_address*."""
        return list(
            self._col.find(
                {'uid': self._uid, 'source_address': source_address},
                {'_id': 0},
            )
        )

    def get_paths_to_sink(self, sink_address: str) -> list[dict[str, Any]]:
        """Return all paths that end at *sink_address*."""
        return list(
            self._col.find(
                {'uid': self._uid, 'sink_address': sink_address},
                {'_id': 0},
            )
        )

    def count_paths(self) -> int:
        """Return the total number of stored paths for this binary."""
        return self._col.count_documents({'uid': self._uid})

    def get_unanalyzed_paths(self) -> list[dict[str, Any]]:
        """Return path records that do not yet have a flow LLM result."""
        return list(
            self._col.find(
                {'uid': self._uid, 'flow_llm_result': None},
                {'_id': 0},
            )
        )
