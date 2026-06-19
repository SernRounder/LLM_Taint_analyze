"""
src/local_db.py – In-memory (MongoDB-free) implementations of AnalysisDB and FlowDB.

These classes implement exactly the same public interface as ``src.db.AnalysisDB``
and ``src.flow_db.FlowDB``, but store all data in plain Python dicts/lists.  They
are used automatically when the pipeline is invoked with ``--binary-file`` and no
explicit ``--mongo-uri``, so no MongoDB installation is required.

Optional JSON persistence
--------------------------
Both classes accept an optional *output_json* path.  When supplied, calling
``save_json()`` writes all collected records to that file.  ``analyze.py``
calls this at the end of the pipeline when ``--output-json`` is provided.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_DEFAULT_FLOW_DB_PREFIX = 'taint_flow'


def _sanitize_name(name: str) -> str:
    """Mirror of flow_db._sanitize_name – keeps the two classes in sync."""
    sanitized = re.sub(r'[/\\. "$*<>:|?]', '_', name)
    return sanitized[:38] or 'unknown'


# ---------------------------------------------------------------------------
# LocalAnalysisDB
# ---------------------------------------------------------------------------

class LocalAnalysisDB:
    """In-memory drop-in replacement for :class:`src.db.AnalysisDB`.

    All data is held in a dictionary keyed by ``(uid, address)``.  The class
    mirrors every public method of ``AnalysisDB`` so that the rest of the
    pipeline can use either backend without modification.

    Parameters
    ----------
    output_json:
        Optional path.  When given, :meth:`save_json` writes all function
        records to this file.
    """

    def __init__(self, output_json: str | Path | None = None) -> None:
        # (uid, address) -> record dict
        self._store: dict[tuple[str, str], dict[str, Any]] = {}
        self._output_json = Path(output_json) if output_json else None

    # ------------------------------------------------------------------
    # Write helpers  (same signature as AnalysisDB)
    # ------------------------------------------------------------------

    def upsert_function(self, record: dict[str, Any]) -> None:
        key = (record['uid'], record['address'])
        existing = self._store.get(key, {})
        existing.update(record)
        self._store[key] = existing

    def upsert_functions(self, records: list[dict[str, Any]]) -> None:
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
        key = (uid, address)
        if key in self._store:
            self._store[key]['llm_result'] = llm_result
            self._store[key]['is_source'] = is_source
            self._store[key]['is_sink'] = is_sink

    # ------------------------------------------------------------------
    # Read helpers  (same signature as AnalysisDB)
    # ------------------------------------------------------------------

    def get_function(self, uid: str, address: str) -> dict[str, Any] | None:
        return dict(self._store.get((uid, address), {})) or None

    def get_all_functions(self, uid: str) -> list[dict[str, Any]]:
        return [dict(v) for (u, _), v in self._store.items() if u == uid]

    def get_unanalyzed_functions(self, uid: str) -> list[dict[str, Any]]:
        return [
            dict(v)
            for (u, _), v in self._store.items()
            if u == uid and v.get('llm_result') is None
        ]

    def count_functions(self, uid: str) -> int:
        return sum(1 for (u, _) in self._store if u == uid)

    def delete_uid(self, uid: str) -> int:
        keys = [(u, a) for (u, a) in self._store if u == uid]
        for k in keys:
            del self._store[k]
        return len(keys)

    # ------------------------------------------------------------------
    # Persistence helper
    # ------------------------------------------------------------------

    def save_json(self, path: str | Path | None = None) -> None:
        """Write all function records to *path* (or *output_json* if set)."""
        dest = Path(path) if path else self._output_json
        if dest is None:
            return
        records = list(self._store.values())
        dest.write_text(json.dumps(records, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# LocalFlowDB
# ---------------------------------------------------------------------------

class LocalFlowDB:
    """In-memory drop-in replacement for :class:`src.flow_db.FlowDB`.

    Parameters
    ----------
    uid:
        Binary identifier (mirrors the FlowDB constructor parameter).
    flow_db_prefix:
        Ignored for local storage; accepted for API compatibility.
    output_json:
        Optional path.  When given, :meth:`save_json` writes all path
        records to this file.
    """

    def __init__(
        self,
        uid: str,
        mongo_uri: str | None = None,  # accepted but ignored
        flow_db_prefix: str | None = None,  # accepted but ignored
        output_json: str | Path | None = None,
    ) -> None:
        self._uid = uid
        self._paths: list[dict[str, Any]] = []
        self._output_json = Path(output_json) if output_json else None

    # ------------------------------------------------------------------
    # Write helpers  (same signature as FlowDB)
    # ------------------------------------------------------------------

    def insert_path(self, path_record: dict[str, Any]) -> None:
        flow = path_record.get('taint_flow', [])
        # Deduplicate by taint_flow list
        for existing in self._paths:
            if existing.get('taint_flow') == flow:
                return
        self._paths.append(dict(path_record))

    def insert_paths(self, path_records: list[dict[str, Any]]) -> int:
        before = len(self._paths)
        for rec in path_records:
            self.insert_path(rec)
        return len(self._paths) - before

    def update_flow_llm_result(
        self,
        source_address: str,
        sink_address: str,
        taint_flow: list[str],
        flow_llm_result: str,
    ) -> None:
        for rec in self._paths:
            if (
                rec.get('uid') == self._uid
                and rec.get('source_address') == source_address
                and rec.get('sink_address') == sink_address
                and rec.get('taint_flow') == taint_flow
            ):
                rec['flow_llm_result'] = flow_llm_result
                return

    # ------------------------------------------------------------------
    # Read helpers  (same signature as FlowDB)
    # ------------------------------------------------------------------

    def get_all_paths(self) -> list[dict[str, Any]]:
        return [dict(p) for p in self._paths if p.get('uid') == self._uid]

    def get_paths_from_source(self, source_address: str) -> list[dict[str, Any]]:
        return [
            dict(p)
            for p in self._paths
            if p.get('uid') == self._uid and p.get('source_address') == source_address
        ]

    def get_paths_to_sink(self, sink_address: str) -> list[dict[str, Any]]:
        return [
            dict(p)
            for p in self._paths
            if p.get('uid') == self._uid and p.get('sink_address') == sink_address
        ]

    def count_paths(self) -> int:
        return sum(1 for p in self._paths if p.get('uid') == self._uid)

    def get_unanalyzed_paths(self) -> list[dict[str, Any]]:
        return [
            dict(p)
            for p in self._paths
            if p.get('uid') == self._uid and p.get('flow_llm_result') is None
        ]

    # ------------------------------------------------------------------
    # Persistence helper
    # ------------------------------------------------------------------

    def save_json(self, path: str | Path | None = None) -> None:
        """Write all path records to *path* (or *output_json* if set)."""
        dest = Path(path) if path else self._output_json
        if dest is None:
            return
        dest.write_text(json.dumps(self._paths, indent=2, ensure_ascii=False))
