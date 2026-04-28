"""
src/taint_flow.py – DFS-based taint-path search.

After LLM source/sink identification is complete, this module walks the
call-graph that was already stored in MongoDB (``function_analysis`` collection)
and finds every simple path from a **source** function to a **sink** function
using iterative depth-first search.

Only the call edges that were captured during Ghidra BFS decompilation are used,
so the search is strictly scoped to the previously decompiled sub-graph.

Path schema returned by ``find_taint_paths``
--------------------------------------------
Each path is a ``dict``:

    {
        "source_address":    str,          # address of the source function
        "sink_address":      str,          # address of the sink function
        "taint_flow":        list[str],    # ordered list of addresses, source → sink
        "functions":         list[dict],   # full function records for each hop
        "sink_decompiled":   str,          # decompiled code of the sink function
    }

The ``"functions"`` list preserves the per-function LLM results already stored
in MongoDB so the caller can include them in the path record without re-querying.
"""

from __future__ import annotations

from typing import Any


def find_taint_paths(
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return all simple source→sink paths in the call-graph.

    Parameters
    ----------
    functions:
        All function records for a single binary UID as returned by
        ``AnalysisDB.get_all_functions(uid)``.  Each record must have at
        least the keys ``address``, ``callees``, ``is_source``, ``is_sink``.

    Returns
    -------
    list[dict]
        One entry per discovered path (may be empty if no source→sink paths
        exist).  See module docstring for the schema.
    """
    # Build lookup maps from the flat list
    by_address: dict[str, dict[str, Any]] = {f['address']: f for f in functions}
    callees_map: dict[str, list[str]] = {
        f['address']: [c for c in f.get('callees', []) if c in by_address]
        for f in functions
    }
    sources = [f['address'] for f in functions if f.get('is_source')]
    sinks = set(f['address'] for f in functions if f.get('is_sink'))

    if not sources or not sinks:
        return []

    paths: list[dict[str, Any]] = []

    for src in sources:
        # Iterative DFS – each stack entry is the current path (list of addresses)
        stack: list[list[str]] = [[src]]
        while stack:
            path = stack.pop()
            current = path[-1]

            if current in sinks and len(path) > 1:
                # Record this path (source may also be a sink; skip trivial self-loops)
                sink_rec = by_address[current]
                paths.append({
                    'source_address': src,
                    'sink_address': current,
                    'taint_flow': list(path),
                    'functions': [by_address[addr] for addr in path],
                    'sink_decompiled': sink_rec.get('decompiled_code', ''),
                })
                # Do NOT continue from a sink – it terminates the flow.
                continue

            visited_set = set(path)
            for callee in callees_map.get(current, []):
                if callee not in visited_set:
                    stack.append(path + [callee])

    return paths
