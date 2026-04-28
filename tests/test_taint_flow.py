"""
tests/test_taint_flow.py – unit tests for src/taint_flow.py

No MongoDB or Ghidra required; tests operate on pure in-memory data.
"""

from __future__ import annotations

import importlib
from typing import Any


def _find(functions):
    mod = importlib.import_module('src.taint_flow')
    return mod.find_taint_paths(functions)


def _func(address: str, callees: list[str], is_source=False, is_sink=False,
          name: str | None = None, code: str = '', llm_result: str = '') -> dict[str, Any]:
    return {
        'address': address,
        'function_name': name or address,
        'decompiled_code': code,
        'callees': callees,
        'is_source': is_source,
        'is_sink': is_sink,
        'llm_result': llm_result,
    }


# ---------------------------------------------------------------------------
# Basic reachability
# ---------------------------------------------------------------------------

class TestFindTaintPaths:
    def test_no_sources_returns_empty(self):
        funcs = [
            _func('A', ['B']),
            _func('B', [], is_sink=True),
        ]
        assert _find(funcs) == []

    def test_no_sinks_returns_empty(self):
        funcs = [
            _func('A', ['B'], is_source=True),
            _func('B', []),
        ]
        assert _find(funcs) == []

    def test_direct_source_to_sink(self):
        funcs = [
            _func('SRC', ['SINK'], is_source=True),
            _func('SINK', [], is_sink=True),
        ]
        paths = _find(funcs)
        assert len(paths) == 1
        p = paths[0]
        assert p['source_address'] == 'SRC'
        assert p['sink_address'] == 'SINK'
        assert p['taint_flow'] == ['SRC', 'SINK']

    def test_multi_hop_path(self):
        funcs = [
            _func('A', ['B'], is_source=True),
            _func('B', ['C']),
            _func('C', ['D']),
            _func('D', [], is_sink=True),
        ]
        paths = _find(funcs)
        assert len(paths) == 1
        assert paths[0]['taint_flow'] == ['A', 'B', 'C', 'D']

    def test_multiple_paths_to_same_sink(self):
        # A→B→D and A→C→D
        funcs = [
            _func('A', ['B', 'C'], is_source=True),
            _func('B', ['D']),
            _func('C', ['D']),
            _func('D', [], is_sink=True),
        ]
        paths = _find(funcs)
        flows = [p['taint_flow'] for p in paths]
        assert ['A', 'B', 'D'] in flows
        assert ['A', 'C', 'D'] in flows

    def test_multiple_sources(self):
        funcs = [
            _func('S1', ['SINK'], is_source=True),
            _func('S2', ['SINK'], is_source=True),
            _func('SINK', [], is_sink=True),
        ]
        paths = _find(funcs)
        assert len(paths) == 2
        sources = {p['source_address'] for p in paths}
        assert sources == {'S1', 'S2'}

    def test_multiple_sinks(self):
        funcs = [
            _func('SRC', ['K1', 'K2'], is_source=True),
            _func('K1', [], is_sink=True),
            _func('K2', [], is_sink=True),
        ]
        paths = _find(funcs)
        assert len(paths) == 2
        sinks = {p['sink_address'] for p in paths}
        assert sinks == {'K1', 'K2'}

    def test_no_cycle_infinite_loop(self):
        # Cycle: A→B→A (source at A, sink at C reachable via B)
        funcs = [
            _func('A', ['B', 'C'], is_source=True),
            _func('B', ['A']),
            _func('C', [], is_sink=True),
        ]
        paths = _find(funcs)
        # Only A→C path (A→B→A is a cycle, A→B→A→C would revisit A)
        assert any(p['taint_flow'] == ['A', 'C'] for p in paths)
        for p in paths:
            # No path should contain A twice
            assert p['taint_flow'].count('A') == 1

    def test_source_also_sink_not_trivial_self_path(self):
        # Node that is both source and sink should not produce a 1-element path
        funcs = [
            _func('X', ['Y'], is_source=True, is_sink=True),
            _func('Y', [], is_sink=True),
        ]
        paths = _find(funcs)
        # X→Y is valid; X alone (trivial) must not appear
        for p in paths:
            assert len(p['taint_flow']) >= 2

    def test_callees_outside_graph_ignored(self):
        # 'MISSING' address not in the functions list – should be silently dropped
        funcs = [
            _func('SRC', ['MISSING', 'SINK'], is_source=True),
            _func('SINK', [], is_sink=True),
        ]
        paths = _find(funcs)
        assert len(paths) == 1
        assert paths[0]['taint_flow'] == ['SRC', 'SINK']

    def test_sink_decompiled_included(self):
        funcs = [
            _func('SRC', ['SNK'], is_source=True),
            _func('SNK', [], is_sink=True, code='void sink() { system(buf); }'),
        ]
        paths = _find(funcs)
        assert paths[0]['sink_decompiled'] == 'void sink() { system(buf); }'

    def test_functions_list_in_path(self):
        funcs = [
            _func('A', ['B'], is_source=True, name='read_input'),
            _func('B', [], is_sink=True, name='exec_cmd'),
        ]
        paths = _find(funcs)
        addresses_in_funcs = [f['address'] for f in paths[0]['functions']]
        assert addresses_in_funcs == ['A', 'B']


# ---------------------------------------------------------------------------
# Isolated call edges (no path exists)
# ---------------------------------------------------------------------------

class TestNoPath:
    def test_source_and_sink_disconnected(self):
        funcs = [
            _func('SRC', [], is_source=True),
            _func('SNK', [], is_sink=True),
        ]
        assert _find(funcs) == []

    def test_sink_not_reachable_from_source(self):
        funcs = [
            _func('SRC', ['MID'], is_source=True),
            _func('MID', []),
            _func('SNK', [], is_sink=True),
        ]
        assert _find(funcs) == []
