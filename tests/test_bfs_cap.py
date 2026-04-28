"""
tests/test_bfs_cap.py – unit tests for the BFS max_functions hard cap logic.

These tests exercise the pure-Python BFS stopping logic without touching
Ghidra or MongoDB.
"""

from __future__ import annotations

from collections import deque


# ---------------------------------------------------------------------------
# Pure-Python re-implementation of the BFS core (mirrors DecompileBFS.py)
# ---------------------------------------------------------------------------

def bfs_collect(
    graph: dict[str, list[str]],
    entry: str,
    max_depth: int,
    max_functions: int,
) -> dict[str, int]:
    """Return {address: depth} for all nodes visited by the capped BFS.

    *graph* maps address → list[callee_address].
    """
    visited: dict[str, int] = {}
    queue: deque[tuple[str, int]] = deque([(entry, 0)])

    while queue:
        addr, depth = queue.popleft()

        if addr in visited:
            continue

        if len(visited) >= max_functions:
            break

        visited[addr] = depth

        if depth < max_depth:
            for callee in graph.get(addr, []):
                if callee not in visited:
                    queue.append((callee, depth + 1))

    return visited


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBFSCap:
    """BFS respects max_functions hard cap."""

    def test_cap_zero_returns_empty(self):
        graph = {'A': ['B', 'C'], 'B': [], 'C': []}
        result = bfs_collect(graph, 'A', max_depth=5, max_functions=0)
        assert result == {}

    def test_cap_one_returns_only_entry(self):
        graph = {'A': ['B', 'C'], 'B': ['D'], 'C': ['D'], 'D': []}
        result = bfs_collect(graph, 'A', max_depth=5, max_functions=1)
        assert result == {'A': 0}

    def test_cap_limits_total_nodes(self):
        # Star graph: A → B0..B9 → C0..C9 (100 leaf nodes reachable)
        graph: dict[str, list[str]] = {'A': [f'B{i}' for i in range(10)]}
        for i in range(10):
            graph[f'B{i}'] = [f'C{i}{j}' for j in range(10)]
        for i in range(10):
            for j in range(10):
                graph[f'C{i}{j}'] = []

        result = bfs_collect(graph, 'A', max_depth=5, max_functions=15)
        assert len(result) == 15

    def test_depth_respected_without_cap(self):
        # Chain: A→B→C→D
        graph = {'A': ['B'], 'B': ['C'], 'C': ['D'], 'D': []}
        result = bfs_collect(graph, 'A', max_depth=2, max_functions=1000)
        # Only A(0), B(1), C(2) – D is at depth 3, beyond max_depth=2
        assert set(result.keys()) == {'A', 'B', 'C'}
        assert result['A'] == 0
        assert result['B'] == 1
        assert result['C'] == 2

    def test_depth_and_cap_combined(self):
        # Branching: A→B,C; B→D,E; C→F,G; depth=1 → should visit A,B,C only
        graph = {
            'A': ['B', 'C'],
            'B': ['D', 'E'],
            'C': ['F', 'G'],
            'D': [], 'E': [], 'F': [], 'G': [],
        }
        # cap=2 should give A and one of {B, C}
        result = bfs_collect(graph, 'A', max_depth=5, max_functions=2)
        assert len(result) == 2
        assert 'A' in result

    def test_no_cycles(self):
        # Cycle: A→B→A
        graph = {'A': ['B'], 'B': ['A']}
        result = bfs_collect(graph, 'A', max_depth=10, max_functions=1000)
        # Should visit A and B exactly once
        assert set(result.keys()) == {'A', 'B'}

    def test_large_binary_default_cap(self):
        """Simulate a binary with 10 000 functions; default cap of 500 applies."""
        # Linear chain of 10 000 nodes
        n = 10_000
        graph = {str(i): [str(i + 1)] for i in range(n - 1)}
        graph[str(n - 1)] = []
        result = bfs_collect(graph, '0', max_depth=n, max_functions=500)
        assert len(result) == 500
        # BFS visits in order, so nodes 0..499 are collected
        assert all(str(i) in result for i in range(500))


class TestBFSDepthOnly:
    """BFS depth limiting without a cap."""

    def test_single_node(self):
        graph: dict[str, list[str]] = {'A': []}
        result = bfs_collect(graph, 'A', max_depth=0, max_functions=1000)
        assert result == {'A': 0}

    def test_depth_zero_returns_only_entry(self):
        graph = {'A': ['B', 'C'], 'B': [], 'C': []}
        result = bfs_collect(graph, 'A', max_depth=0, max_functions=1000)
        assert result == {'A': 0}

    def test_depth_one(self):
        graph = {'A': ['B', 'C'], 'B': ['D'], 'C': ['D'], 'D': []}
        result = bfs_collect(graph, 'A', max_depth=1, max_functions=1000)
        assert set(result.keys()) == {'A', 'B', 'C'}
