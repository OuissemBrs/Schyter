"""Partial orders over protocol events.

The search never builds a trace directly: it accumulates *causal* constraints
(intra-run program order plus send/recv message edges) and lets :meth:`Ordering.linearize`
produce a concrete, deterministic execution order.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable

__all__ = ["EDGE_KINDS", "EventKey", "Ordering"]

#: An event is addressed by ``(run_id, event_index_in_role)``.
EventKey = tuple[int, int]

EDGE_KINDS = ("order", "message")


class Ordering:
    """A DAG of event keys with incremental cycle rejection."""

    def __init__(self) -> None:
        self._index: dict[EventKey, int] = {}
        self._keys: list[EventKey] = []
        self._succ: list[set[int]] = []
        self._pred: list[set[int]] = []
        self._kinds: list[dict[int, str]] = []

    # -- construction ---------------------------------------------------
    def add_node(self, key: EventKey) -> None:
        """Register ``key`` as a node (idempotent)."""
        if key in self._index:
            return
        self._index[key] = len(self._keys)
        self._keys.append(key)
        self._succ.append(set())
        self._pred.append(set())
        self._kinds.append({})

    def add_edge(self, src: EventKey, dst: EventKey, kind: str = "order") -> bool:
        """Add ``src -> dst``; return ``False`` (and change nothing) on a cycle."""
        self.add_node(src)
        self.add_node(dst)
        i, j = self._index[src], self._index[dst]
        if i == j:
            return False
        if j in self._succ[i]:
            if kind == "message":
                self._kinds[i][j] = "message"
            return True
        if self._reaches(j, i):
            return False
        self._succ[i].add(j)
        self._pred[j].add(i)
        self._kinds[i][j] = kind
        return True

    def copy(self) -> Ordering:
        """Return an independent copy of this ordering."""
        clone = Ordering()
        for key in self._keys:
            clone.add_node(key)
        pairs = sorted(
            (source, target)
            for source in range(len(self._keys))
            for target in self._succ[source]
        )
        for source, target in pairs:
            clone.add_edge(
                self._keys[source], self._keys[target], self._kinds[source][target]
            )
        return clone

    def add_path(self, keys: Iterable[EventKey], kind: str = "order") -> bool:
        """Chain ``keys`` left to right.

        Returns ``False`` as soon as an edge would close a cycle; callers that
        need atomicity should work on a :meth:`copy`.
        """
        chain = list(keys)
        for key in chain:
            self.add_node(key)
        return all(self.add_edge(a, b, kind) for a, b in itertools.pairwise(chain))

    # -- queries --------------------------------------------------------
    def nodes(self) -> tuple[EventKey, ...]:
        """Return every node, in insertion order."""
        return tuple(self._keys)

    def has_edge(self, src: EventKey, dst: EventKey) -> bool:
        """True when the edge ``src -> dst`` is present."""
        i = self._index.get(src)
        j = self._index.get(dst)
        return i is not None and j is not None and j in self._succ[i]

    def successors(self, key: EventKey) -> tuple[EventKey, ...]:
        """Return the direct successors of ``key`` in deterministic order."""
        i = self._index.get(key)
        if i is None:
            return ()
        return tuple(sorted(self._keys[j] for j in self._succ[i]))

    def predecessors(self, key: EventKey) -> tuple[EventKey, ...]:
        """Return the direct predecessors of ``key`` in deterministic order."""
        i = self._index.get(key)
        if i is None:
            return ()
        return tuple(sorted(self._keys[j] for j in self._pred[i]))

    def edges(self) -> tuple[tuple[EventKey, EventKey, str], ...]:
        """Return every edge as ``(source, target, kind)``, deterministically ordered."""
        out = [
            (self._keys[i], self._keys[j], self._kinds[i][j])
            for i in range(len(self._keys))
            for j in sorted(self._succ[i], key=lambda x: self._keys[x])
        ]
        return tuple(out)

    def linearize(self) -> tuple[EventKey, ...]:
        """Return a deterministic topological order (smallest key first)."""
        indeg = {i: len(self._pred[i]) for i in range(len(self._keys))}
        ready = sorted(self._keys[i] for i in range(len(self._keys)) if indeg[i] == 0)
        out: list[EventKey] = []
        while ready:
            key = ready.pop(0)
            out.append(key)
            i = self._index[key]
            for j in sorted(self._succ[i]):
                indeg[j] -= 1
                if indeg[j] == 0:
                    ready.append(self._keys[j])
            ready.sort()
        if len(out) != len(self._keys):  # pragma: no cover - add_edge prevents cycles
            raise ValueError("ordering contains a cycle")
        return tuple(out)

    def _reaches(self, start: int, target: int) -> bool:
        """Depth-first reachability test used for incremental cycle rejection."""
        stack = [start]
        seen = {start}
        while stack:
            node = stack.pop()
            if node == target:
                return True
            for nxt in self._succ[node]:
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return False
