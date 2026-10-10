"""Ordering (DAG) tests: cycle rejection, linearisation and copying."""

from __future__ import annotations

from conftest import SRC  # noqa: F401  (path bootstrap)
from protoverify.core.ordering import Ordering

A, B, C = (1, 0), (1, 1), (2, 0)


def test_empty_ordering() -> None:
    assert Ordering().linearize() == ()


def test_add_node_is_idempotent() -> None:
    order = Ordering()
    order.add_node(A)
    order.add_node(A)
    assert order.nodes() == (A,)


def test_add_edge_and_linearize() -> None:
    order = Ordering()
    assert order.add_edge(A, B)
    assert order.linearize() == (A, B)


def test_self_edge_is_rejected() -> None:
    assert not Ordering().add_edge(A, A)


def test_cycle_is_rejected() -> None:
    order = Ordering()
    order.add_edge(A, B)
    order.add_edge(B, C)
    assert not order.add_edge(C, A)


def test_transitive_cycle_is_rejected() -> None:
    order = Ordering()
    order.add_edge(A, B)
    order.add_edge(B, C)
    assert not order.add_edge(C, A, "message")


def test_rejected_edge_leaves_the_graph_unchanged() -> None:
    order = Ordering()
    order.add_edge(A, B)
    order.add_edge(B, C)
    order.add_edge(C, A)
    assert not order.has_edge(C, A)
    assert len(order.edges()) == 2


def test_add_path_chains_in_order() -> None:
    order = Ordering()
    assert order.add_path([A, B, C])
    assert order.linearize() == (A, B, C)


def test_add_path_rejects_a_cycle() -> None:
    order = Ordering()
    order.add_edge(C, A)
    assert not order.add_path([A, B, C])


def test_linearize_is_deterministic() -> None:
    order = Ordering()
    order.add_edge(A, C)
    order.add_node(B)
    assert order.linearize() == order.linearize() == (A, B, C)


def test_linearize_respects_constraints_over_key_order() -> None:
    order = Ordering()
    order.add_edge(C, A)
    order.add_edge(C, B)
    assert order.linearize() == (C, A, B)


def test_predecessors_and_successors() -> None:
    order = Ordering()
    order.add_edge(A, B)
    order.add_edge(A, C)
    assert order.predecessors(B) == (A,)
    assert order.successors(A) == (B, C)


def test_edges_carry_their_kind() -> None:
    order = Ordering()
    order.add_edge(A, B, "message")
    assert order.edges() == ((A, B, "message"),)


def test_message_kind_wins_over_order() -> None:
    order = Ordering()
    order.add_edge(A, B)
    order.add_edge(A, B, "message")
    assert order.edges() == ((A, B, "message"),)


def test_copy_is_independent() -> None:
    order = Ordering()
    order.add_edge(A, B)
    clone = order.copy()
    clone.add_edge(B, C)
    assert not order.has_edge(B, C)
    assert clone.has_edge(B, C)


def test_copy_preserves_kinds() -> None:
    order = Ordering()
    order.add_edge(A, B, "message")
    assert order.copy().edges() == ((A, B, "message"),)


def test_unknown_node_has_no_neighbours() -> None:
    order = Ordering()
    assert order.predecessors((9, 9)) == ()
    assert order.successors((9, 9)) == ()
    assert not order.has_edge(A, B)
