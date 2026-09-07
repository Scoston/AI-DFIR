"""Bounded SHA-256 history-tree inclusion and prefix-consistency proofs."""
from __future__ import annotations

import hashlib

MAX_LEAVES = 65536
MAX_LEAF_BYTES = 4096
MAX_PROOF_NODES = 17
EMPTY_ROOT = hashlib.sha256(b"").digest()


def _hash(value):
    return hashlib.sha256(value).digest()


def leaf_hash(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_LEAF_BYTES:
        raise ValueError("invalid or excessive Merkle leaf")
    return _hash(b"\x00" + raw)


def _node(left, right):
    return _hash(b"\x01" + left + right)


def _digests(values, limit):
    if (not isinstance(values, (list, tuple)) or len(values) > limit
            or not all(isinstance(value, bytes) and len(value) == 32 for value in values)):
        raise ValueError("invalid or excessive Merkle digests")
    return tuple(values)


def _size(value, *, empty=True):
    if type(value) is not int or not (0 if empty else 1) <= value <= MAX_LEAVES:
        raise ValueError("invalid Merkle tree size")
    return value


def _split(size):
    return 1 << ((size - 1).bit_length() - 1)


def _root(leaves):
    if not leaves: return EMPTY_ROOT
    if len(leaves) == 1: return leaves[0]
    cut = _split(len(leaves))
    return _node(_root(leaves[:cut]), _root(leaves[cut:]))


def root(leaves):
    return _root(_digests(leaves, MAX_LEAVES))


def inclusion_proof(leaves, index):
    leaves = _digests(leaves, MAX_LEAVES)
    if type(index) is not int or not 0 <= index < len(leaves):
        raise ValueError("invalid Merkle leaf index")
    def path(part, position):
        if len(part) == 1: return []
        cut = _split(len(part))
        if position < cut: return path(part[:cut], position) + [_root(part[cut:])]
        return path(part[cut:], position - cut) + [_root(part[:cut])]
    return path(leaves, index)


def verify_inclusion(leaf, index, size, path, expected_root):
    _size(size, empty=False); _digests([leaf, expected_root], 2)
    nodes = iter(_digests(path, MAX_PROOF_NODES))
    if type(index) is not int or not 0 <= index < size:
        raise ValueError("invalid Merkle leaf index")
    def reconstruct(position, count):
        if count == 1: return leaf
        cut = _split(count)
        if position < cut:
            branch = reconstruct(position, cut)
            return _node(branch, next(nodes))
        branch = reconstruct(position - cut, count - cut)
        return _node(next(nodes), branch)
    try:
        actual = reconstruct(index, size)
        return actual == expected_root and next(nodes, None) is None
    except StopIteration:
        return False


def consistency_proof(leaves, previous_size):
    leaves = _digests(leaves, MAX_LEAVES); _size(previous_size)
    if previous_size > len(leaves): raise ValueError("Merkle history cannot shrink")
    if previous_size in (0, len(leaves)): return []
    def path(part, count, known):
        if count == len(part): return [] if known else [_root(part)]
        cut = _split(len(part))
        if count <= cut: return path(part[:cut], count, known) + [_root(part[cut:])]
        return path(part[cut:], count - cut, False) + [_root(part[:cut])]
    return path(leaves, previous_size, True)


def verify_consistency(previous_size, size, previous_root, expected_root, path):
    _size(previous_size); _size(size); _digests([previous_root, expected_root], 2)
    proof = _digests(path, MAX_PROOF_NODES)
    if previous_size > size: return False
    if previous_size == 0: return not proof and previous_root == EMPTY_ROOT and (size > 0 or expected_root == EMPTY_ROOT)
    if previous_size == size: return not proof and previous_root == expected_root
    nodes = iter(proof)
    def reconstruct(old_count, count, known):
        if old_count == count:
            value = previous_root if known else next(nodes)
            return value, value
        cut = _split(count)
        if old_count <= cut:
            old, new = reconstruct(old_count, cut, known)
            return old, _node(new, next(nodes))
        old, new = reconstruct(old_count - cut, count - cut, False)
        left = next(nodes)
        return _node(left, old), _node(left, new)
    try:
        old, new = reconstruct(previous_size, size, True)
        return old == previous_root and new == expected_root and next(nodes, None) is None
    except StopIteration:
        return False
