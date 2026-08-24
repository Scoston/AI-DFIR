# Memory and Skill Supply-Chain Investigation

## Memory

Preserve writer identity, source hash, memory version, tenant namespace, TTL,
tombstones/deletion, vector ID, embedding model/version, reads and downstream
uses. A memory entry that existed yesterday may not be the version read today.

## Skills

Preserve approved and suspect skill manifests, publisher/source, commit/version,
all file hashes/Merkle root, scripts/hooks, declared capabilities, observed
capabilities, dependencies, network destinations, external instruction URLs,
install/update time, and signature/provenance.

External instructions can drift without the local skill package changing. Hash
and version remote dependencies used by the skill.
