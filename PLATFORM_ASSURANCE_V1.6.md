# Continuous Platform Assurance

AI-DFIR is itself part of the evidence chain. If its collectors, identity,
storage, clocks or release trust are degraded, the analyst must know before
interpreting missing data.

## Run

Create a manifest pointing to current control evidence and run:

```bash
python platform_assurance_v16.py \
  --manifest /etc/ai-dfir/platform-assurance.json \
  --out /var/lib/ai-dfir/platform_assurance_v16.json
```

The result is:

```text
HEALTHY
DEGRADED
CRITICAL
```

The Workbench exposes the result separately from incident findings.

## Human interpretation

- `CRITICAL` means one or more controls that can materially affect evidence
  integrity/completeness are failed, stale or missing.
- `DEGRADED` means a high-value assurance control needs attention.
- `HEALTHY` means the modeled controls have current passing evidence. It is not
  a guarantee that no unknown deployment weakness exists.

Never transform `CRITICAL` platform state into an incident conclusion such as
"the action did not happen." Instead document which evidence propositions can
no longer be established.
