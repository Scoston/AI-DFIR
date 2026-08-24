# Object Lock, Retention, and Legal Hold

Production deployments should use provider/hardware-enforced immutable storage.
The local immutable store is a reference/test implementation.

Create a signed legal hold:

```bash
python legal_hold_v15.py create   --case IR-001 --tenant ACME --reason "litigation" --actor counsel   --private-key hold-signing.pem --out hold.json
```

Enforce it against durable metadata and objects:

```bash
python legal_hold_apply_v15.py   --dsn "$AIDFIR_POSTGRES_DSN"   --hold hold.json   --hold-public-key hold-signing.pub.pem   --store-json /etc/ai-dfir/object-store.json   --out hold-enforcement.json
```

Release is a separately signed action; preserve both hold and release records.
