# Containment and Consequence Reconciliation

Preferred transaction:

```text
signed containment plan
-> independent approval
-> pre-containment preservation
-> evidence seal
-> containment control
-> post-containment preservation
-> consequence reconciliation
-> separate recovery approval
```

Containment should account for credentials, queued tasks, callbacks, child
agents, memory writes, browser sessions, target-system changes, and external
messages already produced.

Release from containment should require evidence that open consequences have
been reconciled and the approved state is restored.
