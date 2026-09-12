# Prompt Firebreak

Prompt Firebreak is a GenLayer primitive for screening web evidence before an automated workflow consumes it. Validators independently fetch three distinct HTTPS sources, classify every source exactly once, bind risk to source indexes, preserve SHA-256 digests, and produce only a bounded safe extract for the declared objective and schema.

Lifecycle: `QUEUED → FINAL` for a safe packet, or `QUEUED → QUARANTINED → REPLACED → FINAL`. A quarantined packet can be replaced only by its owner with three entirely new origins during the stored window. If the owner disappears, anyone can close it after expiry.

```bash
genvm-lint contracts/contract.py
python -m pytest -q
```

URLs are caller-supplied evidence locations, not proof of independent ownership. Live smoke sources are labelled technical fixtures.
