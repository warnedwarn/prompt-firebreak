# Prompt Firebreak

Prompt Firebreak is a standalone GenLayer Intelligent Contract. It gives other contracts and applications a reusable boundary between public web evidence and instructions embedded inside that evidence.

The caller declares one narrow extraction objective, an expected output schema, and exactly three HTTPS sources on distinct origins. Validators independently refetch each response, hash the full response bytes, and classify every source index exactly once. Only a bounded safe extract survives the screen.

**StudioNet contract:** [`0x0A2c…c21A`](https://explorer-studio.genlayer.com/address/0x0A2cd11D0a59B844bC9993D62404ec02E292c21A)

This repository intentionally contains no frontend application. Reviewers can inspect the deployed source and reproduce the contract lifecycle directly through GenLayer Explorer or the included scripts.

## What consensus decides

The non-deterministic decision has a closed vocabulary:

- `SAFE` — all three sources are usable for the declared objective.
- `QUARANTINE` — one or more indexes carry prompt injection, exfiltration, or authority-spoof risk.
- `CONFLICT` — the records cannot support one consistent task extract.

The leader cannot merely return a label. Its result must partition indexes `0..2`, attach approved risk codes, and include the ordered response-body digests. Every validator refetches the same URLs, rejects a digest mismatch, and semantically verifies that the source attribution fits the exact objective and schema.

## Recovery is part of the protocol

```text
QUEUED ── safe ───────────────► FINAL / PASSED
   │
   └── risk or conflict ──────► QUARANTINED
                                  │
                     owner + time│+ three new origins
                                  ▼
                              REPLACED ── rescreen ──► FINAL / RECHECKED
                                  
QUARANTINED ── deadline elapsed ── anyone ──────────► FINAL / EXPIRED_UNREPLACED
```

Only the original owner may replace a quarantined packet, only before its stored deadline, and none of the replacement origins may appear in the original set. If the owner disappears, `close_expired` prevents permanent limbo.

## Deterministic edges

Before any LLM call, source URLs are parsed and normalized. The contract rejects non-HTTPS schemes, embedded credentials, fragments, invalid ports, decoded `.` or `..` path segments, and repeated origins. IDs are canonicalized once and duplicates fail.

After the LLM call, the contract enforces verdict shape, full index coverage, disjoint safe/risky sets, closed-set risk codes, and digest equality. A validator does not need to reproduce an unstable sentence verbatim; it checks whether the candidate meaning is supported by the same fetched evidence.

## Verification

```bash
genvm-lint contracts/contract.py
python -m pytest -q
python scripts/verify_deployment.py
```

The direct suite includes adversarial cases for forged digest order, inconsistent index attribution, duplicate IDs and origins, unauthorized replacement, expiry closure, and immediate safe finalization.

The public StudioNet smoke record is `FIXTURE-1789230833`. Both workflow transactions and the deployment reached `FINALIZED / SUCCESS`; the deployed source matches `contracts/contract.py`, the record owner matches the configured warnedwarn wallet, and the final scan contains three digests.

The smoke URLs are neutral technical fixtures. Caller-supplied URLs demonstrate source diversity for consensus; they do **not** prove that the caller owns independent publishers or controls independent authorities.
