# Bitcoin Cash II (BCH2) Core v27.0.2 Release Notes

## ⚠️ REQUIRED ACTION — RESTART WITH `-reindex`

**All node operators and miners must upgrade to v27.0.2 and restart with `-reindex`.**

1. Stop your node: `bitcoincashII-cli stop`
2. Replace the binary with v27.0.2
3. Start with reindex: `bitcoincashIId -reindex`
4. Wait ~5 minutes for sync to complete

The reindex is required so the new checkpoints can validate existing chain data and, for
nodes that followed the reorg chain, switch back to the legitimate chain.

---

## Summary

This is a critical release that adds checkpoint protection against a deep chain
reorganization observed on 2026-04-11. All node operators and miners should upgrade
immediately.

---

## What Happened

On 2026-04-11 a 34-block deep reorganization was observed on the BCH2 network, forking
from block 58594. Nodes running v27.0.1 correctly rejected the reorg because
auto-finalization had already locked past the fork point:

```
BCH2: Rejecting reorg that would cross finalization at height 58612 (fork at 58594)
```

Nodes running v27.0.0 (whose finalization had not yet locked block 58594) accepted the
reorg and ended up on the wrong chain. The original chain — the one followed by v27.0.1
nodes — is the legitimate chain.

v27.0.2 hard-codes checkpoints for the original chain so that all nodes converge on the
correct history regardless of the state of their auto-finalization cache.

---

## Changes

### Chain parameter updates

- **`nMinimumChainWork`** bumped to the chainwork at block 58657:
  `0x00000000000000000000000000000000000000000000b97d29188116d332f173`
- **`defaultAssumeValid`** updated to the block 58657 hash:
  `0x0000000000000003821669141aaa9f95f7c5ad944bb532a67077f7ed8f2d84f2`

### New checkpoints

Five checkpoints have been added locking in the legitimate chain across and past the
fork point:

| Height | Hash |
|-------:|------|
| 58595  | `0x0000000000000001481cd824d3b6339488608b6c95b82edad70b89ad1387dacf` |
| 58600  | `0x00000000000000007c50e6678f05adeade78a23d3c4f6656041676f97dda595f` |
| 58620  | `0x0000000000000001d805e5767d36c65c7cd36255cd4e4f6a3028319fd46a5771` |
| 58640  | `0x000000000000000266dab048cc14df2c5dcd4a36b5a70882583c5cb2da79c6e3` |
| 58657  | `0x0000000000000003821669141aaa9f95f7c5ad944bb532a67077f7ed8f2d84f2` |

**Files changed:**
- `src/kernel/chainparams.cpp`
- `configure.ac`

---

## Who Needs To Do What

- **Nodes on v27.0.1** (on the original chain): upgrade to v27.0.2 and restart with
  `-reindex`. Your chain is already correct; the reindex lets the new checkpoints take
  effect.
- **Nodes on v27.0.0** (on the reorg chain): upgrade to v27.0.2 and restart with
  `-reindex`. Your node will switch back to the legitimate chain during reindex.
- **Mining pools**: upgrade immediately and restart with `-reindex`. Do not mine on top
  of the reorg chain.

---

## Notes

- No user funds are lost. Transactions that were included only on the reorg chain will
  need to be rebroadcast on the legitimate chain.
- This release does not change consensus rules beyond the added checkpoints.
- v27.0.2 is otherwise identical to v27.0.1.

---

## Compatibility

- Compatible with all existing chain data from the legitimate chain
- **Reindex is required** on upgrade so the new checkpoints can be applied
- Wire format is unchanged
- Configuration file name remains `bitcoincashII.conf`
