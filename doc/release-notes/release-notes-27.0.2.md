# Bitcoin Cash II (BCH2) Core v27.0.2 Release Notes

## ⚠️ REQUIRED ACTION — UPGRADE AND RESYNC

**All node operators and miners must upgrade to v27.0.2.**

**Replacing the binary alone is NOT enough.** Your node must re-validate chain data
against the new checkpoints. There are two methods — if `-reindex` does not work
(common for nodes that were on the shadow chain), use the **delete and resync** method.

### Method 1: `-reindex` (works if your node was previously on the legit chain)

Restart once with `-reindex`. See platform-specific instructions below.

### Method 2: Delete and resync (recommended if `-reindex` did not fix your chain)

If after reindex your node is still on the wrong chain, delete the `blocks` and
`chainstate` folders from your data directory and restart normally. The node will
re-download the correct chain from peers automatically.

**Do NOT delete** your wallet files, configuration, or anything else — only `blocks`
and `chainstate`.

| Platform | Data directory |
|---|---|
| Linux | `~/.bitcoincashII/` or `~/.bch2/` |
| Windows | `%APPDATA%\Bitcoin Cash II\` or `%APPDATA%\BitcoinCashII\` |
| Docker | Wherever your volume is mounted |

---

### Upgrade Instructions

#### Linux (daemon / systemd)

```bash
bitcoincashII-cli stop
# Wait for the process to fully exit:
pgrep -x bitcoincashIId    # must print nothing before continuing
# Replace the binary with v27.0.2, then:
bitcoincashIId -reindex -daemon
```

Once synced, stop the node and restart normally without `-reindex`. The flag is one-shot.

#### Windows (Qt GUI)

Close the wallet (File → Exit). Press **Win+R**, paste the following exactly (quotes required), and press Enter:

```
"C:\Program Files\Bitcoin Cash II\bitcoincashII-qt.exe" -reindex
```

Wait for "Reindexing blocks…" to finish in the status bar. Then close and reopen
the wallet normally from the Start menu (no flag needed).

#### Linux (Qt GUI)

Close the wallet, then in a terminal:

```bash
bitcoincashII-qt -reindex
```

Once synced, close and reopen normally.

#### Docker

**Do NOT use `docker exec` to reindex.** Docker's restart policy will restart the
container with the original command (without `-reindex`), silently undoing your reindex.
This is the most common cause of failed upgrades.

**The correct way:** add `-reindex` to your container's startup command.

If using **docker-compose**, edit your `docker-compose.yml`:

```yaml
command: bitcoincashIId -reindex
```

Then:

```bash
docker-compose down
docker-compose up -d
docker logs -f <container>
```

Watch the log for `UpdateTip` climbing to the current chain tip. When synced, remove
`-reindex` from the yml and restart:

```bash
docker-compose down
docker-compose up -d
```

If using **plain docker run**, stop and remove the container, then run a new one with
`-reindex` added to the command. After sync, stop and rerun without `-reindex`.

---

### Verify You Are On The Correct Chain

After reindex, run this command (in the Qt debug console via Window → Console, or on
the command line):

```
bitcoincashII-cli getblockhash 58595
```

**Expected result:**

```
0000000000000001481cd824d3b6339488608b6c95b82edad70b89ad1387dacf
```

If you get **any other hash**, the reindex did not take effect. Common causes:

- The `-reindex` flag was not on the actual running process (check with
  `ps auxww | grep bitcoincashIId` on Linux, or Task Manager → Details on Windows)
- On Docker: the container restarted with the original command (see Docker section above)
- The binary is not actually v27.0.2 (verify with `bitcoincashIId -version`)

---

## Summary

This is a critical release that adds checkpoint protection following a chain split on
2026-04-11.

BCH2 v27.0.0 shipped with a CashToken deserialization bug: `OutputToken::Unserialize`
called `ReadCompactSize(s)` with the default 32 MiB buffer-safety range check enabled.
Any CashToken transaction with `amount > 33,554,432` caused the node to throw
`ReadCompactSize(): size too large` and reject the containing block entirely.

This bug is not present in Bitcoin Cash Node (BCHN), which uses
`CompactSizeFormatter<false /* no range check here */>` and has done so since at least
BCHN v27.0.0. The bug was introduced during BCH2's fork when the serialization code was
rewritten in a simplified form; the deliberate disabling of range checking that BCHN's
code documents in an inline comment was not carried over.

v27.0.1 fixed the bug on 2026-04-10 by calling `ReadCompactSize(s, false)`. When the
first CashToken transaction with an amount exceeding the threshold was mined into block
58595 on 2026-04-11 at 04:14 UTC, every v27.0.0 node on the network crashed out of
block validation and began mining an empty-block shadow chain from block 58594.

v27.0.2 adds hard-coded checkpoints so that no node — new or restored — can be drawn
onto the shadow chain, regardless of its finalization state when it first syncs.

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

## Notes

- No user funds are lost. Transactions that were included only on the shadow chain will
  need to be rebroadcast on the legitimate chain.
- This release does not change consensus rules beyond the added checkpoints.
- v27.0.2 is otherwise identical to v27.0.1.

---

## Compatibility

- Compatible with all existing chain data from the legitimate chain
- **Reindex is required** on upgrade so the new checkpoints can be applied
- Wire format is unchanged
- Configuration file name remains `bitcoincashII.conf`
