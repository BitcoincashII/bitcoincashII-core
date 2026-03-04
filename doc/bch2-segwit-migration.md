# BCH2 SegWit Migration Guide

This document describes how to migrate SegWit UTXOs after the BCH2 fork and important limitations to be aware of.

## Overview

BCH2 disables SegWit after the fork activation. However, users who have coins in SegWit addresses (from the original Bitcoin chain) can still claim and spend those UTXOs using a special migration mechanism.

## Supported Address Types for Migration

| Address Type | Support Level | Notes |
|--------------|---------------|-------|
| P2WPKH (bc1q...) | **Full** | Native SegWit v0 key hash |
| P2WSH (bc1q...) | **Full** | Native SegWit v0 script hash |
| P2SH-P2WPKH (3...) | **Full** | Wrapped SegWit key hash |
| P2SH-P2WSH (3...) | **Full** | Wrapped SegWit script hash |
| P2TR Key-path (bc1p...) | **Full** | Taproot key-path spending |
| P2TR Script-path | **NOT SUPPORTED** | See warning below |

## IMPORTANT WARNING: Taproot Script-Path UTXOs

**Taproot script-path UTXOs (P2TR with scripts) are NOT supported for migration.**

If you have Taproot UTXOs that require script-path spending (e.g., multisig via Tapscript, timelocked scripts, etc.), you **MUST** move these coins to a supported address type **BEFORE** the BCH2 fork activates.

### How to identify Taproot script-path UTXOs

If your Taproot address was created with:
- Multiple spending conditions
- Multisig scripts
- Timelocks or other spending conditions
- Any address that requires revealing a script to spend

Then you likely have script-path UTXOs that need to be migrated before the fork.

### Migration steps for Taproot script-path

1. **Before the fork**, send your Taproot script-path UTXOs to:
   - A P2PKH (legacy) address (1...)
   - A P2WPKH address (bc1q...)
   - A P2TR key-path address (bc1p... with key-path spending only)

2. **After the fork**, you can claim the coins using the standard migration mechanism.

## How to Claim SegWit UTXOs After the Fork

### Step 1: Import your SegWit descriptor

Use `importdescriptors` to import your SegWit descriptor **without** setting it as active:

```bash
bitcoincashII-cli importdescriptors '[{
  "desc": "wpkh([fingerprint/84h/0h/0h]xpub.../0/*)#checksum",
  "timestamp": 0,
  "active": false,
  "range": [0, 1000]
}]'
```

**Important:** Do NOT set `"active": true` - SegWit descriptors cannot be activated after the fork.

### Step 2: Rescan the blockchain

The wallet will automatically rescan when you import with `timestamp: 0`. You can also manually rescan:

```bash
bitcoincashII-cli rescanblockchain
```

### Step 3: Verify your balance

```bash
bitcoincashII-cli getbalance
```

Your SegWit UTXOs should now be visible.

### Step 4: Spend to a legacy address

When you send a transaction, the wallet will automatically:
- Use `SIGHASH_FORKID` for replay protection
- Put the witness data in scriptSig instead of the witness field
- Send change to a legacy (P2PKH) address

```bash
bitcoincashII-cli sendtoaddress "1YourLegacyAddress..." 1.0
```

## Technical Details

### How the Migration Works

After the BCH2 fork, SegWit UTXOs are spent using a modified verification mechanism:

1. **Witness data in scriptSig**: Instead of putting signatures in the witness field, they are placed in the scriptSig.

2. **SIGHASH_FORKID required**: All signatures must use `SIGHASH_FORKID` (0x40) for replay protection.

3. **Same security model**: The cryptographic security is identical - the same signatures are required, just located in a different transaction field.

### Signature Version

The wallet uses `SigVersion::BCH_FORKID` when signing SegWit UTXOs after the fork. This ensures:
- Proper sighash computation (BIP143-style)
- Fork ID is included in the hash
- Replay protection against the original chain

## Troubleshooting

### "Witness/SegWit descriptors cannot be set as active after BCH2 fork"

This error occurs when trying to import a SegWit descriptor with `active: true`. Solution: Set `"active": false` in your import request.

### UTXOs not showing up

1. Ensure you're importing the correct descriptor for your address type
2. Use `timestamp: 0` to scan from genesis
3. Check that the range includes your used addresses

### Transaction fails with "SIGHASH_FORKID required"

This should not happen with the BCH2 wallet, which automatically uses FORKID. If you're using raw transactions, ensure you sign with `SIGHASH_ALL | SIGHASH_FORKID` (0x41).

## Fork Activation Heights

| Network | Fork Height | Notes |
|---------|-------------|-------|
| Mainnet | 53200 | Approximately June 2025 |
| Testnet | 0 | Active from genesis |
| Regtest | 200 | For testing |

## Support

For additional help with SegWit migration, please:
1. Check the [BCH2 GitHub Issues](https://github.com/bch2/bch2/issues)
2. Join the BCH2 community channels
