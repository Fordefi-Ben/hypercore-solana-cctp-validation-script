# HyperCore <> Solana CCTP validation script

Withdraws USDC from a HyperCore `spot` or `perp` balance to a Solana wallet via CCTP, following Circle's
[Withdraw USDC from HyperCore to Solana](https://developers.circle.com/cctp/howtos/withdraw-usdc-from-hypercore-to-solana)
guide, with the EIP-712 `sendToEvmWithData` action signed by a [Fordefi](https://www.fordefi.com) EVM vault
through the Fordefi API instead of a raw private key.

## What it does

1. Derives the recipient's Solana USDC associated token account (ATA) and the CCTP `createATA` hook data
   (pure Python: no Solana SDK needed).
2. Builds the `sendToEvmWithData` action (`destinationChainId: 5`, `addressEncoding: base58`).
3. Signs the typed data through Fordefi (`evm_message` / `typed_message_type` on `hypercore_mainnet`, API Signer)
   and checks that the signature recovers to the vault address.
4. With `--submit` only: POSTs the signed action to `https://api.hyperliquid.xyz/exchange`.

Without `--submit`, it signs the action and saves the request it would send, but never contacts Hyperliquid.

**Signature chain id:** Fordefi requires the EIP-712 domain `chainId` to match the chain the request is made on,
so this signs with `signatureChainId: 0x539` (1337, HyperCore) instead of the guide's Arbitrum `0xa4b1`.
Hyperliquid accepts any `signatureChainId` for user-signed actions.

## Setup

```bash
pip install eth-account cryptography
export FORDEFI_API_TOKEN=...        # Fordefi API user (trader role)
export FORDEFI_PRIVATE_KEY=./private.pem   # that API user's request-signing key
export FORDEFI_VAULT_ID=...         # EVM vault holding the HyperCore USDC
export SOLANA_ATA_OWNER=...         # Solana wallet that receives the USDC
```

A Fordefi API Signer must be running to sign API-user requests.

## Run

```bash
python hypercore_to_solana_cctp.py --amount 2            # sign only (dry run)
python hypercore_to_solana_cctp.py --amount 2 --submit   # sign and submit to Hyperliquid mainnet
```

Options: `--source-dex spot|perp` (default `spot`), `--gas-limit` (default 200000), `--sol-owner` (overrides `SOLANA_ATA_OWNER`).
Each run's requests and responses are written to `./runs/run_<timestamp>/`.

## Fees

Withdrawals to Solana pay a CCTP forwarding fee (higher than to EVM chains because it covers ATA creation).
If the amount is below the fee, the withdrawal reverts on HyperEVM. Check the current fee at
`https://iris-api.circle.com/v2/burn/USDC/fees/19/5?forward=true` (HyperEVM domain 19 → Solana domain 5).

## Status

As of October 2026, Fordefi's API returns HTTP 500 when creating this signing request if `destinationRecipient`
is a Solana (non-EVM) address. The same action with an EVM recipient signs normally. This script is the
reproduction case; rerun it once that's fixed.
