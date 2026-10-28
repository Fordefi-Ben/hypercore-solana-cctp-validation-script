"""Withdraw USDC from HyperCore to a Solana wallet via CCTP, signed by a Fordefi EVM vault.

Follows https://developers.circle.com/cctp/howtos/withdraw-usdc-from-hypercore-to-solana
with one change: Fordefi requires the EIP-712 domain chainId to match the request chain,
so we sign on hypercore_mainnet with signatureChainId 0x539 (1337) instead of Arbitrum 0xa4b1.
Hyperliquid accepts any signatureChainId for user-signed actions.

1. Derive the recipient USDC ATA for the Solana owner + createATA hook data.
2. Build the sendToEvmWithData action and its EIP-712 typed data.
3. Sign via Fordefi (evm_message / typed_message_type, api_signer); verify it recovers to the vault.
4. Only with --submit: POST to Hyperliquid mainnet /exchange.

Configuration (env vars):
  FORDEFI_API_TOKEN       Fordefi API user token (trader role)
  FORDEFI_PRIVATE_KEY     path to the API user's request-signing P-256 PEM key
  FORDEFI_VAULT_ID        EVM vault holding the HyperCore USDC balance
  SOLANA_ATA_OWNER        Solana wallet that owns the recipient USDC ATA (or --sol-owner)

Usage: python hypercore_to_solana_cctp.py [--amount 2] [--sol-owner <base58>] [--source-dex spot|perp] [--submit]
"""
import argparse, base64, datetime, hashlib, json, os, sys, time, urllib.error, urllib.request, uuid
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from eth_account import Account
from eth_account.messages import encode_typed_data

API_BASE = "https://api.fordefi.com"
TERMINAL = {"completed", "signed", "aborted", "error_signing", "failed", "stuck", "cancelled"}

USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"  # Solana mainnet USDC
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
HL_URL = "https://api.hyperliquid.xyz/exchange"
SIGNATURE_CHAIN_ID = 1337
SOLANA_DOMAIN = 5

# ---- Solana helpers (pure Python: base58 + PDA derivation) ----
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def b58encode(b):
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def on_ed25519_curve(pk):
    # Point decompression per RFC 8032 §5.1.3; a PDA must NOT be a valid curve point.
    p = 2**255 - 19
    d = (-121665 * pow(121666, p - 2, p)) % p
    y = int.from_bytes(pk, "little") & ((1 << 255) - 1)
    if y >= p:
        return False
    u, v = (y * y - 1) % p, (d * y * y + 1) % p
    x = (u * pow(v, 3, p) * pow(u * pow(v, 7, p), (p - 5) // 8, p)) % p
    return (v * x * x - u) % p == 0 or (v * x * x + u) % p == 0


def find_pda(seeds, program_id):
    for bump in range(255, -1, -1):
        h = hashlib.sha256(b"".join(seeds) + bytes([bump]) + program_id + b"ProgramDerivedAddress").digest()
        if not on_ed25519_curve(h):
            return h
    raise RuntimeError("no PDA found")


def associated_token_address(owner, mint):
    return b58encode(find_pda([b58decode(owner), b58decode(TOKEN_PROGRAM), b58decode(mint)], b58decode(ATA_PROGRAM)))


def create_ata_hook_data(owner):
    return "0x" + b"cctp-forward".hex().ljust(48, "0") + "01" + b58decode(owner).hex()


# ---- Fordefi API ----
def call(method, path, token, key=None, body=None):
    body_str = json.dumps(body, separators=(",", ":")) if body is not None else None
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if method == "POST":
        ts = str(int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
        sig = key.sign(f"{path}|{ts}|{body_str}".encode(), ec.ECDSA(hashes.SHA256()))
        headers.update({"x-signature": base64.b64encode(sig).decode(), "x-timestamp": ts,
                        "x-idempotence-id": str(uuid.uuid4())})
    req = urllib.request.Request(API_BASE + path, data=body_str.encode() if body_str else None,
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw}


# ---- Hyperliquid typed data ----
def typed_data(msg):
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "HyperliquidTransaction:SendToEvmWithData": [
                {"name": "hyperliquidChain", "type": "string"},
                {"name": "token", "type": "string"},
                {"name": "amount", "type": "string"},
                {"name": "sourceDex", "type": "string"},
                {"name": "destinationRecipient", "type": "string"},
                {"name": "addressEncoding", "type": "string"},
                {"name": "destinationChainId", "type": "uint32"},
                {"name": "gasLimit", "type": "uint64"},
                {"name": "data", "type": "bytes"},
                {"name": "nonce", "type": "uint64"},
            ],
        },
        "domain": {"name": "HyperliquidSignTransaction", "version": "1", "chainId": SIGNATURE_CHAIN_ID,
                   "verifyingContract": "0x0000000000000000000000000000000000000000"},
        "primaryType": "HyperliquidTransaction:SendToEvmWithData",
        "message": msg,
    }


def require_env(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"set {name}")
    return value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--amount", default="2", help="USDC amount as a decimal string")
    ap.add_argument("--sol-owner", default=os.environ.get("SOLANA_ATA_OWNER"),
                    help="Solana wallet that owns the recipient USDC ATA")
    ap.add_argument("--source-dex", default="spot", choices=["spot", "perp"])
    ap.add_argument("--gas-limit", type=int, default=200000)
    ap.add_argument("--submit", action="store_true", help="POST the signed action to Hyperliquid mainnet")
    args = ap.parse_args()
    if not args.sol_owner:
        sys.exit("set SOLANA_ATA_OWNER or pass --sol-owner")

    token = require_env("FORDEFI_API_TOKEN")
    vault_id = require_env("FORDEFI_VAULT_ID")
    key = serialization.load_pem_private_key(Path(require_env("FORDEFI_PRIVATE_KEY")).read_bytes(), password=None)

    out = Path.cwd() / "runs" / f"run_{int(time.time())}"
    out.mkdir(parents=True)

    ata = associated_token_address(args.sol_owner, USDC_MINT)
    nonce = int(time.time() * 1000)
    msg = {
        "hyperliquidChain": "Mainnet",
        "token": "USDC",
        "amount": args.amount,
        "sourceDex": "spot" if args.source_dex == "spot" else "",
        "destinationRecipient": ata,
        "addressEncoding": "base58",
        "destinationChainId": SOLANA_DOMAIN,
        "gasLimit": args.gas_limit,
        "data": create_ata_hook_data(args.sol_owner),
        "nonce": nonce,
    }
    action = {"type": "sendToEvmWithData", "signatureChainId": hex(SIGNATURE_CHAIN_ID), **msg}
    typed = typed_data(msg)
    (out / "typed_data.json").write_text(json.dumps({"action": action, "typed_data": typed}, indent=2))
    print(f"owner {args.sol_owner}\nrecipient ATA {ata}\nhook {msg['data']}\n"
          f"amount {args.amount} USDC from {args.source_dex}, nonce {nonce}")

    body = {
        "vault_id": vault_id, "signer_type": "api_signer", "type": "evm_message",
        "details": {"type": "typed_message_type", "chain": "hypercore_mainnet",
                    "raw_data": "0x" + json.dumps(typed, separators=(",", ":")).encode().hex()},
        "note": f"HyperCore -> Solana CCTP withdraw {args.amount} USDC",
    }
    status, tx = call("POST", "/api/v1/transactions", token, key, body)
    (out / "fordefi_create_response.json").write_text(json.dumps(tx, indent=2))
    print(f"Fordefi CREATE HTTP {status}")
    if status >= 300:
        print(json.dumps(tx, indent=2)); return
    print(f"tx {tx['id']} state {tx['state']} — approve in the Fordefi app if required", flush=True)
    deadline = time.time() + 900
    while tx.get("state") not in TERMINAL and time.time() < deadline:
        time.sleep(3)
        _, tx = call("GET", f"/api/v1/transactions/{tx['id']}", token)
    (out / "fordefi_final_transaction.json").write_text(json.dumps(tx, indent=2))
    print("Fordefi final state", tx.get("state"))
    if not tx.get("signatures"):
        print("no signature — stopping"); return

    sig = base64.b64decode(tx["signatures"][0]["data"])
    vault_addr = tx["vault"]["address"]
    recovered = Account.recover_message(encode_typed_data(full_message=typed), signature=sig)
    print(f"local recover {recovered} vault {vault_addr} -> {'MATCH' if recovered.lower() == vault_addr.lower() else 'MISMATCH'}")
    if recovered.lower() != vault_addr.lower():
        print("signature does not recover to vault — not submitting"); return

    payload = {"action": action, "nonce": nonce,
               "signature": {"r": "0x" + sig[:32].hex(), "s": "0x" + sig[32:64].hex(), "v": sig[64]}}
    (out / "hl_request.json").write_text(json.dumps(payload, indent=2))
    if not args.submit:
        print("dry run — pass --submit to POST to", HL_URL); return
    req = urllib.request.Request(HL_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            code, resp = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        code, resp = e.code, e.read().decode(errors="replace")
    (out / "hl_response.json").write_text(json.dumps({"http": code, "body": resp}, indent=2))
    print(f"HL POST {HL_URL} -> HTTP {code}\n{resp}")
    print("saved to", out)


if __name__ == "__main__":
    main()
