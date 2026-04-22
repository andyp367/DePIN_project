#!/usr/bin/env python3
"""
Wallet client for Proof-of-Uptime token system.

Features:
- Generate/load Ed25519 keypairs
- Save keys to disk
- Create signed transactions
- Query validator for account state (balance + next nonce)
- Submit signed transactions to validator over TCP
- CLI commands:
    init
    address
    balance
    send

Dependencies:
    pip install cryptography
"""

import argparse
import base64
import json
import os
import socket
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


# =========================
# Config
# =========================

DEFAULT_WALLET_DIR = "wallet_data"
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"


# =========================
# Utility Helpers
# =========================

def b64encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode_str(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def canonical_json(data: Dict[str, Any]) -> bytes:
    """
    Canonical JSON encoding for signing/verification.
    Use sorted keys and compact separators.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def recv_line(sock: socket.socket) -> str:
    """
    Read until newline. Assumes validator responses are newline-delimited JSON.
    """
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\n" in chunk:
            break

    if not chunks:
        raise ConnectionError("No response received from server")

    data = b"".join(chunks)
    line = data.split(b"\n", 1)[0]
    return line.decode("utf-8")


def send_json_tcp(host: str, port: int, message: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
    """
    Send one JSON message over TCP and expect one newline-delimited JSON response.
    """
    payload = json.dumps(message).encode("utf-8") + b"\n"

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        response_line = recv_line(sock)

    try:
        return json.loads(response_line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Server returned invalid JSON: {response_line}") from exc


# =========================
# Wallet Key Management
# =========================

@dataclass
class WalletKeys:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )

    @property
    def public_key_b64(self) -> str:
        return b64encode_bytes(self.public_key_bytes)


def generate_wallet() -> WalletKeys:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return WalletKeys(private_key=private_key, public_key=public_key)


def save_wallet(keys: WalletKeys, wallet_dir: str = DEFAULT_WALLET_DIR) -> None:
    os.makedirs(wallet_dir, exist_ok=True)

    priv_path = os.path.join(wallet_dir, PRIVATE_KEY_FILE)
    pub_path = os.path.join(wallet_dir, PUBLIC_KEY_FILE)

    private_pem = keys.private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    public_pem = keys.public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    with open(priv_path, "wb") as f:
        f.write(private_pem)

    with open(pub_path, "wb") as f:
        f.write(public_pem)


def load_wallet(wallet_dir: str = DEFAULT_WALLET_DIR) -> WalletKeys:
    priv_path = os.path.join(wallet_dir, PRIVATE_KEY_FILE)
    pub_path = os.path.join(wallet_dir, PUBLIC_KEY_FILE)

    if not os.path.exists(priv_path):
        raise FileNotFoundError(
            f"Private key not found at {priv_path}. Run `init` first."
        )
    if not os.path.exists(pub_path):
        raise FileNotFoundError(
            f"Public key not found at {pub_path}. Run `init` first."
        )

    with open(priv_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    with open(pub_path, "rb") as f:
        public_key = load_pem_public_key(f.read())

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Loaded private key is not an Ed25519 key")
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Loaded public key is not an Ed25519 key")

    return WalletKeys(private_key=private_key, public_key=public_key)


# =========================
# Transaction Logic
# =========================

def build_unsigned_transaction(
    nonce: int,
    sender_pub_b64: str,
    receiver_pub_b64: str,
    amount: int,
) -> Dict[str, Any]:
    if nonce < 0:
        raise ValueError("Nonce must be non-negative")
    if amount <= 0:
        raise ValueError("Amount must be a positive integer")
    if not sender_pub_b64:
        raise ValueError("sender_pub cannot be empty")
    if not receiver_pub_b64:
        raise ValueError("receiver_pub cannot be empty")

    return {
        "nonce": nonce,
        "sender_pub": sender_pub_b64,
        "receiver_pub": receiver_pub_b64,
        "amount": amount,
    }


def sign_transaction(keys: WalletKeys, unsigned_tx: Dict[str, Any]) -> str:
    message = canonical_json(unsigned_tx)
    signature = keys.private_key.sign(message)
    return b64encode_bytes(signature)


def build_signed_transaction(
    keys: WalletKeys,
    nonce: int,
    receiver_pub_b64: str,
    amount: int,
) -> Dict[str, Any]:
    unsigned_tx = build_unsigned_transaction(
        nonce=nonce,
        sender_pub_b64=keys.public_key_b64,
        receiver_pub_b64=receiver_pub_b64,
        amount=amount,
    )
    signature_b64 = sign_transaction(keys, unsigned_tx)
    signed_tx = dict(unsigned_tx)
    signed_tx["signature"] = signature_b64
    return signed_tx


def verify_transaction_signature(tx: Dict[str, Any]) -> bool:
    required_fields = {"nonce", "sender_pub", "receiver_pub", "amount", "signature"}
    if not required_fields.issubset(tx.keys()):
        return False

    unsigned_tx = {
        "nonce": tx["nonce"],
        "sender_pub": tx["sender_pub"],
        "receiver_pub": tx["receiver_pub"],
        "amount": tx["amount"],
    }

    try:
        pub_key_bytes = b64decode_str(tx["sender_pub"])
        sig_bytes = b64decode_str(tx["signature"])
        pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        pub_key.verify(sig_bytes, canonical_json(unsigned_tx))
        return True
    except Exception:
        return False


# =========================
# Validator Protocol
# =========================

def get_account_state(host: str, port: int, public_key_b64: str) -> Tuple[int, int]:
    """
    Expected request:
        {"type": "get_account_state", "public_key": "<base64-pubkey>"}

    Expected response:
        {
          "status": "ok",
          "balance": 123,
          "next_nonce": 4
        }

    If account does not exist yet, validator may return:
        {
          "status": "ok",
          "balance": 0,
          "next_nonce": 0
        }
    """
    request = {
        "type": "get_account_state",
        "public_key": public_key_b64,
    }

    response = send_json_tcp(host, port, request)

    if response.get("status") != "ok":
        raise ValueError(f"Validator error: {response}")

    balance = response.get("balance")
    next_nonce = response.get("next_nonce")

    if not isinstance(balance, int) or balance < 0:
        raise ValueError(f"Invalid balance in validator response: {response}")
    if not isinstance(next_nonce, int) or next_nonce < 0:
        raise ValueError(f"Invalid next_nonce in validator response: {response}")

    return balance, next_nonce


def submit_transaction(host: str, port: int, tx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Expected request:
        {
          "type": "submit_transaction",
          "transaction": { ... }
        }

    Example successful response:
        {
          "status": "accepted",
          "message": "Transaction added to mempool"
        }

    Example failure response:
        {
          "status": "rejected",
          "message": "Insufficient balance"
        }
    """
    request = {
        "type": "submit_transaction",
        "transaction": tx,
    }
    return send_json_tcp(host, port, request)


# =========================
# CLI Commands
# =========================

def cmd_init(args: argparse.Namespace) -> None:
    wallet_dir = args.wallet_dir

    if os.path.exists(os.path.join(wallet_dir, PRIVATE_KEY_FILE)) and not args.force:
        print(
            f"Wallet already exists in '{wallet_dir}'. "
            f"Use --force to overwrite.",
            file=sys.stderr
        )
        sys.exit(1)

    keys = generate_wallet()
    save_wallet(keys, wallet_dir)

    print("Wallet created successfully.")
    print(f"Wallet directory: {wallet_dir}")
    print(f"Public key (base64): {keys.public_key_b64}")


def cmd_address(args: argparse.Namespace) -> None:
    keys = load_wallet(args.wallet_dir)
    print(keys.public_key_b64)


def cmd_balance(args: argparse.Namespace) -> None:
    keys = load_wallet(args.wallet_dir)
    balance, next_nonce = get_account_state(args.host, args.port, keys.public_key_b64)

    print(f"Public key: {keys.public_key_b64}")
    print(f"Balance: {balance}")
    print(f"Next nonce: {next_nonce}")


def cmd_send(args: argparse.Namespace) -> None:
    keys = load_wallet(args.wallet_dir)

    receiver_pub = args.receiver_pub.strip()
    amount = args.amount

    # Query validator for current balance and next nonce
    balance, next_nonce = get_account_state(args.host, args.port, keys.public_key_b64)

    if amount <= 0:
        print("Amount must be positive.", file=sys.stderr)
        sys.exit(1)

    if balance < amount:
        print(
            f"Insufficient balance. Current balance={balance}, requested={amount}",
            file=sys.stderr
        )
        sys.exit(1)

    tx = build_signed_transaction(
        keys=keys,
        nonce=next_nonce,
        receiver_pub_b64=receiver_pub,
        amount=amount,
    )

    # Local self-check before sending
    if not verify_transaction_signature(tx):
        print("Local signature verification failed.", file=sys.stderr)
        sys.exit(1)

    print("Created signed transaction:")
    print(json.dumps(tx, indent=2))

    response = submit_transaction(args.host, args.port, tx)

    print("\nValidator response:")
    print(json.dumps(response, indent=2))


# =========================
# Argument Parser
# =========================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Wallet CLI for Proof-of-Uptime token system"
    )
    parser.add_argument(
        "--wallet-dir",
        default=DEFAULT_WALLET_DIR,
        help=f"Wallet directory (default: {DEFAULT_WALLET_DIR})"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Generate a new wallet keypair")
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing wallet files"
    )
    p_init.set_defaults(func=cmd_init)

    # address
    p_address = subparsers.add_parser("address", help="Show wallet public key")
    p_address.set_defaults(func=cmd_address)

    # balance
    p_balance = subparsers.add_parser(
        "balance",
        help="Query validator for balance and next nonce"
    )
    p_balance.add_argument("--host", required=True, help="Validator host")
    p_balance.add_argument("--port", required=True, type=int, help="Validator TCP port")
    p_balance.set_defaults(func=cmd_balance)

    # send
    p_send = subparsers.add_parser(
        "send",
        help="Create, sign, and submit a transaction"
    )
    p_send.add_argument("--host", required=True, help="Validator host")
    p_send.add_argument("--port", required=True, type=int, help="Validator TCP port")
    p_send.add_argument(
        "--receiver-pub",
        required=True,
        help="Receiver public key in base64"
    )
    p_send.add_argument(
        "--amount",
        required=True,
        type=int,
        help="Amount to send (integer smallest unit)"
    )
    p_send.set_defaults(func=cmd_send)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

    