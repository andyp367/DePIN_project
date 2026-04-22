#!/usr/bin/env python3

import argparse
import json
import os
import socket
import sys
from dataclasses import dataclass
from typing import Any, Dict

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

DEFAULT_WALLET_DIR = "wallet_data"
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"


def canonical_json_for_validator(data: Dict[str, Any]) -> bytes:
    """
    Must match validator exactly:
    json.dumps(payload_dict, sort_keys=True).encode('utf-8')
    """
    return json.dumps(data, sort_keys=True).encode("utf-8")


def recv_line(sock: socket.socket) -> str:
    """
    Read until newline from validator.
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
    return data.decode("utf-8").strip()


def send_json_tcp(host: str, port: int, message: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
    """
    Send one JSON object and read one JSON response.
    """
    payload = json.dumps(message).encode("utf-8")

    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)
        response_line = recv_line(sock)

    try:
        return json.loads(response_line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Server returned invalid JSON: {response_line}") from exc


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
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()


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
        raise FileNotFoundError(f"Private key not found at {priv_path}. Run `init` first.")
    if not os.path.exists(pub_path):
        raise FileNotFoundError(f"Public key not found at {pub_path}. Run `init` first.")

    with open(priv_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    with open(pub_path, "rb") as f:
        public_key = load_pem_public_key(f.read())

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Loaded private key is not an Ed25519 key")
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Loaded public key is not an Ed25519 key")

    return WalletKeys(private_key=private_key, public_key=public_key)


def build_unsigned_transaction(
    nonce: int,
    sender_pub_hex: str,
    receiver_pub_hex: str,
    amount: float,
) -> Dict[str, Any]:
    if nonce < 0:
        raise ValueError("Nonce must be non-negative")
    if amount <= 0:
        raise ValueError("Amount must be positive")
    if not sender_pub_hex:
        raise ValueError("sender_pub cannot be empty")
    if not receiver_pub_hex:
        raise ValueError("receiver_pub cannot be empty")

    return {
        "nonce": nonce,
        "sender_pub": sender_pub_hex,
        "receiver_pub": receiver_pub_hex,
        "amount": amount,
    }


def sign_transaction(keys: WalletKeys, unsigned_tx: Dict[str, Any]) -> str:
    message = canonical_json_for_validator(unsigned_tx)
    signature = keys.private_key.sign(message)
    return signature.hex()


def build_signed_transaction(
    keys: WalletKeys,
    nonce: int,
    receiver_pub_hex: str,
    amount: float,
) -> Dict[str, Any]:
    unsigned_tx = build_unsigned_transaction(
        nonce=nonce,
        sender_pub_hex=keys.public_key_hex,
        receiver_pub_hex=receiver_pub_hex,
        amount=amount,
    )
    signed_tx = dict(unsigned_tx)
    signed_tx["signature"] = sign_transaction(keys, unsigned_tx)
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
        pub_key_bytes = bytes.fromhex(tx["sender_pub"])
        sig_bytes = bytes.fromhex(tx["signature"])
        pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        pub_key.verify(sig_bytes, canonical_json_for_validator(unsigned_tx))
        return True
    except Exception:
        return False


def submit_transaction(host: str, port: int, tx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validator expects the raw transaction JSON directly.
    """
    return send_json_tcp(host, port, tx)


def cmd_init(args: argparse.Namespace) -> None:
    wallet_dir = args.wallet_dir

    if os.path.exists(os.path.join(wallet_dir, PRIVATE_KEY_FILE)) and not args.force:
        print(f"Wallet already exists in '{wallet_dir}'. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    keys = generate_wallet()
    save_wallet(keys, wallet_dir)

    print("Wallet created successfully.")
    print(f"Wallet directory: {wallet_dir}")
    print(f"Public key (hex): {keys.public_key_hex}")


def cmd_address(args: argparse.Namespace) -> None:
    keys = load_wallet(args.wallet_dir)
    print(keys.public_key_hex)


def cmd_balance(args: argparse.Namespace) -> None:
    print("This validator does not support balance lookup over TCP.")
    print("Ask the validator/dashboard owner for balances.")


def cmd_send(args: argparse.Namespace) -> None:
    keys = load_wallet(args.wallet_dir)

    receiver_pub = args.receiver_pub.strip()
    amount = args.amount
    nonce = args.nonce

    tx = build_signed_transaction(
        keys=keys,
        nonce=nonce,
        receiver_pub_hex=receiver_pub,
        amount=amount,
    )

    if not verify_transaction_signature(tx):
        print("Local signature verification failed.", file=sys.stderr)
        sys.exit(1)

    print("Created signed transaction:")
    print(json.dumps(tx, indent=2))

    response = submit_transaction(args.host, args.port, tx)

    print("\nValidator response:")
    print(json.dumps(response, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Wallet CLI for DePIN validator")
    parser.add_argument(
        "--wallet-dir",
        default=DEFAULT_WALLET_DIR,
        help=f"Wallet directory (default: {DEFAULT_WALLET_DIR})"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_init = subparsers.add_parser("init", help="Generate a new wallet keypair")
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing wallet files"
    )
    p_init.set_defaults(func=cmd_init)

    p_address = subparsers.add_parser("address", help="Show wallet public key")
    p_address.set_defaults(func=cmd_address)

    p_balance = subparsers.add_parser("balance", help="Balance lookup not supported by this validator")
    p_balance.set_defaults(func=cmd_balance)

    p_send = subparsers.add_parser("send", help="Create, sign, and submit a transaction")
    p_send.add_argument("--host", required=True, help="Validator host")
    p_send.add_argument("--port", required=True, type=int, help="Validator TCP port")
    p_send.add_argument("--receiver-pub", required=True, help="Receiver public key in hex")
    p_send.add_argument("--amount", required=True, type=float, help="Amount to send")
    p_send.add_argument("--nonce", required=True, type=int, help="Transaction nonce")
    p_send.set_defaults(func=cmd_send)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main() 
    
    
