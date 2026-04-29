#!/usr/bin/env python3


import argparse

import json


import os

import socket

import sys

from dataclasses import dataclass

from typing import Any, Dict
from typing import Any, Dict, Tuple

# Ed25519 is the signature system used for wallet keys and transaction signing
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Serialization tools are used to save/load wallet keys as PEM files
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


SENSOR_KEY_FILE = os.path.join("keys", "device_keys.json")


def canonical_json_for_validator(data: Dict[str, Any]) -> bytes:
    """
    Converts a dictionary into the exact JSON bytes that get signed.

    The wallet and validator must use the same JSON formatting when signing
    and verifying, otherwise signatures will fail.
    """
    return json.dumps(data, sort_keys=True).encode("utf-8")
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def recv_line(sock: socket.socket) -> str:
    """
    Reads a response from the validator until it receives a newline.
    The validator sends JSON responses ending with '\n'.
    """
    chunks = []
    while True:
        chunk = sock.recv(4096)

        # If no more data comes in, stop reading
        if not chunk:
            break

        chunks.append(chunk)

        # Stop when the validator's newline response is complete
        if b"\n" in chunk:
            break

    
    if not chunks:
        raise ConnectionError("No response received from server")

    # Combine all received byte chunks and convert them back into a string
    data = b"".join(chunks)
    return data.decode("utf-8").strip()


def send_json_tcp(host: str, port: int, message: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
    """
    Sends a JSON message to the validator over TCP and waits for a JSON response.
    """
   
    payload = json.dumps(message).encode("utf-8")

    # Opens a TCP connection to the validator
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(payload)

        # Reads validator response
        response_line = recv_line(sock)

    # Converts validator response from JSON string back into a Python dictionary
    try:
        return json.loads(response_line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Server returned invalid JSON: {response_line}") from exc


@dataclass
class WalletKeys:
    """
    Stores the wallet's private/public keypair.
    """
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    source: str = "pem"

    @property
    def public_key_bytes(self) -> bytes:
        """
        Returns the raw 32-byte Ed25519 public key.
        """
        return self.public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )

    @property
    def public_key_hex(self) -> str:
        """
        Returns the public key as a hex string.
        
        """
        return self.public_key_bytes.hex()


def generate_wallet() -> WalletKeys:
    """
    Creates a new Ed25519 private/public keypair for the wallet.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    
    return WalletKeys(private_key=private_key, public_key=public_key)
    return WalletKeys(private_key=private_key, public_key=public_key, source="generated")


def save_wallet(keys: WalletKeys, wallet_dir: str = DEFAULT_WALLET_DIR) -> None:
    """
    Saves wallet keys to disk in PEM format.
    """
    # Makes wallet_data folder if it does not already exist
    os.makedirs(wallet_dir, exist_ok=True)

    # Builds full paths for private/public key files
    priv_path = os.path.join(wallet_dir, PRIVATE_KEY_FILE)
    pub_path = os.path.join(wallet_dir, PUBLIC_KEY_FILE)

    # Converts private key into PEM bytes without encryption
    private_pem = keys.private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    # Converts public key into PEM bytes
    public_pem = keys.public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    # Writes private key file
    with open(priv_path, "wb") as f:
        f.write(private_pem)

    # Writes public key file
    with open(pub_path, "wb") as f:
        f.write(public_pem)


def load_wallet(wallet_dir: str = DEFAULT_WALLET_DIR) -> WalletKeys:
 def load_wallet_from_sensor_file(sensor_key_file: str = SENSOR_KEY_FILE) -> WalletKeys:
    """
    Loads the wallet keypair from keys/device_keys.json.
    """
    with open(sensor_key_file, "r", encoding="utf-8") as f:
        key_data = json.load(f)

    # Reads private/public key hex strings from the sensor key file
    private_hex = key_data["private_key"]
    public_hex = key_data["public_key"]

    # Rebuilds private key from raw private key bytes
    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))

    
    public_key = private_key.public_key()

    
    derived_public_hex = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw
    ).hex()

    
    if derived_public_hex != public_hex:
        raise ValueError(
            "Sensor key file is inconsistent: private_key does not match public_key"
        )

    return WalletKeys(private_key=private_key, public_key=public_key, source="sensor")


def load_wallet_from_pem(wallet_dir: str = DEFAULT_WALLET_DIR) -> WalletKeys:
    """
    Loads wallet keys from wallet_data/private_key.pem and wallet_data/public_key.pem.
    """
    priv_path = os.path.join(wallet_dir, PRIVATE_KEY_FILE)
    pub_path = os.path.join(wallet_dir, PUBLIC_KEY_FILE)

    # Makes sure private key file exists
    if not os.path.exists(priv_path):
        raise FileNotFoundError(f"Private key not found at {priv_path}. Run `init` first.")

    # Makes sure public key file exists
    if not os.path.exists(pub_path):
        raise FileNotFoundError(f"Public key not found at {pub_path}. Run `init` first.")

    # Loads private key from PEM file
    with open(priv_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    # Loads public key from PEM file
    with open(pub_path, "rb") as f:
        public_key = load_pem_public_key(f.read())

    # Confirms the private key is Ed25519
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Loaded private key is not an Ed25519 key")

    # Confirms the public key is Ed25519
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Loaded public key is not an Ed25519 key")

    return WalletKeys(private_key=private_key, public_key=public_key)
    return WalletKeys(private_key=private_key, public_key=public_key, source="pem")


def load_wallet(wallet_dir: str = DEFAULT_WALLET_DIR, use_sensor_keys: bool = True) -> WalletKeys:
    """
    Loads wallet keys.

    If use_sensor_keys is True and keys/device_keys.json exists, it loads sensor keys.
    Otherwise, it falls back to wallet PEM files.
    """
    if use_sensor_keys and os.path.exists(SENSOR_KEY_FILE):
        return load_wallet_from_sensor_file(SENSOR_KEY_FILE)

    return load_wallet_from_pem(wallet_dir)


def build_unsigned_transaction(
    nonce: int,
    sender_pub_hex: str,
    receiver_pub_hex: str,
    amount: float,
) -> Dict[str, Any]:
    """
    Builds a transaction dictionary before the signature is added.
   
    """
    
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
    """
    Signs an unsigned transaction with the wallet private key.
    Returns the signature as a hex string.
    """
    message = canonical_json_for_validator(unsigned_tx)
    signature = keys.private_key.sign(message)
    return signature.hex()


def build_signed_transaction(
    keys: WalletKeys,
    nonce: int,
    receiver_pub_hex: str,
    amount: float,
) -> Dict[str, Any]:
    """
    Builds a complete signed transaction ready to send to the validator.
    """
    # Builds transaction without signature first
    unsigned_tx = build_unsigned_transaction(
        nonce=nonce,
        sender_pub_hex=keys.public_key_hex,
        receiver_pub_hex=receiver_pub_hex,
        amount=amount,
    )

    # Copies unsigned transaction and attach signature
    signed_tx = dict(unsigned_tx)
    signed_tx["signature"] = sign_transaction(keys, unsigned_tx)

    return signed_tx


def verify_transaction_signature(tx: Dict[str, Any]) -> bool:
    """
    Locally verifies a transaction signature before sending it.
    """
    required_fields = {"nonce", "sender_pub", "receiver_pub", "amount", "signature"}

    
    if not required_fields.issubset(tx.keys()):
        return False

    # Rebuilds the original unsigned payload
    unsigned_tx = {
        "nonce": tx["nonce"],
        "sender_pub": tx["sender_pub"],
        "receiver_pub": tx["receiver_pub"],
        "amount": tx["amount"],
    }

    try:
        # Rebuilds public key and signature from hex
        pub_key_bytes = bytes.fromhex(tx["sender_pub"])
        sig_bytes = bytes.fromhex(tx["signature"])

        # Verifies signature using the sender's public key
        pub_key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        pub_key.verify(sig_bytes, canonical_json_for_validator(unsigned_tx))

        return True
    except Exception:
        return False


def get_account_state(host: str, port: int, public_key_hex: str) -> Tuple[float, int]:
    """
    Asks the validator for this wallet's balance and next nonce.
    """
    request = {
        "type": "get_account_state",
        "public_key": public_key_hex,
    }

    # Sends account query to validator
    response = send_json_tcp(host, port, request)

    # Validator should return status ok
    if response.get("status") != "ok":
        raise ValueError(f"Validator error: {response}")

    # Pulls balance and nonce from response
    balance = response.get("balance", 0)
    next_nonce = response.get("next_nonce", 1)

    # Validates response types
    if not isinstance(balance, (int, float)):
        raise ValueError(f"Invalid balance from validator: {response}")
    if not isinstance(next_nonce, int) or next_nonce < 0:
        raise ValueError(f"Invalid next_nonce from validator: {response}")

    return float(balance), next_nonce


def submit_transaction(host: str, port: int, tx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sends a transaction to the validator.
    """
    return send_json_tcp(host, port, tx)

    
    request = {
        "type": "submit_transaction",
        "transaction": tx,
    }
    return send_json_tcp(host, port, request)


def print_key_source(keys: WalletKeys) -> None:
    """
    Prints where the active wallet keypair was loaded from.
    """
    if keys.source == "sensor":
        print(f"Using sensor keypair from {SENSOR_KEY_FILE}")
    elif keys.source == "pem":
        print(f"Using wallet PEM keys from {DEFAULT_WALLET_DIR}")
    else:
        print(f"Using key source: {keys.source}")


def cmd_init(args: argparse.Namespace) -> None:
    """
    Creates a new wallet keypair and saves it to disk.
    """
    wallet_dir = args.wallet_dir

    
    if os.path.exists(SENSOR_KEY_FILE):
        print(
            f"Note: {SENSOR_KEY_FILE} exists. Wallet commands will use that sensor keypair by default.",
            file=sys.stderr,
        )

    # Avoid overwriting wallet unless --force is used
    if os.path.exists(os.path.join(wallet_dir, PRIVATE_KEY_FILE)) and not args.force:
        print(f"Wallet already exists in '{wallet_dir}'. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    # Generate and save wallet keys
    keys = generate_wallet()
    save_wallet(keys, wallet_dir)

    print("Wallet created successfully.")
    print("Wallet PEM keypair created successfully.")
    print(f"Wallet directory: {wallet_dir}")
    print(f"Public key (hex): {keys.public_key_hex}")


def cmd_address(args: argparse.Namespace) -> None:
    """
    Prints the active wallet public key.
    """
    keys = load_wallet(args.wallet_dir)
    keys = load_wallet(args.wallet_dir, use_sensor_keys=not args.pem_only)
    print_key_source(keys)
    print(keys.public_key_hex)


def cmd_balance(args: argparse.Namespace) -> None:
    """
    Queries the validator for this wallet's current balance and next nonce.
    """
    print("This validator does not support balance lookup over TCP.")
    print("Ask the validator/dashboard owner for balances.")

    keys = load_wallet(args.wallet_dir, use_sensor_keys=not args.pem_only)
    print_key_source(keys)

    balance, next_nonce = get_account_state(args.host, args.port, keys.public_key_hex)

    print(f"Public key: {keys.public_key_hex}")
    print(f"Balance: {balance}")
    print(f"Next nonce: {next_nonce}")


def cmd_send(args: argparse.Namespace) -> None:
    """
    Creates, signs, and submits a transaction to the validator.
    """
    keys = load_wallet(args.wallet_dir)
    keys = load_wallet(args.wallet_dir, use_sensor_keys=not args.pem_only)
    print_key_source(keys)

    # Receiver wallet address and transfer amount
    receiver_pub = args.receiver_pub.strip()
    amount = args.amount
    nonce = args.nonce

    # Asks validator for current balance and next nonce
    balance, next_nonce = get_account_state(args.host, args.port, keys.public_key_hex)

    # Validate amount
    if amount <= 0:
        print("Amount must be positive.", file=sys.stderr)
        sys.exit(1)

    # Stop early if wallet does not have enough funds
    if balance < amount:
        print(f"Insufficient balance. Current balance={balance}, requested={amount}", file=sys.stderr)
        sys.exit(1)

    # Builds and sign transaction
    tx = build_signed_transaction(
        keys=keys,
        nonce=nonce,
        nonce=next_nonce,
        receiver_pub_hex=receiver_pub,
        amount=amount,
    )

    # Checks signature locally before sending
    if not verify_transaction_signature(tx):
        print("Local signature verification failed.", file=sys.stderr)
        sys.exit(1)

    print("Created signed transaction:")
    print(json.dumps(tx, indent=2))

    # Sends transaction to validator
    response = submit_transaction(args.host, args.port, tx)

    print("\nValidator response:")
    print(json.dumps(response, indent=2))


def build_parser() -> argparse.ArgumentParser:
    """
    Builds the command-line interface for the wallet.
    """
    parser = argparse.ArgumentParser(description="Wallet CLI for DePIN validator")

    
    parser.add_argument(
        "--wallet-dir",
        default=DEFAULT_WALLET_DIR,
        help=f"Wallet directory (default: {DEFAULT_WALLET_DIR})"
    )

    
    parser.add_argument(
        "--pem-only",
        action="store_true",
        help="Ignore keys/device_keys.json and use wallet_data PEM keys only"
    )

    
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init command
    p_init = subparsers.add_parser("init", help="Generate a new wallet keypair")
    p_init = subparsers.add_parser("init", help="Generate a new wallet PEM keypair")
    p_init.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing wallet files",
        help="Overwrite existing wallet PEM files"
    )
    p_init.set_defaults(func=cmd_init)

    # address command
    p_address = subparsers.add_parser("address", help="Show wallet public key")
    p_address.set_defaults(func=cmd_address)

    # balance command
    p_balance = subparsers.add_parser("balance", help="Balance lookup not supported by this validator")
    p_balance = subparsers.add_parser("balance", help="Query validator for balance and next nonce")
    p_balance.add_argument("--host", required=True, help="Validator host")
    p_balance.add_argument("--port", required=True, type=int, help="Validator TCP port")
    p_balance.set_defaults(func=cmd_balance)

    # send command
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
    
    
    
