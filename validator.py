import json
import time
import socket
import threading
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

class DePINValidator:
    def __init__(self, host='0.0.0.0', port=5500):
        self.host = host
        self.port = port
        
        # In-memory Ledger & State
        self.blockchain = []
        self.pending_records = []
        self.balances = {}       # public_key_hex -> float balance
        self.used_nonces = set() # (public_key_hex, nonce)
        
        # Create the Genesis Block
        self._create_block()

    # --- CRYPTOGRAPHY ---

    def verify_signature(self, pub_key_hex, payload_dict, signature_hex):
        """Verifies an Ed25519 signature."""
        try:
            # 1. Reconstruct the public key from hex
            pub_bytes = bytes.fromhex(pub_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            
            # 2. Serialize payload deterministically (sort keys)
            message = json.dumps(payload_dict, sort_keys=True).encode('utf-8')
            signature = bytes.fromhex(signature_hex)
            
            # 3. Verify
            public_key.verify(signature, message)
            return True
        except (ValueError, InvalidSignature, TypeError):
            return False

    # --- INGRESS & VALIDATION ---

    def process_message(self, msg_data):
        """Routes the message to the correct handler based on its keys."""
        signature = msg_data.pop('signature', None)
        if not signature:
            print("❌ Rejected: Missing signature.")
            return False

        if 'uptime_seconds' in msg_data:
            return self.handle_uptime(msg_data, signature)
        elif 'amount' in msg_data:
            return self.handle_transaction(msg_data, signature)
        else:
            print("❌ Rejected: Unknown message format.")
            return False

    def handle_uptime(self, data, signature):
        """Validates Proof-of-Uptime records."""
        pub_key = data.get('device_id') # Assuming device_id is the public key hex
        
        # 1. Verify Signature
        if not self.verify_signature(pub_key, data, signature):
            print("❌ Rejected Uptime: Invalid signature.")
            return False
            
        # 2. Check Freshness (e.g., within last 5 minutes)
        if time.time() - data.get('timestamp', 0) > 300:
            print("❌ Rejected Uptime: Record too old.")
            return False

        # Re-attach signature for block storage
        data['signature'] = signature
        self.pending_records.append({"type": "uptime", "data": data})
        
        # Reward: 1 token per 60 seconds of uptime
        reward = data['uptime_seconds'] / 60.0
        self.balances[pub_key] = self.balances.get(pub_key, 0) + reward
        
        print(f"✅ Accepted Uptime: Minted {reward} tokens for {pub_key[:8]}...")
        return True

    def handle_transaction(self, data, signature):
        """Validates spend/transfer transactions."""
        sender = data.get('sender_pub')
        receiver = data.get('receiver_pub')
        amount = data.get('amount')
        nonce = data.get('nonce')

        # 1. Verify Signature
        if not self.verify_signature(sender, data, signature):
            print("❌ Rejected TX: Invalid signature.")
            return False

        # 2. Replay Protection
        if (sender, nonce) in self.used_nonces:
            print("❌ Rejected TX: Nonce already used (Replay Attack).")
            return False

        # 3. Balance Check
        sender_balance = self.balances.get(sender, 0)
        if sender_balance < amount:
            print(f"❌ Rejected TX: Insufficient funds. (Balance: {sender_balance})")
            return False

        # Execute State Change
        self.balances[sender] -= amount
        self.balances[receiver] = self.balances.get(receiver, 0) + amount
        self.used_nonces.add((sender, nonce))

        data['signature'] = signature
        self.pending_records.append({"type": "transaction", "data": data})
        print(f"✅ Accepted TX: {amount} tokens {sender[:8]}... -> {receiver[:8]}...")
        return True

    # --- CONSENSUS & BLOCKCHAIN ---

    def _create_block(self):
        """Packages pending records into a new block."""
        prev_hash = self.blockchain[-1]['hash'] if self.blockchain else "0" * 64
        
        block = {
            "index": len(self.blockchain),
            "timestamp": time.time(),
            "records": self.pending_records,
            "previous_hash": prev_hash
        }
        
        # Calculate block hash
        block_string = json.dumps(block, sort_keys=True).encode('utf-8')
        block['hash'] = hashlib.sha256(block_string).hexdigest()
        
        self.blockchain.append(block)
        self.pending_records = [] # Reset pending
        print(f"📦 Block {block['index']} created with hash {block['hash'][:8]}...")
        
        # In a real app, save to JSON file here: json.dump(...)

    # --- NETWORKING ---

    def start_tcp_listener(self):
        """Listens for incoming TCP connections."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"🎧 Validator listening on TCP {self.host}:{self.port}...")

        while True:
            client, addr = server.accept()
            # Handle client in a new thread so we don't block the listener
            threading.Thread(target=self._handle_client, args=(client,)).start()

    def _handle_client(self, client_socket):
        try:
            raw_data = client_socket.recv(4096).decode('utf-8')
            if raw_data:
                msg_data = json.loads(raw_data)
                self.process_message(msg_data)
        except Exception as e:
            print(f"⚠️ TCP Error: {e}")
        finally:
            client_socket.close()

if __name__ == "__main__":
    node = DePINValidator()
    
    # Start the TCP server in a background thread
    threading.Thread(target=node.start_tcp_listener, daemon=True).start()

    # Keep the main thread alive, periodically minting blocks
    try:
        while True:
            time.sleep(10) # Create a new block every 10 seconds if there are records
            if node.pending_records:
                node._create_block()
    except KeyboardInterrupt:
        print("\nShutting down Validator...")