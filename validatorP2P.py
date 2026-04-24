import json
import time
import socket
import threading
import hashlib
import argparse
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

class DePINValidator:
    def __init__(self, host='0.0.0.0', port=5000, peers=None):
        self.host = host
        self.port = port
        self.peers = peers if peers else []
        
        # State
        self.blockchain = []
        self.pending_records = []
        self.balances = {}       
        self.used_nonces = set() 
        
        # Lock for thread safety when modifying the blockchain
        self.chain_lock = threading.Lock()
        
        # Create deterministic Genesis Block (Timestamp 0 ensures all nodes match)
        self._create_genesis_block()

    # --- CRYPTOGRAPHY ---

    def verify_signature(self, pub_key_hex, payload_dict, signature_hex):
        try:
            pub_bytes = bytes.fromhex(pub_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            
            # Canonical JSON to match Wallet/Pi exactly
            message = json.dumps(
                payload_dict, 
                sort_keys=True, 
                separators=(',', ':')
            ).encode('utf-8')
            
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, message)
            return True
        except Exception:
            return False

    # --- INGRESS & VALIDATION ---

    def process_message(self, msg_data):
        """Routes incoming TCP messages."""
        msg_type = msg_data.get('type')

        # 1. Peer-to-Peer Block Gossip
        if msg_type == 'new_block':
            success = self.handle_new_block(msg_data.get('block'))
            return {"status": "ok" if success else "ignored"}

        # 2. Wallet State Query
        if msg_type == 'get_account_state':
            pub_key = msg_data.get('public_key')
            return {
                "status": "ok",
                "balance": self.balances.get(pub_key, 0),
                "next_nonce": len([n for pk, n in self.used_nonces if pk == pub_key]) + 1
            }

        if msg_type == 'get_balances':
            with self.chain_lock:
                return {"status": "ok", "balances": dict(self.balances)}

        if msg_type == 'get_blocks':
            count = msg_data.get('count', 10)
            with self.chain_lock:
                recent = self.blockchain[-count:]
            return {"status": "ok", "blocks": list(reversed(recent))}

        if msg_type == 'get_status':
            with self.chain_lock:
                last_block = self.blockchain[-1] if self.blockchain else None
            return {
                "status": "ok",
                "chain_height": len(self.blockchain),
                "pending_count": len(self.pending_records),
                "last_block_time": last_block['timestamp'] if last_block else 0,
                "last_block_hash": last_block['hash'] if last_block else None,
            }

        # 3. Handle Transactions & Uptime (Needs Signature)
        # Unwrap wallet submission format if present
        if msg_type == 'submit_transaction':
            msg_data = msg_data.get('transaction', {})

        signature = msg_data.pop('signature', None)
        if not signature:
            return {"status": "error", "message": "Missing signature"}

        if 'uptime_seconds' in msg_data:
            success = self.handle_uptime(msg_data, signature)
            return {"status": "ok" if success else "error"}
        elif 'amount' in msg_data:
            success = self.handle_transaction(msg_data, signature)
            return {"status": "accepted" if success else "rejected"}
            
        return {"status": "error", "message": "Unknown message format"}

    def handle_uptime(self, data, signature):
        pub_key = data.get('device_id')
        if not self.verify_signature(pub_key, data, signature):
            return False

        with self.chain_lock:
            data['signature'] = signature
            self.pending_records.append({"type": "uptime", "data": data})
            
            # Optimistic local execution
            reward = data['uptime_seconds'] / 60.0
            self.balances[pub_key] = self.balances.get(pub_key, 0) + reward
            print(f"✅ Mempool: Minted {reward} tokens for {pub_key[:8]}...")
        return True

    def handle_transaction(self, data, signature):
        sender = data.get('sender_pub')
        receiver = data.get('receiver_pub')
        amount = data.get('amount')
        nonce = data.get('nonce')

        if not self.verify_signature(sender, data, signature):
            return False

        with self.chain_lock:
            if (sender, nonce) in self.used_nonces:
                return False

            if self.balances.get(sender, 0) < amount:
                return False

            # Optimistic local execution
            self.balances[sender] -= amount
            self.balances[receiver] = self.balances.get(receiver, 0) + amount
            self.used_nonces.add((sender, nonce))

            data['signature'] = signature
            self.pending_records.append({"type": "transaction", "data": data})
            print(f"✅ Mempool: {amount} tokens {sender[:8]}... -> {receiver[:8]}...")
        return True

    # --- CONSENSUS & BLOCKCHAIN ---

    def _create_genesis_block(self):
        block = {
            "index": 0,
            "timestamp": 0,  # Hardcoded so all nodes generate the same hash
            "records": [],
            "previous_hash": "0" * 64
        }
        block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode('utf-8')
        block['hash'] = hashlib.sha256(block_string).hexdigest()
        self.blockchain.append(block)

    def mine_block(self):
        """Packages pending records into a new block and broadcasts it."""
        with self.chain_lock:
            if not self.pending_records:
                return

            prev_hash = self.blockchain[-1]['hash']
            block = {
                "index": len(self.blockchain),
                "timestamp": time.time(),
                "records": self.pending_records.copy(),
                "previous_hash": prev_hash
            }
            
            block_string = json.dumps(block, sort_keys=True, separators=(',', ':')).encode('utf-8')
            block['hash'] = hashlib.sha256(block_string).hexdigest()
            
            self.blockchain.append(block)
            self.pending_records = []
            print(f"\n📦 Mined Block {block['index']} | Hash: {block['hash'][:8]}...")

        # Broadcast outside the lock
        self.broadcast_block(block)

    def handle_new_block(self, block):
        """Processes a block received from a peer."""
        with self.chain_lock:
            # Basic Consensus: Only accept if it perfectly builds on our current chain
            if block['index'] <= len(self.blockchain) - 1:
                return False # We already have this block (or a longer chain)
                
            if block['previous_hash'] != self.blockchain[-1]['hash']:
                print(f"⚠️ Fork detected! Rejecting block {block['index']} from peer.")
                return False

            # Verify block hash
            block_copy = block.copy()
            claimed_hash = block_copy.pop('hash')
            block_string = json.dumps(block_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
            calculated_hash = hashlib.sha256(block_string).hexdigest()
            
            if claimed_hash != calculated_hash:
                print("❌ Rejected Peer Block: Invalid block hash.")
                return False

            # Accept Block
            self.blockchain.append(block)
            print(f"\n📥 Received & Accepted Block {block['index']} from peer.")

            # Clean up our pending records (remove ones included in peer's block)
            peer_record_signatures = [r['data']['signature'] for r in block['records']]
            self.pending_records = [
                r for r in self.pending_records 
                if r['data']['signature'] not in peer_record_signatures
            ]
            
            # Note: In a production system, we would re-evaluate balances here.
            # For this lab, our optimistic mempool execution holds state.
            return True

    # --- NETWORKING ---

    def start_tcp_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow port reuse so we don't get 'Address already in use' errors in the lab
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"🎧 Validator listening on {self.host}:{self.port}")
        if self.peers:
            print(f"🔗 Connected peers: {self.peers}")

        while True:
            client, addr = server.accept()
            threading.Thread(target=self._handle_client, args=(client,)).start()

    def _handle_client(self, client_socket):
        try:
            raw_data = b""
            # Read until the connection stops sending
            while True:
                chunk = client_socket.recv(4096)
                if not chunk: break
                raw_data += chunk
                # Simple heuristic to know when JSON is done for the lab
                if b"}" in chunk: break 

            if raw_data:
                msg_data = json.loads(raw_data.decode('utf-8'))
                response = self.process_message(msg_data)
                client_socket.sendall((json.dumps(response) + "\n").encode('utf-8'))
        except Exception as e:
            pass # Ignore simple disconnects
        finally:
            client_socket.close()

    def broadcast_block(self, block):
        """Sends a newly mined block to all known peers."""
        payload = json.dumps({"type": "new_block", "block": block}).encode('utf-8')
        for peer_port in self.peers:
            try:
                with socket.create_connection((self.host, peer_port), timeout=2) as sock:
                    sock.sendall(payload)
            except ConnectionRefusedError:
                pass # Peer is offline

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DePIN Validator Node")
    parser.add_argument("--port", type=int, default=5000, help="Port to run this validator on")
    parser.add_argument("--peers", type=str, default="", help="Comma-separated list of peer ports")
    args = parser.parse_args()

    # Parse peers
    peer_list = [int(p) for p in args.peers.split(',')] if args.peers else []

    node = DePINValidator(port=args.port, peers=peer_list)
    threading.Thread(target=node.start_tcp_listener, daemon=True).start()

    try:
        while True:
            time.sleep(15) # Mine a block every 15 seconds
            node.mine_block()
    except KeyboardInterrupt:
        print("\nShutting down Validator...")
