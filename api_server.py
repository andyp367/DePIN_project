"""
api_server.py
Wraps DePINValidator with a Flask HTTP API so the dashboard can poll live data.
Run this instead of validator.py directly.
"""

import threading
import time

from validatorP2P import DePINValidator

try:
    from flask import Flask, jsonify
    from flask_cors import CORS
except ImportError:
    print("Missing deps — run: .venv/bin/pip install flask flask-cors")
    raise

node = DePINValidator(host='0.0.0.0')

app = Flask(__name__)
CORS(app)


@app.route('/api/stats')
def stats():
    total_tokens = sum(node.balances.values())
    return jsonify({
        "total_blocks":   len(node.blockchain),
        "tokens_minted":  round(total_tokens, 4),
        "active_wallets": len(node.balances),
        "validator_online": True,
        "tcp_port": node.port,
    })


@app.route('/api/blocks')
def blocks():
    return jsonify(node.blockchain)


@app.route('/api/balances')
def balances():
    return jsonify(node.balances)


@app.route('/api/transactions')
def transactions():
    txs = []
    for block in node.blockchain:
        for record in block.get('records', []):
            if record.get('type') == 'transaction':
                d = record['data']
                txs.append({
                    "block":    block['index'],
                    "sender":   d.get('sender_pub', ''),
                    "receiver": d.get('receiver_pub', ''),
                    "amount":   d.get('amount', 0),
                    "nonce":    d.get('nonce', 0),
                    "timestamp": block['timestamp'],
                })
    return jsonify(txs)


def block_miner():
    while True:
        time.sleep(15)
        node.mine_block()


TCP_PORT  = 5502
HTTP_PORT = 5501

if __name__ == "__main__":
    node.port = TCP_PORT
    threading.Thread(target=node.start_tcp_listener, daemon=True).start()
    threading.Thread(target=block_miner, daemon=True).start()
    print(f"🔌 TCP  listener on port {TCP_PORT}")
    print(f"🌐 HTTP API       on http://0.0.0.0:{HTTP_PORT}")
    app.run(host='0.0.0.0', port=HTTP_PORT, use_reloader=False, threaded=True)
